//go:build linux

// Package hostguardlinux implements the HostGuard sensor for Linux.
package hostguardlinux

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

const (
	utmpUserProcess = 7
	utmpDeadProcess = 8
)

// utmpRecord is a simplified Go representation of the Linux utmp struct.
// The binary layout matches struct utmp on x86-64 Linux.
type utmpRecord struct {
	Type    int16
	_       [2]byte
	PID     int32
	Line    [32]byte
	ID      [4]byte
	User    [32]byte
	Host    [256]byte
	Exit    [4]byte
	Session int32
	TV      [8]byte // struct timeval
	AddrV6  [16]byte
	_       [20]byte // reserved
}

// sessionKey returns a stable key for a utmp record.
func sessionKey(rec *utmpRecord) string {
	return fmt.Sprintf("%s:%d", nullTerm(rec.Line[:]), rec.PID)
}

// SessionMonitor watches /var/run/utmp for login/logout events and
// auth log files for sudo/SSH events.
type SessionMonitor struct {
	cfg          common.Config
	eventCh      chan<- *common.HostEvent
	logger       *zap.Logger
	baseline     map[string]utmpRecord // key: sessionKey
	logOffsets   map[string]int64      // key: log path, value: last read offset
	watcher      *fsnotify.Watcher
	mu           sync.Mutex
	cancelFn     context.CancelFunc
	wg           sync.WaitGroup
}

// newSessionMonitor creates a SessionMonitor that sends events to eventCh.
func newSessionMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *SessionMonitor {
	return &SessionMonitor{
		cfg:        cfg,
		eventCh:    eventCh,
		logger:     logger,
		baseline:   make(map[string]utmpRecord),
		logOffsets: make(map[string]int64),
	}
}

// Start begins watching utmp and auth log files.
func (m *SessionMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	// Baseline utmp.
	records, err := parseUtmp()
	if err != nil {
		m.logger.Warn("linux: session monitor utmp baseline", zap.Error(err))
	} else {
		m.mu.Lock()
		for _, rec := range records {
			if rec.Type == utmpUserProcess {
				m.baseline[sessionKey(&rec)] = rec
			}
		}
		m.mu.Unlock()
	}

	// Set up fsnotify watcher.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		m.logger.Warn("linux: session monitor fsnotify", zap.Error(err))
	} else {
		m.watcher = watcher
		for _, path := range []string{"/var/run/utmp", "/var/log/auth.log", "/var/log/secure"} {
			if err := watcher.Add(path); err != nil {
				m.logger.Debug("linux: session monitor watch path unavailable",
					zap.String("path", path), zap.Error(err))
			}
		}
	}

	m.wg.Add(1)
	go m.run(ctx)
	return nil
}

// Stop gracefully shuts down the SessionMonitor.
func (m *SessionMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	if m.watcher != nil {
		m.watcher.Close() //nolint:errcheck
	}
	m.wg.Wait()
}

// run is the main event loop.
func (m *SessionMonitor) run(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.pollUtmp(ctx)
		case event, ok := <-m.watcherEvents():
			if !ok {
				return
			}
			if strings.HasSuffix(event.Name, "utmp") {
				m.pollUtmp(ctx)
			} else {
				m.pollAuthLog(ctx, event.Name)
			}
		case err, ok := <-m.watcherErrors():
			if !ok {
				return
			}
			m.logger.Debug("linux: session watcher error", zap.Error(err))
		}
	}
}

func (m *SessionMonitor) watcherEvents() <-chan fsnotify.Event {
	if m.watcher == nil {
		return nil
	}
	return m.watcher.Events
}

func (m *SessionMonitor) watcherErrors() <-chan error {
	if m.watcher == nil {
		return nil
	}
	return m.watcher.Errors
}

// pollUtmp reads /var/run/utmp and diffs against baseline.
func (m *SessionMonitor) pollUtmp(ctx context.Context) {
	records, err := parseUtmp()
	if err != nil {
		m.logger.Warn("linux: session monitor utmp poll", zap.Error(err))
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	current := make(map[string]utmpRecord)
	for _, rec := range records {
		if rec.Type == utmpUserProcess {
			current[sessionKey(&rec)] = rec
		}
	}

	now := time.Now()

	// New logins.
	for key, rec := range current {
		if _, existed := m.baseline[key]; !existed {
			username := nullTerm(rec.User[:])
			tty := nullTerm(rec.Line[:])
			host := nullTerm(rec.Host[:])
			indicators := classifyLogin(username, host)
			m.emit(ctx, "user_login", username, tty, host, uint32(rec.PID), 0, "login", indicators, now)
		}
	}

	// Logouts (USER_PROCESS entries that disappeared).
	for key, rec := range m.baseline {
		if _, exists := current[key]; !exists {
			username := nullTerm(rec.User[:])
			tty := nullTerm(rec.Line[:])
			host := nullTerm(rec.Host[:])
			m.emit(ctx, "user_logout", username, tty, host, uint32(rec.PID), 0, "logout", nil, now)
		}
	}

	m.baseline = current
}

// pollAuthLog scans a log file for sudo/ssh keywords, starting from last read offset.
func (m *SessionMonitor) pollAuthLog(ctx context.Context, path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close() //nolint:errcheck

	m.mu.Lock()
	offset := m.logOffsets[path]
	m.mu.Unlock()

	if _, err := f.Seek(offset, 0); err != nil {
		return
	}

	now := time.Now()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "sudo") {
			m.emit(ctx, "sudo_invocation", "", "", "", 0, 0, "sudo", nil, now)
		} else if strings.Contains(line, "sshd") && strings.Contains(line, "Accepted") {
			m.emit(ctx, "ssh_login", "", "", "", 0, 0, "ssh", nil, now)
		}
	}

	pos, err := f.Seek(0, 1)
	if err == nil {
		m.mu.Lock()
		m.logOffsets[path] = pos
		m.mu.Unlock()
	}
}

// emit sends a session HostEvent.
func (m *SessionMonitor) emit(ctx context.Context, eventType, username, tty, host string, pid, sessionID uint32, subtype string, indicators []string, ts time.Time) {
	if indicators == nil {
		indicators = []string{}
	}
	event := &common.HostEvent{
		EventType: eventType,
		Platform:  "linux",
		Hostname:  m.cfg.Hostname,
		Timestamp: ts,
		Login: &common.LoginEvent{
			Username:     username,
			TTY:          tty,
			RemoteHost:   host,
			PID:          pid,
			SessionID:    sessionID,
			EventSubtype: subtype,
		},
		Indicators: indicators,
		RawData: map[string]interface{}{
			"username":    username,
			"tty":         tty,
			"remote_host": host,
			"pid":         pid,
		},
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}

// classifyLogin returns indicators for a login event.
func classifyLogin(username, host string) []string {
	var indicators []string
	if host != "" && host != "localhost" {
		ip := net.ParseIP(host)
		if ip != nil && !common.IsPrivateRange(host) && !common.IsLoopback(host) {
			indicators = append(indicators, "remote_login")
			if username == "root" {
				indicators = append(indicators, "root_remote_login")
			}
		}
	}
	return indicators
}

// parseUtmp reads /var/run/utmp and returns all records.
func parseUtmp() ([]utmpRecord, error) {
	data, err := os.ReadFile("/var/run/utmp")
	if err != nil {
		return nil, fmt.Errorf("linux: read /var/run/utmp: %w", err)
	}

	recSize := binary.Size(utmpRecord{})
	if recSize <= 0 {
		return nil, fmt.Errorf("linux: utmpRecord size invalid")
	}

	var records []utmpRecord
	r := bytes.NewReader(data)
	for {
		var rec utmpRecord
		if err := binary.Read(r, binary.LittleEndian, &rec); err != nil {
			break
		}
		records = append(records, rec)
	}
	return records, nil
}

// nullTerm returns a null-terminated string from a byte slice.
func nullTerm(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
