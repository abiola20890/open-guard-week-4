//go:build darwin

// Package hostguarddarwin implements the HostGuard sensor for macOS.
package hostguarddarwin

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// darwinSession holds a parsed session entry from `who`.
type darwinSession struct {
	username string
	tty      string
	host     string
}

// SessionMonitor watches `who` output for login/logout events and
// log files for sudo/SSH events.
type SessionMonitor struct {
	cfg          common.Config
	eventCh      chan<- *common.HostEvent
	logger       *zap.Logger
	baseline     map[string]darwinSession // key: tty
	lastLogLines map[string]int           // key: log path, value: last seen line count
	watcher      *fsnotify.Watcher
	mu           sync.Mutex
	cancelFn     context.CancelFunc
	wg           sync.WaitGroup
}

// newSessionMonitor creates a SessionMonitor that sends events to eventCh.
func newSessionMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *SessionMonitor {
	return &SessionMonitor{
		cfg:          cfg,
		eventCh:      eventCh,
		logger:       logger,
		baseline:     make(map[string]darwinSession),
		lastLogLines: make(map[string]int),
	}
}

// Start baselines current sessions and begins watching.
func (m *SessionMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	// Baseline.
	sessions, err := runWho(ctx)
	if err != nil {
		m.logger.Warn("darwin: session monitor who baseline", zap.Error(err))
	} else {
		m.mu.Lock()
		m.baseline = sessions
		m.mu.Unlock()
	}

	// Set up fsnotify for auth logs.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		m.logger.Warn("darwin: session monitor fsnotify", zap.Error(err))
	} else {
		m.watcher = watcher
		for _, path := range []string{"/var/log/system.log", "/var/log/auth.log"} {
			if err := watcher.Add(path); err != nil {
				m.logger.Debug("darwin: session monitor watch path unavailable",
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

func (m *SessionMonitor) run(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.pollWho(ctx)
		case event, ok := <-m.watcherEvents():
			if !ok {
				return
			}
			m.pollLogFile(ctx, event.Name)
		case err, ok := <-m.watcherErrors():
			if !ok {
				return
			}
			m.logger.Debug("darwin: session watcher error", zap.Error(err))
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

// pollWho runs `who` and diffs against baseline.
func (m *SessionMonitor) pollWho(ctx context.Context) {
	current, err := runWho(ctx)
	if err != nil {
		m.logger.Warn("darwin: session monitor who poll", zap.Error(err))
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	for key, sess := range current {
		if _, existed := m.baseline[key]; !existed {
			indicators := darwinClassifyLogin(sess.username, sess.host)
			m.emit(ctx, "user_login", sess.username, sess.tty, sess.host, 0, 0, "login", indicators, now)
		}
	}
	for key, sess := range m.baseline {
		if _, exists := current[key]; !exists {
			m.emit(ctx, "user_logout", sess.username, sess.tty, sess.host, 0, 0, "logout", nil, now)
		}
	}
	m.baseline = current
}

// pollLogFile uses tail and tracks already-seen line counts to avoid duplicate events.
func (m *SessionMonitor) pollLogFile(ctx context.Context, path string) {
	out, err := exec.CommandContext(ctx, "tail", "-1000", path).Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(out), "\n")

	m.mu.Lock()
	lastSeen := m.lastLogLines[path]
	startIdx := lastSeen
	if startIdx > len(lines) {
		startIdx = 0
	}
	m.lastLogLines[path] = len(lines)
	m.mu.Unlock()

	now := time.Now()
	for _, line := range lines[startIdx:] {
		if strings.Contains(line, "sudo") {
			m.emit(ctx, "sudo_invocation", "", "", "", 0, 0, "sudo", nil, now)
		} else if strings.Contains(line, "sshd") && strings.Contains(line, "Accepted") {
			m.emit(ctx, "ssh_login", "", "", "", 0, 0, "ssh", nil, now)
		}
	}
}

// emit sends a session HostEvent.
func (m *SessionMonitor) emit(ctx context.Context, eventType, username, tty, host string, pid, sessionID uint32, subtype string, indicators []string, ts time.Time) {
	if indicators == nil {
		indicators = []string{}
	}
	event := &common.HostEvent{
		EventType: eventType,
		Platform:  "darwin",
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
		},
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}

// runWho runs `who` and parses current sessions.
func runWho(ctx context.Context) (map[string]darwinSession, error) {
	out, err := exec.CommandContext(ctx, "who").Output()
	if err != nil {
		return nil, err
	}
	sessions := make(map[string]darwinSession)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		sess := darwinSession{
			username: fields[0],
			tty:      fields[1],
		}
		if len(fields) >= 5 {
			// Last field in parentheses is often the remote host.
			last := fields[len(fields)-1]
			sess.host = strings.Trim(last, "()")
		}
		sessions[sess.tty] = sess
	}
	return sessions, scanner.Err()
}

// darwinClassifyLogin returns indicators for a login.
func darwinClassifyLogin(username, host string) []string {
	var indicators []string
	if host != "" {
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
