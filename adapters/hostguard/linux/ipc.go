//go:build linux

// Package hostguardlinux implements the HostGuard sensor for Linux.
package hostguardlinux

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// shmSegment holds information about a System V shared memory segment.
type shmSegment struct {
	shmid   string
	owner   string
	perms   uint32
	sizeMB  float64
}

// IPCMonitor polls /proc/sysvipc for IPC objects and /proc/net/unix for
// Unix domain sockets, emitting events for new or suspicious IPC resources.
type IPCMonitor struct {
	cfg          common.Config
	eventCh      chan<- *common.HostEvent
	logger       *zap.Logger
	shmBaseline  map[string]shmSegment // key: shmid
	unixBaseline map[string]struct{}   // key: socket path/inode
	mu           sync.Mutex
	cancelFn     context.CancelFunc
	wg           sync.WaitGroup
}

// newIPCMonitor creates an IPCMonitor that sends events to eventCh.
func newIPCMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *IPCMonitor {
	return &IPCMonitor{
		cfg:          cfg,
		eventCh:      eventCh,
		logger:       logger,
		shmBaseline:  make(map[string]shmSegment),
		unixBaseline: make(map[string]struct{}),
	}
}

// Start baselines IPC state and begins polling.
func (m *IPCMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	// Baseline shared memory.
	segs, err := parseShmSegments()
	if err != nil {
		m.logger.Warn("linux: ipc monitor shm baseline", zap.Error(err))
	} else {
		m.mu.Lock()
		m.shmBaseline = segs
		m.mu.Unlock()
	}

	// Baseline unix sockets.
	unixSocks, err := parseUnixSockets()
	if err != nil {
		m.logger.Warn("linux: ipc monitor unix socket baseline", zap.Error(err))
	} else {
		m.mu.Lock()
		m.unixBaseline = unixSocks
		m.mu.Unlock()
	}

	interval := m.cfg.PollInterval * 6
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.poll(ctx)
			}
		}
	}()
	return nil
}

// Stop gracefully shuts down the IPCMonitor.
func (m *IPCMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// poll reads /proc/sysvipc/shm and /proc/net/unix and diffs against baseline.
func (m *IPCMonitor) poll(ctx context.Context) {
	m.pollShm(ctx)
	m.pollUnixSockets(ctx)
}

func (m *IPCMonitor) pollShm(ctx context.Context) {
	current, err := parseShmSegments()
	if err != nil {
		m.logger.Warn("linux: ipc monitor shm poll", zap.Error(err))
		return
	}

	m.mu.Lock()
	last := m.shmBaseline
	m.shmBaseline = current
	m.mu.Unlock()

	now := time.Now()

	// New segments.
	for id, seg := range current {
		if _, existed := last[id]; !existed {
			indicators := classifyShmSegment(seg)
			event := &common.HostEvent{
				EventType:  "ipc_shared_memory_created",
				Platform:   "linux",
				Hostname:   m.cfg.Hostname,
				Timestamp:  now,
				Indicators: indicators,
				RawData: map[string]interface{}{
					"shmid":   seg.shmid,
					"owner":   seg.owner,
					"perms":   fmt.Sprintf("%04o", seg.perms),
					"size_mb": fmt.Sprintf("%.2f", seg.sizeMB),
				},
			}
			select {
			case m.eventCh <- event:
			case <-ctx.Done():
				return
			}
		}
	}

	// Deleted segments.
	for id, seg := range last {
		if _, exists := current[id]; !exists {
			event := &common.HostEvent{
				EventType:  "ipc_shared_memory_deleted",
				Platform:   "linux",
				Hostname:   m.cfg.Hostname,
				Timestamp:  now,
				Indicators: []string{},
				RawData: map[string]interface{}{
					"shmid": seg.shmid,
					"owner": seg.owner,
				},
			}
			select {
			case m.eventCh <- event:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (m *IPCMonitor) pollUnixSockets(ctx context.Context) {
	current, err := parseUnixSockets()
	if err != nil {
		m.logger.Warn("linux: ipc monitor unix socket poll", zap.Error(err))
		return
	}

	m.mu.Lock()
	last := m.unixBaseline
	m.unixBaseline = current
	m.mu.Unlock()

	now := time.Now()
	for key := range current {
		if _, existed := last[key]; !existed {
			// Check if the socket path matches any suspicious path prefix.
			isSuspicious := false
			for _, sp := range m.cfg.SuspiciousPaths {
				if strings.HasPrefix(key, sp) {
					isSuspicious = true
					break
				}
			}
			if isSuspicious {
				event := &common.HostEvent{
					EventType:  "suspicious_unix_socket",
					Platform:   "linux",
					Hostname:   m.cfg.Hostname,
					Timestamp:  now,
					Indicators: []string{"suspicious_unix_socket"},
					RawData:    map[string]interface{}{"socket_path": key},
				}
				select {
				case m.eventCh <- event:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

// parseShmSegments reads /proc/sysvipc/shm and returns a map of shmid → shmSegment.
func parseShmSegments() (map[string]shmSegment, error) {
	f, err := os.Open("/proc/sysvipc/shm")
	if err != nil {
		return nil, fmt.Errorf("linux: open /proc/sysvipc/shm: %w", err)
	}
	defer f.Close() //nolint:errcheck

	segs := make(map[string]shmSegment)
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // skip header
		}
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		// Fields: key shmid owner perms size cpid lpid nattch uid gid cuid cgid atime dtime ctime
		if len(fields) < 5 {
			continue
		}
		shmid := fields[1]
		owner := fields[2]
		permsVal, _ := strconv.ParseUint(fields[3], 8, 32)
		sizeBytes, _ := strconv.ParseUint(fields[4], 10, 64)
		sizeMB := float64(sizeBytes) / (1024 * 1024)
		segs[shmid] = shmSegment{
			shmid:  shmid,
			owner:  owner,
			perms:  uint32(permsVal),
			sizeMB: sizeMB,
		}
	}
	return segs, scanner.Err()
}

// parseUnixSockets reads /proc/net/unix and returns a set of socket paths/inodes.
func parseUnixSockets() (map[string]struct{}, error) {
	f, err := os.Open("/proc/net/unix")
	if err != nil {
		return nil, fmt.Errorf("linux: open /proc/net/unix: %w", err)
	}
	defer f.Close() //nolint:errcheck

	sockets := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // skip header
		}
		line := scanner.Text()
		fields := strings.Fields(line)
		// Last field is the socket path (optional).
		if len(fields) >= 8 {
			path := fields[7]
			sockets[path] = struct{}{}
		} else if len(fields) >= 1 {
			// Use inode as key when no path.
			sockets[fields[0]] = struct{}{}
		}
	}
	return sockets, scanner.Err()
}

// classifyShmSegment returns suspicious indicators for a shared memory segment.
func classifyShmSegment(seg shmSegment) []string {
	var indicators []string
	if seg.sizeMB > 100 {
		indicators = append(indicators, "large_shared_memory")
	}
	// World-writable permissions by non-root.
	if seg.owner != "0" && seg.perms&0o002 != 0 {
		indicators = append(indicators, "suspicious_ipc")
	}
	return indicators
}
