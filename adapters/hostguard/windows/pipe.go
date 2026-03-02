//go:build windows

// Package hostguardwindows implements the HostGuard sensor for Windows.
package hostguardwindows

import (
	"context"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

// namedPipeInfo holds information about a named pipe.
type namedPipeInfo struct {
	name string
}

// NamedPipeMonitor enumerates named pipes via FindFirstFile/FindNextFile on
// \\.\pipe\* and emits events for newly created pipes.
type NamedPipeMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	baseline map[string]namedPipeInfo // key: pipe name
	mu       sync.Mutex
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newNamedPipeMonitor creates a NamedPipeMonitor that sends events to eventCh.
func newNamedPipeMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *NamedPipeMonitor {
	return &NamedPipeMonitor{
		cfg:      cfg,
		eventCh:  eventCh,
		logger:   logger,
		baseline: make(map[string]namedPipeInfo),
	}
}

// Start baselines current named pipes and begins polling every 30s.
func (m *NamedPipeMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	pipes, err := enumerateNamedPipes()
	if err != nil {
		m.logger.Warn("windows: named pipe monitor baseline", zap.Error(err))
	} else {
		m.mu.Lock()
		m.baseline = pipes
		m.mu.Unlock()
	}

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(30 * time.Second)
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

// Stop gracefully shuts down the NamedPipeMonitor.
func (m *NamedPipeMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// poll enumerates named pipes and diffs against baseline.
func (m *NamedPipeMonitor) poll(ctx context.Context) {
	current, err := enumerateNamedPipes()
	if err != nil {
		m.logger.Warn("windows: named pipe monitor poll", zap.Error(err))
		return
	}

	m.mu.Lock()
	last := m.baseline
	m.baseline = current
	m.mu.Unlock()

	now := time.Now()
	for name, pipe := range current {
		if _, existed := last[name]; !existed {
			indicators := classifyNamedPipe(pipe.name)
			event := &common.HostEvent{
				EventType:  "named_pipe_created",
				Platform:   "windows",
				Hostname:   m.cfg.Hostname,
				Timestamp:  now,
				Indicators: indicators,
				RawData:    map[string]interface{}{"pipe_name": pipe.name},
			}
			select {
			case m.eventCh <- event:
			case <-ctx.Done():
				return
			}
		}
	}
}

// enumerateNamedPipes lists all named pipes on the system.
func enumerateNamedPipes() (map[string]namedPipeInfo, error) {
	pattern, err := windows.UTF16PtrFromString(`\\.\pipe\*`)
	if err != nil {
		return nil, err
	}

	var findData windows.Win32finddata
	handle, err := windows.FindFirstFile(pattern, &findData)
	if err != nil {
		return nil, err
	}
	defer windows.FindClose(handle) //nolint:errcheck

	pipes := make(map[string]namedPipeInfo)
	for {
		name := windows.UTF16ToString(findData.FileName[:])
		pipes[name] = namedPipeInfo{name: name}

		err = windows.FindNextFile(handle, &findData)
		if err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			break
		}
	}
	return pipes, nil
}

// suspiciousPipePatterns lists pipe name patterns associated with malicious activity.
var suspiciousPipePatterns = []string{
	"msagent_", "lsarpc", "samr", "epmapper",
}

// classifyNamedPipe returns suspicious indicators for a pipe name.
func classifyNamedPipe(name string) []string {
	nameLower := strings.ToLower(name)
	for _, pattern := range suspiciousPipePatterns {
		if strings.Contains(nameLower, pattern) {
			return []string{"suspicious_named_pipe"}
		}
	}
	return []string{}
}
