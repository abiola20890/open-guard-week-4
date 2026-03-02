//go:build darwin

// Package hostguarddarwin implements the HostGuard sensor for macOS.
package hostguarddarwin

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// darwinSHMSegment holds information about a SysV shared memory segment on macOS.
type darwinSHMSegment struct {
	shmid   string
	owner   string
	perms   uint32
	sizeMB  float64
}

// IPCMonitor polls `ipcs -a` for SysV IPC objects and emits events for new or
// suspicious resources.
type IPCMonitor struct {
	cfg         common.Config
	eventCh     chan<- *common.HostEvent
	logger      *zap.Logger
	shmBaseline map[string]darwinSHMSegment // key: shmid
	mu          sync.Mutex
	cancelFn    context.CancelFunc
	wg          sync.WaitGroup
}

// newIPCMonitor creates an IPCMonitor that sends events to eventCh.
func newIPCMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *IPCMonitor {
	return &IPCMonitor{
		cfg:         cfg,
		eventCh:     eventCh,
		logger:      logger,
		shmBaseline: make(map[string]darwinSHMSegment),
	}
}

// Start baselines IPC state and begins polling.
func (m *IPCMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	segs, err := runIPCS(ctx)
	if err != nil {
		m.logger.Warn("darwin: ipc monitor ipcs baseline", zap.Error(err))
	} else {
		m.mu.Lock()
		m.shmBaseline = segs
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

// poll re-runs ipcs and diffs against baseline.
func (m *IPCMonitor) poll(ctx context.Context) {
	current, err := runIPCS(ctx)
	if err != nil {
		m.logger.Warn("darwin: ipc monitor ipcs poll", zap.Error(err))
		return
	}

	m.mu.Lock()
	last := m.shmBaseline
	m.shmBaseline = current
	m.mu.Unlock()

	now := time.Now()

	for id, seg := range current {
		if _, existed := last[id]; !existed {
			indicators := darwinClassifySHM(seg)
			event := &common.HostEvent{
				EventType:  "ipc_shared_memory_created",
				Platform:   "darwin",
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

	for id, seg := range last {
		if _, exists := current[id]; !exists {
			event := &common.HostEvent{
				EventType:  "ipc_shared_memory_deleted",
				Platform:   "darwin",
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

// runIPCS runs `ipcs -a` and parses shared memory segments.
func runIPCS(ctx context.Context) (map[string]darwinSHMSegment, error) {
	out, err := exec.CommandContext(ctx, "ipcs", "-m").Output()
	if err != nil {
		return nil, err
	}

	segs := make(map[string]darwinSHMSegment)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	inShm := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Shared Memory:") || strings.HasPrefix(line, "T      ID") {
			inShm = true
			continue
		}
		if strings.HasPrefix(line, "Semaphores:") || strings.HasPrefix(line, "Message Queues:") {
			inShm = false
			continue
		}
		if !inShm {
			continue
		}
		fields := strings.Fields(line)
		// macOS ipcs -m: T ID KEY MODE OWNER GROUP ...
		if len(fields) < 6 {
			continue
		}
		shmid := fields[1]
		owner := fields[4]
		modeStr := fields[3]
		permsVal := parseIPCSMode(modeStr)
		// Size is not directly in ipcs -m on macOS; use 0 as placeholder.
		sizeBytes := uint64(0)
		if len(fields) >= 9 {
			sizeBytes, _ = strconv.ParseUint(fields[8], 10, 64)
		}
		sizeMB := float64(sizeBytes) / (1024 * 1024)
		segs[shmid] = darwinSHMSegment{
			shmid:  shmid,
			owner:  owner,
			perms:  permsVal,
			sizeMB: sizeMB,
		}
	}
	return segs, scanner.Err()
}

// parseIPCSMode converts an ipcs mode string like "rw-rw-rw-" to a uint32.
func parseIPCSMode(mode string) uint32 {
	var perms uint32
	if len(mode) >= 9 {
		if mode[8] == 'w' {
			perms |= 0o002
		}
	}
	return perms
}

// darwinClassifySHM returns suspicious indicators for a shared memory segment.
func darwinClassifySHM(seg darwinSHMSegment) []string {
	var indicators []string
	if seg.sizeMB > 100 {
		indicators = append(indicators, "large_shared_memory")
	}
	if seg.owner != "0" && seg.owner != "root" && seg.perms&0o002 != 0 {
		indicators = append(indicators, "suspicious_ipc")
	}
	return indicators
}
