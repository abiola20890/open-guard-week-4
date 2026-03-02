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

// darwinPIDSample holds one CPU/memory reading for a PID on macOS.
type darwinPIDSample struct {
	cpuPct   float64
	memoryMB float64
}

// ResourceMonitor polls ps for per-process CPU/RSS and emits resource_spike
// events when thresholds are exceeded for two consecutive samples.
type ResourceMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	samples  map[uint32][]darwinPIDSample // rolling window: last 2 samples
	mu       sync.Mutex
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newResourceMonitor creates a ResourceMonitor that sends events to eventCh.
func newResourceMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *ResourceMonitor {
	return &ResourceMonitor{
		cfg:     cfg,
		eventCh: eventCh,
		logger:  logger,
		samples: make(map[uint32][]darwinPIDSample),
	}
}

// Start begins polling at the configured interval.
func (m *ResourceMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	interval := m.cfg.PollInterval
	if interval <= 0 {
		interval = 5 * time.Second
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

// Stop gracefully shuts down the ResourceMonitor.
func (m *ResourceMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// poll runs ps and checks CPU/memory thresholds.
func (m *ResourceMonitor) poll(ctx context.Context) {
	out, err := exec.CommandContext(ctx, "ps", "-axo", "pid=,pcpu=,rss=", "-r").Output()
	if err != nil {
		m.logger.Warn("darwin: resource monitor ps", zap.Error(err))
		return
	}

	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	activePIDs := make(map[uint32]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid64, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		activePIDs[pid] = struct{}{}

		cpuPct, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}
		rssKB, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			continue
		}
		memMB := float64(rssKB) / 1024.0

		sample := darwinPIDSample{cpuPct: cpuPct, memoryMB: memMB}
		window := m.samples[pid]
		window = append(window, sample)
		if len(window) > 3 {
			window = window[len(window)-3:]
		}
		m.samples[pid] = window

		if len(window) < 2 {
			continue
		}

		curr := window[len(window)-1]
		prev := window[len(window)-2]

		cpuHigh := curr.cpuPct > m.cfg.AnomalyThresholds.CPUPercentHigh
		memHigh := curr.memoryMB > m.cfg.AnomalyThresholds.MemoryMBHigh
		prevCPUHigh := prev.cpuPct > m.cfg.AnomalyThresholds.CPUPercentHigh
		prevMemHigh := prev.memoryMB > m.cfg.AnomalyThresholds.MemoryMBHigh

		// Require threshold exceeded for 2 consecutive samples.
		if !(cpuHigh && prevCPUHigh) && !(memHigh && prevMemHigh) {
			continue
		}

		event := &common.HostEvent{
			EventType: "resource_spike",
			Platform:  "darwin",
			Hostname:  m.cfg.Hostname,
			Timestamp: now,
			Process: &common.ProcessInfo{
				PID:        pid,
				CPUPercent: curr.cpuPct,
				MemoryMB:   curr.memoryMB,
			},
			Indicators: []string{"resource_spike"},
			RawData: map[string]interface{}{
				"cpu_percent": fmt.Sprintf("%.2f", curr.cpuPct),
				"memory_mb":   fmt.Sprintf("%.2f", curr.memoryMB),
			},
		}
		select {
		case m.eventCh <- event:
		case <-ctx.Done():
			return
		}
	}

	// Clean up stale PIDs.
	for pid := range m.samples {
		if _, ok := activePIDs[pid]; !ok {
			delete(m.samples, pid)
		}
	}
}
