//go:build windows

// Package hostguardwindows implements the HostGuard sensor for Windows.
package hostguardwindows

import (
	"context"
	"fmt"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"github.com/StackExchange/wmi"
	"go.uber.org/zap"
)

// win32PerfProcess represents a row from Win32_PerfFormattedData_PerfProc_Process.
type win32PerfProcess struct {
	ProcessId            uint32
	Name                 string
	PercentProcessorTime uint64
	WorkingSetSize       uint64
}

// windowsPIDSample holds one CPU/memory reading for a PID.
type windowsPIDSample struct {
	cpuPct   float64
	memoryMB float64
}

// ResourceMonitor polls WMI Win32_PerfFormattedData_PerfProc_Process and emits
// resource_spike events when thresholds are exceeded for two consecutive samples.
type ResourceMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	samples  map[uint32][]windowsPIDSample // rolling window: last 2 samples
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
		samples: make(map[uint32][]windowsPIDSample),
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

// poll queries WMI and checks CPU/memory thresholds.
func (m *ResourceMonitor) poll(ctx context.Context) {
	var procs []win32PerfProcess
	query := "SELECT ProcessId, Name, PercentProcessorTime, WorkingSetSize FROM Win32_PerfFormattedData_PerfProc_Process WHERE PercentProcessorTime > 0"
	if err := wmi.Query(query, &procs); err != nil {
		m.logger.Warn("windows: resource monitor WMI query", zap.Error(err))
		return
	}

	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	activePIDs := make(map[uint32]struct{})
	for _, proc := range procs {
		pid := proc.ProcessId
		activePIDs[pid] = struct{}{}

		cpuPct := float64(proc.PercentProcessorTime)
		memMB := float64(proc.WorkingSetSize) / (1024.0 * 1024.0)

		sample := windowsPIDSample{cpuPct: cpuPct, memoryMB: memMB}
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
			Platform:  "windows",
			Hostname:  m.cfg.Hostname,
			Timestamp: now,
			Process: &common.ProcessInfo{
				PID:        pid,
				Name:       proc.Name,
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
