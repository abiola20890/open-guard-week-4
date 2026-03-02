//go:build linux

// Package hostguardlinux implements the HostGuard sensor for Linux.
package hostguardlinux

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// kernelModule holds information parsed from /proc/modules.
type kernelModule struct {
	name    string
	size    string
	address string
}

// suspiciousKernelModuleNames is a list of known rootkit module names.
var suspiciousKernelModuleNames = []string{
	"diamorphine", "azazel", "hiding", "kbeast",
}

// KernelModuleMonitor baselines /proc/modules on start and detects newly
// loaded or unloaded kernel modules on each tick.
type KernelModuleMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	baseline map[string]kernelModule // key: module name
	mu       sync.Mutex
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newKernelModuleMonitor creates a KernelModuleMonitor that sends events to eventCh.
func newKernelModuleMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *KernelModuleMonitor {
	return &KernelModuleMonitor{
		cfg:      cfg,
		eventCh:  eventCh,
		logger:   logger,
		baseline: make(map[string]kernelModule),
	}
}

// Start baselines current modules and begins polling.
func (m *KernelModuleMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	// Baseline on start.
	modules, err := parseModules()
	if err != nil {
		m.logger.Warn("linux: kmodule baseline /proc/modules", zap.Error(err))
	} else {
		m.mu.Lock()
		m.baseline = modules
		m.mu.Unlock()
	}

	interval := m.cfg.PollInterval * 12
	if interval < 60*time.Second {
		interval = 60 * time.Second
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

// Stop gracefully shuts down the KernelModuleMonitor.
func (m *KernelModuleMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// poll re-reads /proc/modules and diffs against baseline.
func (m *KernelModuleMonitor) poll(ctx context.Context) {
	current, err := parseModules()
	if err != nil {
		m.logger.Warn("linux: kmodule poll /proc/modules", zap.Error(err))
		return
	}

	m.mu.Lock()
	last := m.baseline
	m.baseline = current
	m.mu.Unlock()

	// Detect newly loaded modules.
	for name, mod := range current {
		if _, existed := last[name]; !existed {
			indicators := classifyKernelModule(name)
			event := &common.HostEvent{
				EventType: "kernel_module_loaded",
				Platform:  "linux",
				Hostname:  m.cfg.Hostname,
				Timestamp: time.Now(),
				Indicators: indicators,
				RawData: map[string]interface{}{
					"module_name":    mod.name,
					"module_size":    mod.size,
					"module_address": mod.address,
				},
			}
			select {
			case m.eventCh <- event:
			case <-ctx.Done():
				return
			}
		}
	}

	// Detect unloaded modules.
	for name, mod := range last {
		if _, exists := current[name]; !exists {
			event := &common.HostEvent{
				EventType: "kernel_module_unloaded",
				Platform:  "linux",
				Hostname:  m.cfg.Hostname,
				Timestamp: time.Now(),
				Indicators: []string{},
				RawData: map[string]interface{}{
					"module_name":    mod.name,
					"module_size":    mod.size,
					"module_address": mod.address,
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

// parseModules reads /proc/modules and returns a map of module name → kernelModule.
func parseModules() (map[string]kernelModule, error) {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return nil, fmt.Errorf("linux: open /proc/modules: %w", err)
	}
	defer f.Close() //nolint:errcheck

	modules := make(map[string]kernelModule)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		mod := kernelModule{
			name:    fields[0],
			size:    fields[1],
			address: fields[5],
		}
		modules[mod.name] = mod
	}
	return modules, scanner.Err()
}

// classifyKernelModule returns suspicious indicators for a module name.
func classifyKernelModule(name string) []string {
	var indicators []string

	// Check known rootkit names.
	nameLower := strings.ToLower(name)
	for _, sus := range suspiciousKernelModuleNames {
		if strings.Contains(nameLower, sus) {
			indicators = append(indicators, "suspicious_kernel_module")
			return indicators
		}
	}

	// All-numeric name.
	allNumeric := true
	for _, c := range name {
		if c < '0' || c > '9' {
			allNumeric = false
			break
		}
	}
	if allNumeric && name != "" {
		indicators = append(indicators, "suspicious_kernel_module")
		return indicators
	}

	// Single-character name.
	if len(name) == 1 {
		indicators = append(indicators, "suspicious_kernel_module")
	}

	return indicators
}
