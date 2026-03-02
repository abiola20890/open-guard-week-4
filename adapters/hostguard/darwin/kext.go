//go:build darwin

// Package hostguarddarwin implements the HostGuard sensor for macOS.
package hostguarddarwin

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// kextInfo holds information about a loaded kernel extension.
type kextInfo struct {
	name    string
	version string
	address string
}

// KextMonitor baselines loaded kernel extensions via kextstat and detects
// newly loaded or unloaded extensions on each tick.
type KextMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	baseline map[string]kextInfo // key: kext name
	mu       sync.Mutex
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newKextMonitor creates a KextMonitor that sends events to eventCh.
func newKextMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *KextMonitor {
	return &KextMonitor{
		cfg:      cfg,
		eventCh:  eventCh,
		logger:   logger,
		baseline: make(map[string]kextInfo),
	}
}

// Start baselines loaded kexts and begins polling every 60s.
func (m *KextMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	kexts, err := runKextstat(ctx)
	if err != nil {
		m.logger.Warn("darwin: kext baseline kextstat", zap.Error(err))
	} else {
		m.mu.Lock()
		m.baseline = kexts
		m.mu.Unlock()
	}

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(60 * time.Second)
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

// Stop gracefully shuts down the KextMonitor.
func (m *KextMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// poll re-runs kextstat and diffs against baseline.
func (m *KextMonitor) poll(ctx context.Context) {
	current, err := runKextstat(ctx)
	if err != nil {
		m.logger.Warn("darwin: kext poll kextstat", zap.Error(err))
		return
	}

	m.mu.Lock()
	last := m.baseline
	m.baseline = current
	m.mu.Unlock()

	// Detect newly loaded kexts.
	for name, kext := range current {
		if _, existed := last[name]; !existed {
			indicators := classifyKext(kext)
			event := &common.HostEvent{
				EventType:  "kernel_extension_loaded",
				Platform:   "darwin",
				Hostname:   m.cfg.Hostname,
				Timestamp:  time.Now(),
				Indicators: indicators,
				RawData: map[string]interface{}{
					"kext_name":    kext.name,
					"kext_version": kext.version,
					"kext_address": kext.address,
				},
			}
			select {
			case m.eventCh <- event:
			case <-ctx.Done():
				return
			}
		}
	}

	// Detect unloaded kexts.
	for name, kext := range last {
		if _, exists := current[name]; !exists {
			event := &common.HostEvent{
				EventType:  "kernel_extension_unloaded",
				Platform:   "darwin",
				Hostname:   m.cfg.Hostname,
				Timestamp:  time.Now(),
				Indicators: []string{},
				RawData: map[string]interface{}{
					"kext_name":    kext.name,
					"kext_version": kext.version,
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

// runKextstat runs kextstat -l and parses its output into a map.
func runKextstat(ctx context.Context) (map[string]kextInfo, error) {
	out, err := exec.CommandContext(ctx, "kextstat", "-l").Output()
	if err != nil {
		return nil, err
	}

	kexts := make(map[string]kextInfo)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // skip header
		}
		line := scanner.Text()
		fields := strings.Fields(line)
		// Fields: Index Refs Address Size Wired Name (Version) <Dependencies>
		if len(fields) < 6 {
			continue
		}
		name := fields[5]
		version := ""
		if len(fields) > 6 {
			version = strings.Trim(fields[6], "()")
		}
		address := fields[2]
		kexts[name] = kextInfo{name: name, version: version, address: address}
	}
	return kexts, scanner.Err()
}

// classifyKext returns suspicious indicators for a kernel extension.
func classifyKext(kext kextInfo) []string {
	// Flag kexts not from Apple or well-known vendors as suspicious.
	name := kext.name
	if !strings.HasPrefix(name, "com.apple.") &&
		!strings.HasPrefix(name, "com.intel.") &&
		!strings.HasPrefix(name, "com.broadcom.") &&
		!strings.HasPrefix(name, "com.amd.") &&
		!strings.HasPrefix(name, "com.nvidia.") {
		return []string{"suspicious_kernel_extension"}
	}
	return []string{}
}
