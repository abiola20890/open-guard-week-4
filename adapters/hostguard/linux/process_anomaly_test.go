//go:build linux

// Package hostguardlinux — internal tests for process anomaly detection.
// These tests drive the ProcessMonitor directly (bypassing the full sensor
// pipeline) so they exercise checkAnomalies, process_terminated detection,
// and the high-memory threshold regardless of whether the realtime netlink
// monitor is available in the test environment.
package hostguardlinux

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// collectProcessEvent reads from ch until pred returns true or the timeout
// elapses.  Returns the matching event and true, or nil and false on timeout.
func collectProcessEvent(ch <-chan *common.HostEvent, timeout time.Duration, pred func(*common.HostEvent) bool) (*common.HostEvent, bool) {
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-ch:
			if pred(ev) {
				return ev, true
			}
		case <-deadline:
			return nil, false
		}
	}
}

// copyToTmp copies srcBin into os.TempDir() with a unique per-test name and
// registers a Cleanup hook to remove it after the test.
func copyToTmp(t *testing.T, srcBin string) string {
	t.Helper()
	dst := filepath.Join(os.TempDir(), fmt.Sprintf("og-hg-test-%d", os.Getpid()))
	data, err := os.ReadFile(srcBin)
	if err != nil {
		t.Fatalf("copyToTmp: read %s: %v", srcBin, err)
	}
	if err := os.WriteFile(dst, data, 0700); err != nil { //nolint:gosec
		t.Fatalf("copyToTmp: write %s: %v", dst, err)
	}
	t.Cleanup(func() { os.Remove(dst) }) //nolint:errcheck
	return dst
}

// startProcessMonitor creates and starts a ProcessMonitor, returning the
// event channel and a stop function.
func startProcessMonitor(t *testing.T, cfg common.Config) (chan *common.HostEvent, func()) {
	t.Helper()
	eventCh := make(chan *common.HostEvent, 256)
	monitor := newProcessMonitor(cfg, eventCh, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	if err := monitor.Start(ctx); err != nil {
		cancel()
		t.Fatalf("ProcessMonitor.Start: %v", err)
	}
	return eventCh, func() {
		cancel()
		monitor.Stop()
	}
}

// TestProcessMonitorSuspiciousPathDetection copies a binary into os.TempDir(),
// runs it, and expects the ProcessMonitor to emit a process_anomaly event
// with the "suspicious_path" indicator on its first poll (all processes are
// treated as new when lastPIDs is empty).
func TestProcessMonitorSuspiciousPathDetection(t *testing.T) {
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep binary not available:", err)
	}

	tmpBin := copyToTmp(t, sleepBin)

	// Start the target process BEFORE the monitor so it is visible on poll 1.
	cmd := exec.Command(tmpBin, "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start suspicious process: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	})

	cfg := common.DefaultConfig()
	cfg.SuspiciousPaths = []string{os.TempDir()}
	cfg.PollInterval = 200 * time.Millisecond

	eventCh, stop := startProcessMonitor(t, cfg)
	defer stop()

	ev, found := collectProcessEvent(eventCh, 3*time.Second, func(e *common.HostEvent) bool {
		if e.EventType != "process_anomaly" {
			return false
		}
		for _, ind := range e.Indicators {
			if ind == "suspicious_path" {
				return true
			}
		}
		return false
	})
	if !found {
		t.Fatal("timeout: no process_anomaly/suspicious_path event emitted for binary in /tmp")
	}
	t.Logf("PASS: process_anomaly detected — pid=%d exe=%q indicators=%v",
		ev.Process.PID, ev.Process.ExePath, ev.Indicators)
}

// TestProcessMonitorHighMemoryDetection sets the RSS threshold to 1 MB so that
// virtually every running process on the system triggers a resource_spike event.
// This validates that the memory anomaly path inside checkAnomalies fires.
func TestProcessMonitorHighMemoryDetection(t *testing.T) {
	cfg := common.DefaultConfig()
	cfg.AnomalyThresholds.MemoryMBHigh = 1.0 // 1 MB — practically all processes exceed this
	cfg.PollInterval = 200 * time.Millisecond

	eventCh, stop := startProcessMonitor(t, cfg)
	defer stop()

	ev, found := collectProcessEvent(eventCh, 3*time.Second, func(e *common.HostEvent) bool {
		if e.EventType != "process_anomaly" {
			return false
		}
		for _, ind := range e.Indicators {
			if ind == "resource_spike" {
				return true
			}
		}
		return false
	})
	if !found {
		t.Fatal("timeout: no process_anomaly/resource_spike event — no process exceeds 1 MB RSS?")
	}
	t.Logf("PASS: resource_spike detected — pid=%d name=%q memory=%.1f MB",
		ev.Process.PID, ev.Process.Name, ev.Process.MemoryMB)
}

// TestProcessMonitorProcessTerminated spawns a long-lived process, waits for the
// monitor to include it in its baseline (one poll cycle), then kills it and
// asserts a process_terminated event is emitted on the following poll.
func TestProcessMonitorProcessTerminated(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start target process: %v", err)
	}
	targetPID := uint32(cmd.Process.Pid)
	t.Logf("spawned target pid=%d", targetPID)

	cfg := common.DefaultConfig()
	cfg.PollInterval = 200 * time.Millisecond

	eventCh, stop := startProcessMonitor(t, cfg)
	defer stop()

	// Wait for one full poll so targetPID is recorded in lastPIDs.
	time.Sleep(350 * time.Millisecond)

	// Terminate the process.
	cmd.Process.Kill() //nolint:errcheck
	cmd.Wait()         //nolint:errcheck
	t.Logf("killed pid=%d; waiting for process_terminated event", targetPID)

	ev, found := collectProcessEvent(eventCh, 3*time.Second, func(e *common.HostEvent) bool {
		return e.EventType == "process_terminated" &&
			e.Process != nil &&
			e.Process.PID == targetPID
	})
	if !found {
		t.Fatalf("timeout: no process_terminated event for pid=%d", targetPID)
	}
	t.Logf("PASS: process_terminated detected for pid=%d", ev.Process.PID)
}
