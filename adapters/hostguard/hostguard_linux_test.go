//go:build linux

// Package hostguard_test contains integration tests for the HostGuard sensor
// running on Linux.  They exercise the full sensor pipeline – process events,
// sensitive-file I/O monitoring, and the sensor health check – using
// NewSensorDirect so no NATS server is required.
package hostguard_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	hostguard "github.com/DiniMuhd7/openguard/adapters/hostguard"
	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// rawEvent is a minimal parsed representation of a published Unified-Event
// JSON payload (schemas/unified-event.schema.json).
type rawEvent struct {
	Indicators []string               `json:"indicators"`
	Metadata   map[string]interface{} `json:"metadata"`
}

func (r rawEvent) EventType() string {
	if r.Metadata == nil {
		return ""
	}
	et, _ := r.Metadata["event_type"].(string)
	return et
}

func (r rawEvent) HasIndicator(ind string) bool {
	for _, i := range r.Indicators {
		if i == ind {
			return true
		}
	}
	return false
}

// eventCollector gathers every unified-event payload published by the sensor
// and provides a thread-safe polling helper.
type eventCollector struct {
	mu     sync.Mutex
	events []rawEvent
}

func (c *eventCollector) handler(payload []byte) error {
	var ev rawEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
	return nil
}

// waitFor polls the collected events until pred returns true or the timeout
// elapses.  Returns the matching event and true, or zero-value and false.
func (c *eventCollector) waitFor(timeout time.Duration, pred func(rawEvent) bool) (rawEvent, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		snapshot := make([]rawEvent, len(c.events))
		copy(snapshot, c.events)
		c.mu.Unlock()
		for _, ev := range snapshot {
			if pred(ev) {
				return ev, true
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return rawEvent{}, false
}

// startTestSensor wires col to the sensor event stream and starts it.
// Returns the sensor and a stop function that cancels the context and calls
// sensor.Stop().
func startTestSensor(t *testing.T, cfg common.Config, col *eventCollector) (common.Sensor, func()) {
	t.Helper()
	cfg.PollInterval = 200 * time.Millisecond
	sensor, err := hostguard.NewSensorDirect(cfg, col.handler, zap.NewNop())
	if err != nil {
		t.Fatalf("NewSensorDirect: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := sensor.Start(ctx); err != nil {
		cancel()
		t.Fatalf("sensor.Start: %v", err)
	}
	return sensor, func() {
		cancel()
		if err := sensor.Stop(); err != nil {
			t.Logf("sensor.Stop: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestSensorHealthCheck verifies the sensor starts on Linux and its health
// check passes (i.e. /proc is accessible).
func TestSensorHealthCheck(t *testing.T) {
	col := &eventCollector{}
	sensor, stop := startTestSensor(t, common.DefaultConfig(), col)
	defer stop()

	if err := sensor.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck returned error: %v", err)
	}
	if got := sensor.Platform(); got != "linux" {
		t.Errorf("Platform() = %q, want %q", got, "linux")
	}
	t.Log("PASS: sensor started and health check passed")
}

// TestSensitiveFileCreatedDetected creates a file inside a directory that is
// configured as a sensitive path prefix.  The test verifies that the sensor
// emits both a file_created event and a suspicious_file_access event with the
// "sensitive_path_access" indicator.
func TestSensitiveFileCreatedDetected(t *testing.T) {
	monitorDir := t.TempDir()

	cfg := common.DefaultConfig()
	cfg.SensitivePathPrefixes = []string{monitorDir}

	col := &eventCollector{}
	_, stop := startTestSensor(t, cfg, col)
	defer stop()

	// Give the inotify watcher time to register its watch descriptor before
	// we create the file.
	time.Sleep(150 * time.Millisecond)

	testFile := filepath.Join(monitorDir, "secret.conf")
	if err := os.WriteFile(testFile, []byte("api_key=abc123\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Logf("created file: %s", testFile)

	// --- file_created --------------------------------------------------
	_, foundCreate := col.waitFor(3*time.Second, func(e rawEvent) bool {
		if e.EventType() != "file_created" {
			return false
		}
		path, _ := e.Metadata["file_path"].(string)
		return strings.HasPrefix(path, monitorDir)
	})
	if foundCreate {
		t.Logf("PASS: file_created event detected for %s", testFile)
	} else {
		t.Errorf("FAIL: no file_created event within timeout for %s", testFile)
	}

	// --- suspicious_file_access ----------------------------------------
	_, foundSuspicious := col.waitFor(3*time.Second, func(e rawEvent) bool {
		return e.EventType() == "suspicious_file_access" &&
			e.HasIndicator("sensitive_path_access")
	})
	if foundSuspicious {
		t.Log("PASS: suspicious_file_access event with sensitive_path_access indicator detected")
	} else {
		t.Errorf("FAIL: no suspicious_file_access event within timeout for monitored dir %s", monitorDir)
	}
}

// TestProcessEventsFlowing uses the polling-based ProcessMonitor (realtime
// monitor disabled via cfg.DisableRealtimeMonitor) to verify process_created
// and process_terminated events flow through the full sensor pipeline.
func TestProcessEventsFlowing(t *testing.T) {
	// Spawn the target process before sensor start so it is seen as "new"
	// on the very first poll — giving us a deterministic process_created event.
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child process: %v", err)
	}
	targetPID := uint32(cmd.Process.Pid)
	t.Logf("spawned child pid=%d", targetPID)
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	})

	col := &eventCollector{}
	cfg := common.DefaultConfig()
	cfg.DisableRealtimeMonitor = true // force polling so events are deterministic
	_, stop := startTestSensor(t, cfg, col)
	defer stop()

	// --- process_created ------------------------------------------------
	_, foundCreate := col.waitFor(3*time.Second, func(e rawEvent) bool {
		if e.EventType() != "process_created" {
			return false
		}
		evPID, _ := e.Metadata["pid"].(float64)
		return uint32(evPID) == targetPID
	})
	if foundCreate {
		t.Logf("PASS: process_created event for pid=%d", targetPID)
	} else {
		t.Errorf("FAIL: no process_created event for pid=%d", targetPID)
	}

	// Baseline is now established; kill the process and expect terminated.
	cmd.Process.Kill() //nolint:errcheck
	cmd.Wait()         //nolint:errcheck
	t.Logf("killed pid=%d; waiting for process_terminated event", targetPID)

	// --- process_terminated ---------------------------------------------
	_, foundTerm := col.waitFor(3*time.Second, func(e rawEvent) bool {
		if e.EventType() != "process_terminated" {
			return false
		}
		evPID, _ := e.Metadata["pid"].(float64)
		return uint32(evPID) == targetPID
	})
	if foundTerm {
		t.Logf("PASS: process_terminated event for pid=%d", targetPID)
	} else {
		t.Errorf("FAIL: no process_terminated event for pid=%d", targetPID)
	}
}
