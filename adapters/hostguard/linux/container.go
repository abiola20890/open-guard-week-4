//go:build linux

// Package hostguardlinux implements the HostGuard sensor for Linux.
package hostguardlinux

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// containerIDRegex matches 64-character hex strings (container IDs in cgroup paths).
var containerIDRegex = regexp.MustCompile(`[a-f0-9]{64}`)

// containerPIDs maps containerID → set of PIDs.
type containerPIDs = map[string]map[uint32]struct{}

// ContainerMonitor detects container namespace escapes, privileged containers,
// and new container cgroup appearances.
type ContainerMonitor struct {
	cfg              common.Config
	eventCh          chan<- *common.HostEvent
	logger           *zap.Logger
	containerPIDsMap containerPIDs    // containerID → PIDs
	knownContainers  map[string]struct{} // known container IDs
	hostNS           map[string]string   // namespace name → symlink target
	mu               sync.Mutex
	cancelFn         context.CancelFunc
	wg               sync.WaitGroup
}

// newContainerMonitor creates a ContainerMonitor that sends events to eventCh.
func newContainerMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *ContainerMonitor {
	return &ContainerMonitor{
		cfg:              cfg,
		eventCh:          eventCh,
		logger:           logger,
		containerPIDsMap: make(containerPIDs),
		knownContainers:  make(map[string]struct{}),
		hostNS:           make(map[string]string),
	}
}

// Start reads host namespace symlinks and begins polling.
func (m *ContainerMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	// Read host (PID 1) namespace symlinks as the reference.
	for _, nsName := range []string{"mnt", "net", "pid"} {
		target, err := os.Readlink(fmt.Sprintf("/proc/1/ns/%s", nsName))
		if err == nil {
			m.hostNS[nsName] = target
		}
	}

	interval := m.cfg.PollInterval * 4
	if interval <= 0 {
		interval = 20 * time.Second
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

// Stop gracefully shuts down the ContainerMonitor.
func (m *ContainerMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// poll iterates /proc and checks each PID for container membership.
func (m *ContainerMonitor) poll(ctx context.Context) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		m.logger.Warn("linux: container monitor readdir /proc", zap.Error(err))
		return
	}

	now := time.Now()
	currentContainers := make(map[string]map[uint32]struct{})

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)

		cgroupPath, containerID := readCgroupInfo(pid)
		if containerID == "" {
			continue
		}

		if _, ok := currentContainers[containerID]; !ok {
			currentContainers[containerID] = make(map[uint32]struct{})
		}
		currentContainers[containerID][pid] = struct{}{}

		// Check if this is a new PID in a known container.
		m.mu.Lock()
		existingPIDs := m.containerPIDsMap[containerID]
		m.mu.Unlock()

		if existingPIDs != nil {
			if _, exists := existingPIDs[pid]; !exists {
				m.emitEvent(ctx, "container_process_created", pid, containerID, cgroupPath, nil, now)
			}
		}

		// Check for namespace escape: process in container cgroup but using host namespaces.
		m.checkNamespaceEscape(ctx, pid, containerID, cgroupPath, now)

		// Check for full capabilities (privileged container).
		m.checkPrivilegedProcess(ctx, pid, containerID, cgroupPath, now)
	}

	m.mu.Lock()
	lastContainers := m.knownContainers
	m.containerPIDsMap = currentContainers
	newKnown := make(map[string]struct{})
	for id := range currentContainers {
		newKnown[id] = struct{}{}
	}
	m.knownContainers = newKnown
	m.mu.Unlock()

	// New containers.
	for id := range currentContainers {
		if _, existed := lastContainers[id]; !existed {
			m.emitEvent(ctx, "container_started", 0, id, "", nil, now)
		}
	}

	// Stopped containers.
	for id := range lastContainers {
		if _, exists := currentContainers[id]; !exists {
			m.emitEvent(ctx, "container_stopped", 0, id, "", nil, now)
		}
	}
}

// checkNamespaceEscape checks if a containerized process is using host namespaces.
func (m *ContainerMonitor) checkNamespaceEscape(ctx context.Context, pid uint32, containerID, cgroupPath string, now time.Time) {
	for _, nsName := range []string{"mnt", "net", "pid"} {
		target, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", pid, nsName))
		if err != nil {
			continue
		}
		hostTarget, ok := m.hostNS[nsName]
		if !ok {
			continue
		}
		if target == hostTarget {
			m.emitEvent(ctx, "container_escape_attempt", pid, containerID, cgroupPath,
				[]string{"container_escape_attempt"}, now)
			return
		}
	}
}

// checkPrivilegedProcess checks if a containerized process has full capabilities.
func (m *ContainerMonitor) checkPrivilegedProcess(ctx context.Context, pid uint32, containerID, cgroupPath string, now time.Time) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.ToLower(fields[1]) == "ffffffffffffffff" {
				m.emitEvent(ctx, "privileged_container_process", pid, containerID, cgroupPath,
					[]string{"privileged_container_process"}, now)
			}
			return
		}
	}
}

// emitEvent sends a container-related HostEvent.
func (m *ContainerMonitor) emitEvent(ctx context.Context, eventType string, pid uint32, containerID, cgroupPath string, indicators []string, ts time.Time) {
	if indicators == nil {
		indicators = []string{}
	}
	event := &common.HostEvent{
		EventType: eventType,
		Platform:  "linux",
		Hostname:  m.cfg.Hostname,
		Timestamp: ts,
		Process: &common.ProcessInfo{
			PID:         pid,
			ContainerID: containerID,
			CgroupPath:  cgroupPath,
		},
		Indicators: indicators,
		RawData: map[string]interface{}{
			"container_id": containerID,
			"cgroup_path":  cgroupPath,
			"pid":          pid,
		},
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}

// readCgroupInfo reads /proc/<pid>/cgroup and extracts the container ID.
func readCgroupInfo(pid uint32) (cgroupPath string, containerID string) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		// Look for known container runtimes in the cgroup path.
		if strings.Contains(line, "docker") || strings.Contains(line, "kubepods") ||
			strings.Contains(line, "containerd") || strings.Contains(line, "lxc") ||
			strings.Contains(line, "systemd-nspawn") {
			// Extract the cgroup path (third field, colon-separated).
			parts := strings.SplitN(line, ":", 3)
			if len(parts) == 3 {
				cgroupPath = parts[2]
				// Try to extract 64-char container ID.
				if m := containerIDRegex.FindString(cgroupPath); m != "" {
					return cgroupPath, m
				}
				// Fall back to using the last path segment.
				segs := strings.Split(strings.TrimRight(cgroupPath, "/"), "/")
				if len(segs) > 0 {
					last := segs[len(segs)-1]
					if len(last) >= 12 {
						return cgroupPath, last
					}
				}
			}
		}
	}
	return "", ""
}
