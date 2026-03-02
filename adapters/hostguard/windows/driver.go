//go:build windows

// Package hostguardwindows implements the HostGuard sensor for Windows.
package hostguardwindows

import (
	"context"
	"strings"
	"sync"
	"time"
	"unsafe"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"github.com/StackExchange/wmi"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

// win32SystemDriver represents a row from Win32_SystemDriver.
type win32SystemDriver struct {
	Name        string
	PathName    string
	State       string
	StartMode   string
	ServiceType string
}

// driverInfo holds snapshot info about a driver.
type driverInfo struct {
	name      string
	pathName  string
	state     string
	startMode string
}

// ntModuleInfo holds basic info from NtQuerySystemInformation SystemModuleInformation.
type ntModuleInfo struct {
	name string
}

// DriverMonitor baselines loaded drivers via WMI and detects newly loaded or
// unloaded drivers, cross-referencing with NtQuerySystemInformation to find
// hidden drivers.
type DriverMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	baseline map[string]driverInfo // key: driver name
	mu       sync.Mutex
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newDriverMonitor creates a DriverMonitor that sends events to eventCh.
func newDriverMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *DriverMonitor {
	return &DriverMonitor{
		cfg:      cfg,
		eventCh:  eventCh,
		logger:   logger,
		baseline: make(map[string]driverInfo),
	}
}

// Start baselines current drivers and begins polling every 60s.
func (m *DriverMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	drivers, err := queryWMIDrivers()
	if err != nil {
		m.logger.Warn("windows: driver monitor WMI baseline", zap.Error(err))
	} else {
		m.mu.Lock()
		m.baseline = drivers
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

// Stop gracefully shuts down the DriverMonitor.
func (m *DriverMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// poll re-queries WMI and diffs against baseline.
func (m *DriverMonitor) poll(ctx context.Context) {
	current, err := queryWMIDrivers()
	if err != nil {
		m.logger.Warn("windows: driver monitor WMI poll", zap.Error(err))
		return
	}

	m.mu.Lock()
	last := m.baseline
	m.baseline = current
	m.mu.Unlock()

	// Detect newly loaded drivers.
	for name, drv := range current {
		if _, existed := last[name]; !existed {
			indicators := classifyDriver(drv)
			event := &common.HostEvent{
				EventType:  "driver_loaded",
				Platform:   "windows",
				Hostname:   m.cfg.Hostname,
				Timestamp:  time.Now(),
				Indicators: indicators,
				RawData: map[string]interface{}{
					"driver_name":       drv.name,
					"driver_path":       drv.pathName,
					"driver_state":      drv.state,
					"driver_start_mode": drv.startMode,
				},
			}
			select {
			case m.eventCh <- event:
			case <-ctx.Done():
				return
			}
		}
	}

	// Detect unloaded drivers.
	for name, drv := range last {
		if _, exists := current[name]; !exists {
			event := &common.HostEvent{
				EventType:  "driver_unloaded",
				Platform:   "windows",
				Hostname:   m.cfg.Hostname,
				Timestamp:  time.Now(),
				Indicators: []string{},
				RawData: map[string]interface{}{
					"driver_name": drv.name,
					"driver_path": drv.pathName,
				},
			}
			select {
			case m.eventCh <- event:
			case <-ctx.Done():
				return
			}
		}
	}

	// Cross-reference with NtQuerySystemInformation to find hidden drivers.
	ntModules, err := queryNTModules()
	if err != nil {
		m.logger.Warn("windows: driver monitor NtQuerySystemInformation", zap.Error(err))
	} else {
		for _, mod := range ntModules {
			baseName := strings.ToLower(extractBaseName(mod.name))
			found := false
			for name := range current {
				if strings.ToLower(name) == baseName {
					found = true
					break
				}
			}
			if !found && baseName != "" {
				event := &common.HostEvent{
					EventType:  "driver_loaded",
					Platform:   "windows",
					Hostname:   m.cfg.Hostname,
					Timestamp:  time.Now(),
					Indicators: []string{"hidden_driver"},
					RawData: map[string]interface{}{
						"driver_name": mod.name,
						"source":      "nt_module_list",
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
}

// queryWMIDrivers queries Win32_SystemDriver and returns a map of driver name → driverInfo.
func queryWMIDrivers() (map[string]driverInfo, error) {
	var rows []win32SystemDriver
	if err := wmi.Query("SELECT Name, PathName, State, StartMode, ServiceType FROM Win32_SystemDriver", &rows); err != nil {
		return nil, err
	}
	drivers := make(map[string]driverInfo, len(rows))
	for _, r := range rows {
		drivers[r.Name] = driverInfo{
			name:      r.Name,
			pathName:  r.PathName,
			state:     r.State,
			startMode: r.StartMode,
		}
	}
	return drivers, nil
}

// classifyDriver returns suspicious indicators for a driver.
func classifyDriver(drv driverInfo) []string {
	path := strings.ToLower(drv.pathName)
	if path != "" &&
		!strings.HasPrefix(path, `c:\windows\system32\drivers\`) &&
		!strings.HasPrefix(path, `c:\windows\syswow64\`) &&
		!strings.HasPrefix(path, `c:\windows\system32\`) {
		return []string{"suspicious_driver_path"}
	}
	return []string{}
}

// extractBaseName returns the base file name without extension.
func extractBaseName(path string) string {
	// Find last backslash or forward slash.
	idx := strings.LastIndexAny(path, `/\`)
	if idx >= 0 {
		path = path[idx+1:]
	}
	// Remove .sys or .dll extension.
	if i := strings.LastIndex(path, "."); i >= 0 {
		path = path[:i]
	}
	return path
}

// ─── NtQuerySystemInformation SystemModuleInformation ────────────────────────

const systemModuleInformation = 11

// rtlProcessModule is a simplified version of RTL_PROCESS_MODULE_INFORMATION.
type rtlProcessModule struct {
	_          [16]byte // reserved pointers / handles
	imageBase  uintptr
	imageSize  uint32
	flags      uint32
	loadCount  uint16
	offsetToFileName uint16
	fullPathName [256]byte
}

// rtlProcessModules is a simplified version of RTL_PROCESS_MODULES.
type rtlProcessModules struct {
	numberOfModules uint32
	// modules follow inline — we use unsafe pointer arithmetic below.
}

var (
	ntdll                       = windows.NewLazySystemDLL("ntdll.dll")
	procNtQuerySystemInformation = ntdll.NewProc("NtQuerySystemInformation")
)

// queryNTModules uses NtQuerySystemInformation to enumerate kernel modules.
func queryNTModules() ([]ntModuleInfo, error) {
	var size uint32 = 1 << 16
	for {
		buf := make([]byte, size)
		r, _, _ := procNtQuerySystemInformation.Call(
			systemModuleInformation,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(size),
			uintptr(unsafe.Pointer(&size)),
		)
		// STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
		if r == 0xC0000004 {
			size *= 2
			continue
		}
		if r != 0 {
			return nil, windows.NTStatus(r)
		}

		header := (*rtlProcessModules)(unsafe.Pointer(&buf[0]))
		count := header.numberOfModules
		moduleSize := uint32(unsafe.Sizeof(rtlProcessModule{}))
		base := uintptr(unsafe.Pointer(&buf[0])) + uintptr(unsafe.Sizeof(rtlProcessModules{}))

		var modules []ntModuleInfo
		for i := uint32(0); i < count; i++ {
			if base+uintptr(moduleSize) > uintptr(unsafe.Pointer(&buf[0]))+uintptr(len(buf)) {
				break
			}
			mod := (*rtlProcessModule)(unsafe.Pointer(base))
			offset := mod.offsetToFileName
			name := ""
			if int(offset) < len(mod.fullPathName) {
				raw := mod.fullPathName[offset:]
				for j, b := range raw {
					if b == 0 {
						name = string(raw[:j])
						break
					}
				}
			}
			modules = append(modules, ntModuleInfo{name: name})
			base += uintptr(moduleSize)
		}
		return modules, nil
	}
}
