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
	"unicode"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// DNSMonitor watches /etc/resolv.conf and system log for DNS-related events.
type DNSMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	watcher  *fsnotify.Watcher
	mu       sync.Mutex
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newDNSMonitor creates a DNSMonitor that sends events to eventCh.
func newDNSMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *DNSMonitor {
	return &DNSMonitor{
		cfg:     cfg,
		eventCh: eventCh,
		logger:  logger,
	}
}

// Start begins watching DNS config and log files.
func (m *DNSMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		m.logger.Warn("darwin: dns monitor fsnotify", zap.Error(err))
	} else {
		m.watcher = watcher
		watchPaths := []string{
			"/etc/resolv.conf",
			"/var/log/system.log",
		}
		for _, path := range watchPaths {
			if werr := watcher.Add(path); werr != nil {
				m.logger.Debug("darwin: dns monitor watch path unavailable",
					zap.String("path", path), zap.Error(werr))
			}
		}
	}

	m.wg.Add(1)
	go m.run(ctx)
	return nil
}

// Stop gracefully shuts down the DNSMonitor.
func (m *DNSMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	if m.watcher != nil {
		m.watcher.Close() //nolint:errcheck
	}
	m.wg.Wait()
}

func (m *DNSMonitor) run(ctx context.Context) {
	defer m.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-m.watcherEvents():
			if !ok {
				return
			}
			if strings.HasSuffix(event.Name, "resolv.conf") {
				m.emitConfigChanged(ctx, event.Name)
			} else {
				m.scanSysLog(ctx)
			}
		case err, ok := <-m.watcherErrors():
			if !ok {
				return
			}
			m.logger.Debug("darwin: dns watcher error", zap.Error(err))
		}
	}
}

func (m *DNSMonitor) watcherEvents() <-chan fsnotify.Event {
	if m.watcher == nil {
		return nil
	}
	return m.watcher.Events
}

func (m *DNSMonitor) watcherErrors() <-chan error {
	if m.watcher == nil {
		return nil
	}
	return m.watcher.Errors
}

// emitConfigChanged emits a dns_config_changed event.
func (m *DNSMonitor) emitConfigChanged(ctx context.Context, path string) {
	event := &common.HostEvent{
		EventType:  "dns_config_changed",
		Platform:   "darwin",
		Hostname:   m.cfg.Hostname,
		Timestamp:  time.Now(),
		Indicators: []string{},
		RawData:    map[string]interface{}{"config_file": path},
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}

// scanSysLog tails /var/log/system.log for mDNSResponder entries.
func (m *DNSMonitor) scanSysLog(ctx context.Context) {
	out, err := exec.CommandContext(ctx, "tail", "-200", "/var/log/system.log").Output()
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "mDNSResponder") {
			continue
		}
		domain := darwinExtractDomain(line)
		if domain == "" {
			continue
		}
		indicators := darwinClassifyDNS(domain)
		event := &common.HostEvent{
			EventType:  "dns_query",
			Platform:   "darwin",
			Hostname:   m.cfg.Hostname,
			Timestamp:  time.Now(),
			Indicators: indicators,
			DNSQuery: &common.DNSQueryEvent{
				QueryName: domain,
				QueryType: "A",
			},
			RawData: map[string]interface{}{"query_name": domain},
		}
		select {
		case m.eventCh <- event:
		case <-ctx.Done():
			return
		}
	}
}

func darwinExtractDomain(line string) string {
	for _, prefix := range []string{"for ", "query "} {
		if idx := strings.Index(line, prefix); idx >= 0 {
			rest := line[idx+len(prefix):]
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				domain := strings.Trim(fields[0], "\"'")
				if strings.Contains(domain, ".") {
					return domain
				}
			}
		}
	}
	return ""
}

func darwinClassifyDNS(domain string) []string {
	var indicators []string
	parts := strings.Split(domain, ".")
	if len(parts) > 5 {
		indicators = append(indicators, "dga_domain")
		return indicators
	}
	if len(parts) > 0 {
		sub := parts[0]
		if len(sub) > 20 && darwinIsHighEntropy(sub) {
			indicators = append(indicators, "dga_domain")
		}
	}
	return indicators
}

func darwinIsHighEntropy(s string) bool {
	vowels := 0
	for _, c := range strings.ToLower(s) {
		if unicode.IsLetter(c) && strings.ContainsRune("aeiou", c) {
			vowels++
		}
	}
	ratio := float64(vowels) / float64(len(s))
	return ratio < 0.15
}
