//go:build linux

// Package hostguardlinux implements the HostGuard sensor for Linux.
package hostguardlinux

import (
	"bufio"
	"context"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// DNSMonitor watches /etc/resolv.conf for DNS config changes and scans
// syslog entries for DNS queries to suspicious domains.
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
		m.logger.Warn("linux: dns monitor fsnotify", zap.Error(err))
	} else {
		m.watcher = watcher
		for _, path := range []string{"/etc/resolv.conf", "/var/log/syslog", "/var/log/messages"} {
			if werr := watcher.Add(path); werr != nil {
				m.logger.Debug("linux: dns monitor watch path unavailable",
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
				m.scanLogFile(ctx, event.Name)
			}
		case err, ok := <-m.watcherErrors():
			if !ok {
				return
			}
			m.logger.Debug("linux: dns watcher error", zap.Error(err))
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
		Platform:   "linux",
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

// scanLogFile tails the given log file looking for DNS query lines.
func (m *DNSMonitor) scanLogFile(ctx context.Context, path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close() //nolint:errcheck

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "resolved") && !strings.Contains(line, "systemd-resolved") {
			continue
		}
		// Extract query domain heuristically.
		domain := extractDomainFromLogLine(line)
		if domain == "" {
			continue
		}
		indicators := classifyDNSDomain(domain)
		event := &common.HostEvent{
			EventType:  "dns_query",
			Platform:   "linux",
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

// extractDomainFromLogLine tries to extract a domain name from a log line.
func extractDomainFromLogLine(line string) string {
	// Look for "for <domain>" or "query <domain>" patterns.
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

// classifyDNSDomain returns DGA-related indicators for a domain.
func classifyDNSDomain(domain string) []string {
	var indicators []string

	parts := strings.Split(domain, ".")
	// DGA heuristic: >4 subdomain levels.
	if len(parts) > 5 {
		indicators = append(indicators, "dga_domain")
		return indicators
	}
	// DGA heuristic: subdomain with >20 chars of consonant-heavy text.
	if len(parts) > 0 {
		sub := parts[0]
		if len(sub) > 20 && isHighEntropy(sub) {
			indicators = append(indicators, "dga_domain")
			return indicators
		}
	}
	return indicators
}

// isHighEntropy returns true if the string has few vowels (DGA heuristic).
func isHighEntropy(s string) bool {
	vowels := 0
	for _, c := range strings.ToLower(s) {
		if unicode.IsLetter(c) && strings.ContainsRune("aeiou", c) {
			vowels++
		}
	}
	ratio := float64(vowels) / float64(len(s))
	return ratio < 0.15
}
