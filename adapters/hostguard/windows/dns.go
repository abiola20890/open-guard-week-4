//go:build windows

// Package hostguardwindows implements the HostGuard sensor for Windows.
package hostguardwindows

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
	"go.uber.org/zap"
)

// DNSMonitor monitors DNS activity on Windows by polling ipconfig /displaydns
// and watching for DNS config registry changes.
type DNSMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	seen     map[string]struct{} // recently seen query names
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
		seen:    make(map[string]struct{}),
	}
}

// Start begins polling DNS cache at the configured interval.
func (m *DNSMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	interval := m.cfg.PollInterval * 6
	if interval < 30*time.Second {
		interval = 30 * time.Second
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

// Stop gracefully shuts down the DNSMonitor.
func (m *DNSMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// poll runs ipconfig /displaydns and checks for suspicious query names.
func (m *DNSMonitor) poll(ctx context.Context) {
	out, err := exec.CommandContext(ctx, "ipconfig", "/displaydns").Output()
	if err != nil {
		m.logger.Debug("windows: dns monitor ipconfig /displaydns", zap.Error(err))
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Lines with "Record Name" contain the queried domain.
		if strings.HasPrefix(line, "Record Name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) < 2 {
				continue
			}
			domain := strings.TrimSpace(parts[1])
			if domain == "" || strings.HasSuffix(domain, ".") {
				domain = strings.TrimSuffix(domain, ".")
			}
			if _, already := m.seen[domain]; already {
				continue
			}
			m.seen[domain] = struct{}{}

			indicators := windowsClassifyDNS(domain, m.cfg.AllowedDNSResolvers)
			if len(indicators) == 0 {
				continue
			}
			event := &common.HostEvent{
				EventType:  "dns_query",
				Platform:   "windows",
				Hostname:   m.cfg.Hostname,
				Timestamp:  now,
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
}

func windowsClassifyDNS(domain string, allowedResolvers []string) []string {
	_ = allowedResolvers // reserved for future non-standard resolver detection
	var indicators []string
	parts := strings.Split(domain, ".")
	if len(parts) > 5 {
		indicators = append(indicators, "dga_domain")
		return indicators
	}
	if len(parts) > 0 {
		sub := parts[0]
		if len(sub) > 20 && windowsIsHighEntropy(sub) {
			indicators = append(indicators, "dga_domain")
		}
	}
	return indicators
}

func windowsIsHighEntropy(s string) bool {
	vowels := 0
	for _, c := range strings.ToLower(s) {
		if unicode.IsLetter(c) && strings.ContainsRune("aeiou", c) {
			vowels++
		}
	}
	ratio := float64(vowels) / float64(len(s))
	return ratio < 0.15
}
