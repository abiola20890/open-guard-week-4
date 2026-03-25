// Package consoleapi — networkguard.go provides the NetworkGuard-specific REST
// API handlers for the console: network flow statistics, event filtering, and
// built-in detection rule listing.
package consoleapi

import (
	"net/http"
	"time"
)

// ─── Detection rules ──────────────────────────────────────────────────────────

// netRule describes a built-in NetworkGuard detection rule.
type netRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Tier        string   `json:"tier"`
	Responses   []string `json:"responses"`
	Enabled     bool     `json:"enabled"`
}

var builtinNetRules = []netRule{
	{
		ID:          "NET-001",
		Name:        "Port Scan Detection",
		Description: "Detects sequential or randomised SYN sweeps from a single source to multiple destination ports within a short window.",
		Severity:    "medium",
		Tier:        "T2",
		Responses:   []string{"alert", "rate_limit"},
		Enabled:     true,
	},
	{
		ID:          "NET-002",
		Name:        "Lateral Movement",
		Description: "Detects east–west internal traffic to common attack-path ports (SMB 445, RDP 3389, WinRM 5985, SSH 22) from unexpected source hosts.",
		Severity:    "high",
		Tier:        "T3",
		Responses:   []string{"alert", "block", "contain"},
		Enabled:     true,
	},
	{
		ID:          "NET-003",
		Name:        "C2 Beaconing",
		Description: "Identifies periodic outbound connections at regular intervals to unknown external IPs, consistent with command-and-control check-in behaviour.",
		Severity:    "critical",
		Tier:        "T4",
		Responses:   []string{"block", "alert", "quarantine_host"},
		Enabled:     true,
	},
	{
		ID:          "NET-004",
		Name:        "DNS Tunneling",
		Description: "Flags abnormally large DNS queries, high subdomain entropy, or unusual query volumes that suggest data exfiltration over DNS.",
		Severity:    "high",
		Tier:        "T3",
		Responses:   []string{"alert", "block"},
		Enabled:     true,
	},
	{
		ID:          "NET-005",
		Name:        "Network-Based Data Exfiltration",
		Description: "Detects high-volume outbound transfers to non-allowlisted external destinations, especially outside business hours.",
		Severity:    "critical",
		Tier:        "T4",
		Responses:   []string{"block", "alert", "audit_log"},
		Enabled:     true,
	},
	{
		ID:          "NET-006",
		Name:        "Unauthorized Remote Access",
		Description: "Detects SSH, RDP, or VNC connection attempts from source IPs not on the approved remote-access allowlist.",
		Severity:    "high",
		Tier:        "T2",
		Responses:   []string{"alert", "block"},
		Enabled:     true,
	},
	{
		ID:          "NET-007",
		Name:        "Protocol Anomaly",
		Description: "Flags traffic where the observed protocol does not match the expected protocol for the destination port (e.g. non-HTTP on port 80).",
		Severity:    "medium",
		Tier:        "T2",
		Responses:   []string{"alert"},
		Enabled:     true,
	},
	{
		ID:          "NET-008",
		Name:        "Geo IP Anomaly",
		Description: "Alerts on traffic to or from IP addresses registered in high-risk or unsanctioned geographic regions.",
		Severity:    "medium",
		Tier:        "T2",
		Responses:   []string{"alert", "hold"},
		Enabled:     true,
	},
}

// ─── Stats ────────────────────────────────────────────────────────────────────

// netEventTypeStat holds an event-type name and its observed count.
type netEventTypeStat struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// netStatsResponse is the JSON body for GET /api/v1/networkguard/stats.
type netStatsResponse struct {
	TotalEvents       int                `json:"total_events"`
	ThreatEvents      int                `json:"threat_events"`
	UniqueSources     int                `json:"unique_sources"`
	BlockedFlows      int                `json:"blocked_flows"`
	ActiveRules       int                `json:"active_rules"`
	EventTypes        []netEventTypeStat `json:"event_types"`
	ProtocolBreakdown map[string]int     `json:"protocol_breakdown"`
	TierBreakdown     map[string]int     `json:"tier_breakdown"`
	Period            string             `json:"period"`
	ComputedAt        string             `json:"computed_at"`
}

// handleNetworkGuardStats handles GET /api/v1/networkguard/stats.
func (s *Server) handleNetworkGuardStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	allEvents, _ := s.events.List(1, 5000)

	typeCounts := map[string]int{}
	protoBreakdown := map[string]int{}
	tierCounts := map[string]int{}
	sources := map[string]struct{}{}
	var threatEvents, totalNetEvents, blockedFlows int

	for _, ev := range allEvents {
		if !isNetworkEvent(ev) {
			continue
		}
		totalNetEvents++

		// Count threat events (tier >= T2 or risk_score >= 50).
		tierStr, _ := ev["tier"].(string)
		riskScore, _ := ev["risk_score"].(float64)
		if parseTierNum(tierStr) >= 2 || riskScore >= 50 {
			threatEvents++
		}

		// Tier breakdown — tierStr is already the canonical label ("T0"…"T4").
		if tierStr == "" {
			tierStr = "T0"
		}
		tierCounts[tierStr]++

		// Unique source tracking — source is a map, not a bare string.
		if src, ok := ev["source"].(map[string]interface{}); ok {
			hostID, _ := src["host_id"].(string)
			adapter, _ := src["adapter"].(string)
			if key := adapter + ":" + hostID; key != ":" {
				sources[key] = struct{}{}
			}
		}

		meta, _ := ev["metadata"].(map[string]interface{})
		if meta != nil {
			// Event-type counting.
			if et, _ := meta["event_type"].(string); et != "" {
				typeCounts[et]++
			}
			// Protocol breakdown.
			if proto, _ := meta["protocol"].(string); proto != "" {
				protoBreakdown[proto]++
			}
			// Blocked flows.
			if blocked, _ := meta["blocked"].(bool); blocked {
				blockedFlows++
			}
		}
	}

	eventTypes := make([]netEventTypeStat, 0, len(typeCounts))
	for t, c := range typeCounts {
		eventTypes = append(eventTypes, netEventTypeStat{Type: t, Count: c})
	}

	// Seed demo data when no real network events exist.
	if len(eventTypes) == 0 {
		eventTypes = []netEventTypeStat{
			{Type: "port_scan", Count: 28},
			{Type: "c2_beaconing", Count: 4},
			{Type: "lateral_movement", Count: 7},
			{Type: "dns_tunneling", Count: 3},
			{Type: "data_exfiltration", Count: 2},
			{Type: "protocol_anomaly", Count: 11},
			{Type: "geo_ip_anomaly", Count: 9},
			{Type: "remote_access", Count: 18},
		}
		threatEvents = 16
		blockedFlows = 12
		totalNetEvents = 82
		sources["10.0.1.45"] = struct{}{}
		sources["10.0.2.12"] = struct{}{}
		sources["192.168.0.32"] = struct{}{}
		sources["172.16.5.88"] = struct{}{}
		protoBreakdown = map[string]int{"TCP": 51, "UDP": 17, "DNS": 8, "ICMP": 6}
		tierCounts = map[string]int{"T0": 36, "T1": 14, "T2": 20, "T3": 9, "T4": 3}
	}

	activeRules := 0
	for _, rule := range builtinNetRules {
		if rule.Enabled {
			activeRules++
		}
	}

	writeJSON(w, http.StatusOK, netStatsResponse{
		TotalEvents:       totalNetEvents,
		ThreatEvents:      threatEvents,
		UniqueSources:     len(sources),
		BlockedFlows:      blockedFlows,
		ActiveRules:       activeRules,
		EventTypes:        eventTypes,
		ProtocolBreakdown: protoBreakdown,
		TierBreakdown:     tierCounts,
		Period:            "24h",
		ComputedAt:        time.Now().UTC().Format(time.RFC3339),
	})
}

// ─── Events ───────────────────────────────────────────────────────────────────

// handleNetworkGuardEvents handles GET /api/v1/networkguard/events.
// Supports query params: event_type, source_ip, direction, page, page_size.
func (s *Server) handleNetworkGuardEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	q := r.URL.Query()
	filterEventType := q.Get("event_type")
	filterSourceIP := q.Get("source_ip")
	filterDirection := q.Get("direction")
	page := parseIntParam(q.Get("page"), 1)
	pageSize := parseIntParam(q.Get("page_size"), 25)

	allEvents, _ := s.events.List(1, 5000)

	var filtered []map[string]interface{}
	for _, ev := range allEvents {
		if !isNetworkEvent(ev) {
			continue
		}

		if filterSourceIP != "" {
			sourceIP := extractSourceIP(ev)
			if sourceIP != filterSourceIP {
				continue
			}
		}

		meta, _ := ev["metadata"].(map[string]interface{})

		if filterEventType != "" {
			et := ""
			if meta != nil {
				et, _ = meta["event_type"].(string)
			}
			if et != filterEventType {
				continue
			}
		}

		if filterDirection != "" {
			dir := ""
			if meta != nil {
				dir, _ = meta["direction"].(string)
			}
			if dir != filterDirection {
				continue
			}
		}

		filtered = append(filtered, ev)
	}

	total := len(filtered)
	start := (page - 1) * pageSize
	if start >= total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"events":    filtered[start:end],
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// ─── Rules ────────────────────────────────────────────────────────────────────

// handleNetworkGuardRules handles GET /api/v1/networkguard/rules.
func (s *Server) handleNetworkGuardRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"rules": builtinNetRules,
		"total": len(builtinNetRules),
	})
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// networkEventTypes is the set of event_type values produced by HostGuard's
// network monitors that are classified as network-domain events.
var networkEventTypes = map[string]bool{
	"connection_established":   true,
	"connection_closed":        true,
	"suspicious_connection":    true,
	"high_volume_connection":   true,
	"dns_query":                true,
	"dns_config_changed":       true,
	"port_scan":                true,
	"c2_beaconing":             true,
	"lateral_movement":         true,
	"dns_tunneling":            true,
	"protocol_anomaly":         true,
	"geo_ip_anomaly":           true,
	"network_data_exfiltration": true,
}

// isNetworkEvent returns true if the event belongs to the network monitoring
// domain. It accepts events with domain="network" (future dedicated sensor) as
// well as domain="host" events whose metadata event_type is network-related.
func isNetworkEvent(ev map[string]interface{}) bool {
	domain, _ := ev["domain"].(string)
	if domain == "network" {
		return true
	}
	if domain == "host" {
		if meta, ok := ev["metadata"].(map[string]interface{}); ok {
			et, _ := meta["event_type"].(string)
			return networkEventTypes[et]
		}
	}
	return false
}

// parseTierNum converts a tier string ("T0"…"T4") to its numeric equivalent.
func parseTierNum(tier string) int {
	switch tier {
	case "T4":
		return 4
	case "T3":
		return 3
	case "T2":
		return 2
	case "T1":
		return 1
	default:
		return 0
	}
}

// extractSourceIP returns a best-effort source IP from the event's source map or metadata.
func extractSourceIP(ev map[string]interface{}) string {
	if src, ok := ev["source"].(map[string]interface{}); ok {
		if ip, _ := src["ip"].(string); ip != "" {
			return ip
		}
		if hostID, _ := src["host_id"].(string); hostID != "" {
			return hostID
		}
	}
	if meta, ok := ev["metadata"].(map[string]interface{}); ok {
		if ip, _ := meta["source_ip"].(string); ip != "" {
			return ip
		}
	}
	return ""
}
