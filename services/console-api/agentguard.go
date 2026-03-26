// Package consoleapi — agentguard.go provides the AgentGuard-specific REST
// API handlers for the console: agent registry, threat statistics, event
// filtering, and agent lifecycle management (suspend/unsuspend/quarantine).
package consoleapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ─── Detection rules ──────────────────────────────────────────────────────────

// agentRule describes a built-in AgentGuard detection rule.
type agentRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Tier        string `json:"tier"`
	Responses   []string `json:"responses"`
	Enabled     bool   `json:"enabled"`
}

var builtinAgentRules = []agentRule{
	{
		ID:          "AGENT-001",
		Name:        "Unsanctioned Outreach",
		Description: "Agent attempted to contact a domain not in its approved-domain allowlist.",
		Severity:    "high",
		Tier:        "T2–T4",
		Responses:   []string{"block", "suspend", "lockdown"},
		Enabled:     true,
	},
	{
		ID:          "AGENT-002",
		Name:        "Unapproved Tool Use",
		Description: "Agent invoked a tool not on its approved-tool allowlist.",
		Severity:    "medium",
		Tier:        "T2",
		Responses:   []string{"block", "request_approval"},
		Enabled:     true,
	},
	{
		ID:          "AGENT-003",
		Name:        "Self-Policy Modification",
		Description: "Agent attempted to modify, patch, or disable its own policy or rules (constitutional hard rule).",
		Severity:    "critical",
		Tier:        "immediate",
		Responses:   []string{"block", "quarantine", "emergency_alert"},
		Enabled:     true,
	},
	{
		ID:          "AGENT-004",
		Name:        "Prompt Injection Detected",
		Description: "Input payload contained known prompt-injection patterns designed to override agent instructions.",
		Severity:    "critical",
		Tier:        "immediate",
		Responses:   []string{"block", "suspend", "alert"},
		Enabled:     true,
	},
	{
		ID:          "AGENT-005",
		Name:        "Data Exfiltration Attempt",
		Description: "Agent attempted a bulk-export or upload action outside approved scope.",
		Severity:    "critical",
		Tier:        "immediate",
		Responses:   []string{"block", "suspend", "alert", "audit_log"},
		Enabled:     true,
	},
	{
		ID:          "AGENT-006",
		Name:        "Indirect Prompt Injection",
		Description: "Injection payload detected in tool response or RAG-retrieved content rather than direct user input.",
		Severity:    "critical",
		Tier:        "immediate",
		Responses:   []string{"block", "suspend", "quarantine_tool_output"},
		Enabled:     true,
	},
	{
		ID:          "AGENT-007",
		Name:        "Memory Write Anomaly",
		Description: "Agent performed an anomalous write to its persistent memory store outside of approved scope.",
		Severity:    "high",
		Tier:        "T2–T3",
		Responses:   []string{"block", "alert", "audit_log"},
		Enabled:     true,
	},
	{
		ID:          "AGENT-008",
		Name:        "RAG Corpus Poisoning",
		Description: "Retrieval-augmented generation corpus may have been tampered with to influence agent responses.",
		Severity:    "critical",
		Tier:        "T3–immediate",
		Responses:   []string{"block", "suspend", "quarantine_corpus", "alert"},
		Enabled:     true,
	},
}

// ─── Agent store ─────────────────────────────────────────────────────────────

// agentRecord is the console's view of a registered agent.
type agentRecord struct {
	AgentID         string    `json:"agent_id"`
	AgentName       string    `json:"agent_name"`
	AgentType       string    `json:"agent_type"`
	ApprovedTools   []string  `json:"approved_tools"`
	ApprovedDomains []string  `json:"approved_domains"`
	TokenQuota      int64     `json:"token_quota"`
	CallQuota       int64     `json:"call_quota"`
	Suspended       bool      `json:"suspended"`
	Quarantined     bool      `json:"quarantined"`
	RegisteredAt    time.Time `json:"registered_at"`
	LastActivityAt  time.Time `json:"last_activity_at,omitempty"`
	ThreatCount     int       `json:"threat_count"`
	ActionCount     int       `json:"action_count"`
}

// agentStore is a thread-safe in-memory registry of agentRecords populated by
// real agent registrations via POST /api/v1/agentguard/agents.
type agentStore struct {
	mu     sync.RWMutex
	agents map[string]*agentRecord
}

func newAgentStore() *agentStore {
	return &agentStore{agents: make(map[string]*agentRecord)}
}

func (s *agentStore) list() []*agentRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*agentRecord, 0, len(s.agents))
	for _, a := range s.agents {
		out = append(out, a)
	}
	return out
}

func (s *agentStore) get(id string) (*agentRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[id]
	return a, ok
}

func (s *agentStore) suspend(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[id]
	if !ok {
		return false
	}
	a.Suspended = true
	return true
}

func (s *agentStore) unsuspend(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[id]
	if !ok {
		return false
	}
	a.Suspended = false
	return true
}

func (s *agentStore) quarantine(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[id]
	if !ok {
		return false
	}
	a.Quarantined = true
	return true
}

// register adds or replaces an agent record.
func (s *agentStore) register(rec *agentRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[rec.AgentID] = rec
}

// incThreat increments the threat counter for an agent.
func (s *agentStore) incThreat(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.agents[id]; ok {
		a.ThreatCount++
	}
}

// incAction increments the action counter for an agent.
func (s *agentStore) incAction(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.agents[id]; ok {
		a.ActionCount++
	}
}

// ─── Stats helpers ────────────────────────────────────────────────────────────

// agentEventTypeStat holds a count for a named event type.
type agentEventTypeStat struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// agentStatsResponse is the response body for GET /api/v1/agentguard/stats.
type agentStatsResponse struct {
	TotalAgents    int                  `json:"total_agents"`
	ActiveAgents   int                  `json:"active_agents"`
	SuspendedCount int                  `json:"suspended_count"`
	QuarantineCount int                 `json:"quarantine_count"`
	TotalThreats   int                  `json:"total_threats"`
	TotalActions   int                  `json:"total_actions"`
	EventTypes     []agentEventTypeStat `json:"event_types"`
	Period         string               `json:"period"`
	ComputedAt     string               `json:"computed_at"`
}

// ─── Handler methods ──────────────────────────────────────────────────────────

// handleAgentGuardStats handles GET /api/v1/agentguard/stats.
func (s *Server) handleAgentGuardStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	agents := s.agentGuardStore.list()
	var suspended, quarantined int
	for _, a := range agents {
		if a.Suspended {
			suspended++
		}
		if a.Quarantined {
			quarantined++
		}
	}
	active := len(agents) - suspended - quarantined

	// Derive threats and actions by summing the counters on each registered agent
	// record. These are incremented in real-time as events arrive (via incThreat
	// and incAction), so they are always consistent with the per-agent cards in
	// the UI.
	threats := 0
	actions := 0
	for _, a := range agents {
		threats += a.ThreatCount
		actions += a.ActionCount
	}

	// Derive the event-type breakdown from the live event store (domain="agent").
	// This is the only stat that requires the ingest pipeline to be running.
	typeCounts := map[string]int{}
	allEvents, _ := s.events.List(1, 5000)
	for _, ev := range allEvents {
		domain, _ := ev["domain"].(string)
		if domain != "agent" {
			continue
		}
		meta, _ := ev["metadata"].(map[string]interface{})
		if meta == nil {
			continue
		}
		et, _ := meta["event_type"].(string)
		if et != "" && et != "agent_action_submitted" {
			typeCounts[et]++
		}
	}

	eventTypes := make([]agentEventTypeStat, 0, len(typeCounts))
	for t, c := range typeCounts {
		eventTypes = append(eventTypes, agentEventTypeStat{Type: t, Count: c})
	}

	writeJSON(w, http.StatusOK, agentStatsResponse{
		TotalAgents:     len(agents),
		ActiveAgents:    active,
		SuspendedCount:  suspended,
		QuarantineCount: quarantined,
		TotalThreats:    threats,
		TotalActions:    actions,
		EventTypes:      eventTypes,
		Period:          "24h",
		ComputedAt:      time.Now().UTC().Format(time.RFC3339),
	})
}

// handleAgentGuardAgents handles GET and POST /api/v1/agentguard/agents.
//
// GET  returns the full list of registered agents.
// POST registers a new agent (or replaces an existing record with the same agent_id).
func (s *Server) handleAgentGuardAgents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		agents := s.agentGuardStore.list()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"agents": agents,
			"total":  len(agents),
		})

	case http.MethodPost:
		var rec agentRecord
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		if rec.AgentID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent_id is required"})
			return
		}
		if rec.RegisteredAt.IsZero() {
			rec.RegisteredAt = time.Now().UTC()
		}
		s.agentGuardStore.register(&rec)
		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"registered": true,
			"agent_id":   rec.AgentID,
		})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// handleAgentGuardAgent handles GET /api/v1/agentguard/agents/{id}.
func (s *Server) handleAgentGuardAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/agentguard/agents/")
	// Strip any trailing action segment (e.g. /suspend).
	if idx := strings.Index(id, "/"); idx != -1 {
		id = id[:idx]
	}
	if id == "" {
		s.handleAgentGuardAgents(w, r)
		return
	}
	agent, ok := s.agentGuardStore.get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
		return
	}
	writeJSON(w, http.StatusOK, agent)
}

// handleAgentGuardAgentActions handles POST /api/v1/agentguard/agents/{id}/{action}
// where action is one of: suspend, unsuspend, quarantine.
func (s *Server) handleAgentGuardAgentActions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	// Path: /api/v1/agentguard/agents/{id}/{action}
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/v1/agentguard/agents/")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid path; expected /agents/{id}/{action}"})
		return
	}
	id, action := parts[0], parts[1]

	switch action {
	case "suspend":
		if !s.agentGuardStore.suspend(id) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"suspended": true, "agent_id": id})
	case "unsuspend":
		if !s.agentGuardStore.unsuspend(id) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"unsuspended": true, "agent_id": id})
	case "quarantine":
		if !s.agentGuardStore.quarantine(id) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"quarantined": true, "agent_id": id})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown action; valid: suspend, unsuspend, quarantine"})
	}
}

// handleAgentGuardEvents handles GET /api/v1/agentguard/events.
// Supports query params: agent_id, event_type, page, page_size.
func (s *Server) handleAgentGuardEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	q := r.URL.Query()
	filterAgentID := q.Get("agent_id")
	filterEventType := q.Get("event_type")
	page := parseIntParam(q.Get("page"), 1)
	pageSize := parseIntParam(q.Get("page_size"), 25)

	allEvents, _ := s.events.List(1, 5000)

	// Filter to domain="agent" events.
	var filtered []map[string]interface{}
	for _, ev := range allEvents {
		domain, _ := ev["domain"].(string)
		if domain != "agent" {
			continue
		}
		meta, _ := ev["metadata"].(map[string]interface{})
		if filterAgentID != "" {
			aid := ""
			if meta != nil {
				aid, _ = meta["agent_id"].(string)
			}
			if aid != filterAgentID {
				continue
			}
		}
		if filterEventType != "" {
			et := ""
			if meta != nil {
				et, _ = meta["event_type"].(string)
			}
			if et != filterEventType {
				continue
			}
		}
		filtered = append(filtered, ev)
	}

	total := len(filtered)
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	page_data := filtered[start:end]

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"events":    page_data,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// handleAgentGuardRules handles GET /api/v1/agentguard/rules.
func (s *Server) handleAgentGuardRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"rules": builtinAgentRules,
		"total": len(builtinAgentRules),
	})
}

// ─── Route dispatcher for /api/v1/agentguard/agents/ prefix ──────────────────

// handleAgentGuardAgentsPrefix dispatches requests under /api/v1/agentguard/agents/
// to either handleAgentGuardAgent (GET) or handleAgentGuardAgentActions (POST).
func (s *Server) handleAgentGuardAgentsPrefix(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/v1/agentguard/agents/")
	if strings.Contains(trimmed, "/") {
		// Has an action segment → action handler.
		s.handleAgentGuardAgentActions(w, r)
		return
	}
	// Single segment → individual agent detail.
	s.handleAgentGuardAgent(w, r)
}

// parseIntParam parses an integer query parameter, returning def on failure.
func parseIntParam(s string, def int) int {
	if s == "" {
		return def
	}
	var v int
	if _, err := parseIntFromStr(s, &v); err != nil {
		return def
	}
	return v
}

// parseIntFromStr is a thin wrapper to avoid importing strconv at package level.
func parseIntFromStr(s string, out *int) (int, error) {
	n := 0
	neg := false
	for i, c := range s {
		if i == 0 && c == '-' {
			neg = true
			continue
		}
		if c < '0' || c > '9' {
			return 0, &json.SyntaxError{}
		}
		n = n*10 + int(c-'0')
	}
	if neg {
		n = -n
	}
	*out = n
	return n, nil
}

// watchAgentEvents subscribes to the EventStore and keeps the AgentGuard
// store up-to-date with live data from the ingest pipeline. For every
// domain="agent" event:
//   - unknown agents are auto-registered from the event's metadata fields,
//   - ActionCount is incremented for every action event,
//   - ThreatCount is incremented for every violation event (anything other
//     than the baseline "agent_action_submitted" type).
//
// This eliminates the need for demo data: as soon as real AgentGuard sensors
// start publishing events, the console registry and stats reflect live state.
func (s *Server) watchAgentEvents(ctx context.Context) {
	ch := s.events.Subscribe()
	defer s.events.Unsubscribe(ch)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			domain, _ := ev["domain"].(string)
			if domain != "agent" {
				continue
			}
			meta, _ := ev["metadata"].(map[string]interface{})
			if meta == nil {
				continue
			}
			agentID, _ := meta["agent_id"].(string)
			if agentID == "" {
				continue
			}
			// Auto-register the agent the first time we see it.
			if _, exists := s.agentGuardStore.get(agentID); !exists {
				agentName, _ := meta["agent_name"].(string)
				agentType, _ := meta["agent_type"].(string)
				if agentName == "" {
					agentName = agentID
				}
				s.agentGuardStore.register(&agentRecord{
					AgentID:      agentID,
					AgentName:    agentName,
					AgentType:    agentType,
					RegisteredAt: time.Now().UTC(),
				})
			}
			// Every agent event counts as one action.
			s.agentGuardStore.incAction(agentID)
			// Violation events (not the baseline submission) count as threats.
			et, _ := meta["event_type"].(string)
			if et != "" && et != "agent_action_submitted" {
				s.agentGuardStore.incThreat(agentID)
			}
		case <-ctx.Done():
			return
		}
	}
}
