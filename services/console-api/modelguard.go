// Package consoleapi — modelguard.go provides the ModelGuard-specific REST API
// handlers: provider health status, guardrail configuration, model-call audit
// entries, and aggregate statistics.
package consoleapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ─── Guardrail config ─────────────────────────────────────────────────────────

// guardrailConfig holds the current ModelGuard guardrail settings.
type guardrailConfig struct {
	mu sync.RWMutex

	BlockOnInjection  bool    `json:"block_on_injection"`
	RedactCredentials bool    `json:"redact_credentials"`
	RedactPII         bool    `json:"redact_pii"`
	MaxPromptLength   int     `json:"max_prompt_length"`
	MinConfidence     float64 `json:"min_confidence"`
	RateLimitRPM      int     `json:"rate_limit_rpm"`
}

func newGuardrailConfig() *guardrailConfig {
	return &guardrailConfig{
		BlockOnInjection:  true,
		RedactCredentials: true,
		RedactPII:         true,
		MaxPromptLength:   8192,
		MinConfidence:     0.6,
		RateLimitRPM:      60,
	}
}

func (c *guardrailConfig) snapshot() guardrailConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return guardrailConfig{
		BlockOnInjection:  c.BlockOnInjection,
		RedactCredentials: c.RedactCredentials,
		RedactPII:         c.RedactPII,
		MaxPromptLength:   c.MaxPromptLength,
		MinConfidence:     c.MinConfidence,
		RateLimitRPM:      c.RateLimitRPM,
	}
}

func (c *guardrailConfig) update(patch guardrailConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.BlockOnInjection = patch.BlockOnInjection
	c.RedactCredentials = patch.RedactCredentials
	c.RedactPII = patch.RedactPII
	if patch.MaxPromptLength > 0 {
		c.MaxPromptLength = patch.MaxPromptLength
	}
	if patch.MinConfidence >= 0 && patch.MinConfidence <= 1 {
		c.MinConfidence = patch.MinConfidence
	}
	if patch.RateLimitRPM > 0 {
		c.RateLimitRPM = patch.RateLimitRPM
	}
}

// ─── Model call audit store ───────────────────────────────────────────────────

// modelCallEntry is a single model call audit record.
type modelCallEntry struct {
	CallID          string    `json:"call_id"`
	Timestamp       time.Time `json:"timestamp"`
	AgentID         string    `json:"agent_id"`
	Provider        string    `json:"provider"`
	RiskLevel       string    `json:"risk_level"`
	RoutingStrategy string    `json:"routing_strategy"`
	LatencyMS       int64     `json:"latency_ms"`
	TokenCount      int       `json:"token_count"`
	Redactions      []string  `json:"redactions,omitempty"`
	Blocked         bool      `json:"blocked"`
	InputHash       string    `json:"input_hash"`
	OutputHash      string    `json:"output_hash"`
}

// modelCallStore is an in-memory ring-buffer of recent model call audit entries,
// seeded with representative demo data so the UI is immediately useful.
type modelCallStore struct {
	mu      sync.RWMutex
	entries []modelCallEntry
	maxSize int
}

func newModelCallStore() *modelCallStore {
	now := time.Now().UTC()
	demos := []modelCallEntry{
		{
			CallID: "mc-001", AgentID: "agent-llm-001", Provider: "openai-codex",
			RiskLevel: "low", RoutingStrategy: "single", LatencyMS: 342, TokenCount: 1200,
			Blocked: false, InputHash: "a1b2c3d4", OutputHash: "e5f6a7b8",
			Timestamp: now.Add(-2 * time.Minute),
		},
		{
			CallID: "mc-002", AgentID: "agent-auto-002", Provider: "anthropic-claude",
			RiskLevel: "medium", RoutingStrategy: "fallback", LatencyMS: 780, TokenCount: 2400,
			Blocked: false, InputHash: "b2c3d4e5", OutputHash: "f6a7b8c9",
			Redactions: []string{"pii_email"},
			Timestamp: now.Add(-5 * time.Minute),
		},
		{
			CallID: "mc-003", AgentID: "agent-llm-003", Provider: "google-gemini",
			RiskLevel: "high", RoutingStrategy: "quorum", LatencyMS: 1430, TokenCount: 3100,
			Blocked: false, InputHash: "c3d4e5f6", OutputHash: "a7b8c9d0",
			Timestamp: now.Add(-9 * time.Minute),
		},
		{
			CallID: "mc-004", AgentID: "agent-deploy-004", Provider: "openai-codex",
			RiskLevel: "critical", RoutingStrategy: "quorum", LatencyMS: 1920, TokenCount: 4200,
			Blocked: true, InputHash: "d4e5f6a7", OutputHash: "",
			Redactions: []string{"injection_detected"},
			Timestamp: now.Add(-15 * time.Minute),
		},
		{
			CallID: "mc-005", AgentID: "agent-comms-005", Provider: "anthropic-claude",
			RiskLevel: "low", RoutingStrategy: "single", LatencyMS: 265, TokenCount: 980,
			Blocked: false, InputHash: "e5f6a7b8", OutputHash: "b9c0d1e2",
			Timestamp: now.Add(-22 * time.Minute),
		},
		{
			CallID: "mc-006", AgentID: "agent-llm-001", Provider: "openai-codex",
			RiskLevel: "medium", RoutingStrategy: "single", LatencyMS: 410, TokenCount: 1650,
			Blocked: false, InputHash: "f6a7b8c9", OutputHash: "c0d1e2f3",
			Redactions: []string{"pii_phone"},
			Timestamp: now.Add(-31 * time.Minute),
		},
		{
			CallID: "mc-007", AgentID: "agent-auto-002", Provider: "google-gemini",
			RiskLevel: "low", RoutingStrategy: "single", LatencyMS: 290, TokenCount: 870,
			Blocked: false, InputHash: "a7b8c9d0", OutputHash: "d1e2f3a4",
			Timestamp: now.Add(-45 * time.Minute),
		},
		{
			CallID: "mc-008", AgentID: "agent-llm-003", Provider: "openai-codex",
			RiskLevel: "high", RoutingStrategy: "quorum", LatencyMS: 1760, TokenCount: 3800,
			Blocked: false, InputHash: "b8c9d0e1", OutputHash: "e2f3a4b5",
			Timestamp: now.Add(-58 * time.Minute),
		},
		{
			CallID: "mc-009", AgentID: "agent-comms-005", Provider: "anthropic-claude",
			RiskLevel: "low", RoutingStrategy: "single", LatencyMS: 310, TokenCount: 1100,
			Blocked: false, InputHash: "c9d0e1f2", OutputHash: "f3a4b5c6",
			Timestamp: now.Add(-72 * time.Minute),
		},
		{
			CallID: "mc-010", AgentID: "agent-deploy-004", Provider: "openai-codex",
			RiskLevel: "critical", RoutingStrategy: "quorum", LatencyMS: 2100, TokenCount: 5000,
			Blocked: true, InputHash: "d0e1f2a3", OutputHash: "",
			Redactions: []string{"credential_redacted", "injection_detected"},
			Timestamp: now.Add(-90 * time.Minute),
		},
	}
	return &modelCallStore{
		entries: demos,
		maxSize: 500,
	}
}

// add appends a call entry, evicting the oldest when full.
func (s *modelCallStore) add(e modelCallEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) >= s.maxSize {
		s.entries = s.entries[1:]
	}
	s.entries = append(s.entries, e)
}

// list returns entries in reverse-chronological order, applying optional filters.
func (s *modelCallStore) list(provider, riskLevel string, page, pageSize int) ([]modelCallEntry, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filtered []modelCallEntry
	for i := len(s.entries) - 1; i >= 0; i-- {
		e := s.entries[i]
		if provider != "" && e.Provider != provider {
			continue
		}
		if riskLevel != "" && e.RiskLevel != riskLevel {
			continue
		}
		filtered = append(filtered, e)
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
	return filtered[start:end], total
}

// stats returns aggregate counts over all stored entries.
func (s *modelCallStore) stats() (total, blocked int, providers, strategies, riskLevels map[string]int, totalLatency int64, totalTokens int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	providers = map[string]int{}
	strategies = map[string]int{}
	riskLevels = map[string]int{}
	for _, e := range s.entries {
		total++
		if e.Blocked {
			blocked++
		}
		providers[e.Provider]++
		strategies[e.RoutingStrategy]++
		riskLevels[e.RiskLevel]++
		totalLatency += e.LatencyMS
		totalTokens += e.TokenCount
	}
	return
}

// ─── ModelGuard store (attached to Server) ────────────────────────────────────

// modelGuardState bundles all ModelGuard runtime state.
type modelGuardState struct {
	calls      *modelCallStore
	guardrails *guardrailConfig
}

func newModelGuardState() *modelGuardState {
	return &modelGuardState{
		calls:      newModelCallStore(),
		guardrails: newGuardrailConfig(),
	}
}

// ─── Provider health ──────────────────────────────────────────────────────────

// providerHealthEntry is the health record for a single model provider.
type providerHealthEntry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Healthy     bool   `json:"healthy"`
	LatencyMS   int64  `json:"latency_ms"`
	LastChecked string `json:"last_checked"`
	Error       string `json:"error,omitempty"`
}

// builtinProviders enumerates the supported model providers.
var builtinProviders = []struct{ id, name string }{
	{"openai-codex", "OpenAI Codex (GPT-4o)"},
	{"anthropic-claude", "Anthropic Claude 3.5 Sonnet"},
	{"google-gemini", "Google Gemini 1.5 Pro"},
}

// modelGuardProviderHealth synthesises health entries. When the active provider
// matches, it is considered reachable (assumed live via NATS); others reflect
// reachability based on whether credentials are stored.
func (s *Server) modelGuardProviderHealth() []providerHealthEntry {
	active := s.activeProvider.Load().(string)
	now := time.Now().UTC().Format(time.RFC3339)

	entries := make([]providerHealthEntry, 0, len(builtinProviders))
	for _, p := range builtinProviders {
		_, credOK := s.userCreds.Load(credKey("admin", p.id))
		healthy := (p.id == active) || credOK
		latency := int64(0)
		errMsg := ""
		if healthy {
			// Simulated check latency — in production this would ping the provider.
			latency = 120 + int64(len(p.id)*7)
		} else {
			errMsg = "no credentials configured"
		}
		entries = append(entries, providerHealthEntry{
			ID:          p.id,
			Name:        p.name,
			Healthy:     healthy,
			LatencyMS:   latency,
			LastChecked: now,
			Error:       errMsg,
		})
	}
	return entries
}

// ─── Response shapes ──────────────────────────────────────────────────────────

type kvStat struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

type modelGuardStatsResponse struct {
	TotalCalls        int      `json:"total_calls"`
	BlockedCalls      int      `json:"blocked_calls"`
	AvgLatencyMS      int64    `json:"avg_latency_ms"`
	AvgTokenCount     int      `json:"avg_token_count"`
	AvgConfidence     float64  `json:"avg_confidence"`
	ProviderBreakdown []kvStat `json:"provider_breakdown"`
	StrategyBreakdown []kvStat `json:"strategy_breakdown"`
	RiskBreakdown     []kvStat `json:"risk_breakdown"`
	ActiveProvider    string   `json:"active_provider"`
	Period            string   `json:"period"`
	ComputedAt        string   `json:"computed_at"`
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

// handleModelGuardStats handles GET /api/v1/modelguard/stats.
func (s *Server) handleModelGuardStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	total, blocked, provMap, stratMap, riskMap, latSum, tokSum := s.modelGuard.calls.stats()

	avgLatency := int64(0)
	avgTokens := 0
	if total > 0 {
		avgLatency = latSum / int64(total)
		avgTokens = tokSum / total
	}

	toSlice := func(m map[string]int) []kvStat {
		out := make([]kvStat, 0, len(m))
		for k, v := range m {
			out = append(out, kvStat{Label: k, Count: v})
		}
		return out
	}

	writeJSON(w, http.StatusOK, modelGuardStatsResponse{
		TotalCalls:        total,
		BlockedCalls:      blocked,
		AvgLatencyMS:      avgLatency,
		AvgTokenCount:     avgTokens,
		AvgConfidence:     0.82, // synthetic: real value comes from ledger in production
		ProviderBreakdown: toSlice(provMap),
		StrategyBreakdown: toSlice(stratMap),
		RiskBreakdown:     toSlice(riskMap),
		ActiveProvider:    s.activeProvider.Load().(string),
		Period:            "24h",
		ComputedAt:        time.Now().UTC().Format(time.RFC3339),
	})
}

// handleModelGuardAudit handles GET /api/v1/modelguard/audit.
// Query params: provider, risk_level, page, page_size.
func (s *Server) handleModelGuardAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	q := r.URL.Query()
	provider := q.Get("provider")
	riskLevel := q.Get("risk_level")
	page := parseIntParam(q.Get("page"), 1)
	pageSize := parseIntParam(q.Get("page_size"), 25)

	entries, total := s.modelGuard.calls.list(provider, riskLevel, page, pageSize)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries":   entries,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// handleModelGuardProviders handles GET /api/v1/modelguard/providers.
func (s *Server) handleModelGuardProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"providers": s.modelGuardProviderHealth(),
	})
}

// handleModelGuardGuardrails handles GET and POST /api/v1/modelguard/guardrails.
//
// GET  returns the current guardrail configuration.
// POST updates the configuration; unknown fields are ignored.
func (s *Server) handleModelGuardGuardrails(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snap := s.modelGuard.guardrails.snapshot()
		writeJSON(w, http.StatusOK, snap)

	case http.MethodPost:
		var patch guardrailConfig
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		s.modelGuard.guardrails.update(patch)
		snap := s.modelGuard.guardrails.snapshot()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status": "updated",
			"config": snap,
		})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// handleModelGuardRequests handles POST /api/v1/modelguard/requests — allows
// the console to inject a synthetic model call record (used by tests and the
// model-gateway-agent once integrated).
func (s *Server) handleModelGuardRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var entry modelCallEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	// Sanitise provider value — only accept known providers.
	known := map[string]bool{
		"openai-codex":     true,
		"anthropic-claude": true,
		"google-gemini":    true,
	}
	if !known[entry.Provider] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown provider"})
		return
	}
	s.modelGuard.calls.add(entry)
	writeJSON(w, http.StatusCreated, map[string]string{"status": "recorded"})
}

// handleModelGuardPrefix dispatches all /api/v1/modelguard/* requests.
func (s *Server) handleModelGuardPrefix(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/modelguard")
	path = strings.TrimPrefix(path, "/")

	switch {
	case path == "stats":
		s.handleModelGuardStats(w, r)
	case path == "audit":
		s.handleModelGuardAudit(w, r)
	case path == "providers":
		s.handleModelGuardProviders(w, r)
	case path == "guardrails":
		s.handleModelGuardGuardrails(w, r)
	case path == "requests":
		s.handleModelGuardRequests(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}
