// Package consoleapi — config.go provides unified CRUD endpoints for runtime
// configuration across all OpenGuard functional domains:
// HostGuard, AgentGuard, CommsGuard, ModelGuard, and Baseline Policies.
//
// Routes (all under /api/v1/config/, JWT-authenticated):
//
//	GET  /api/v1/config/hostguard                   – sensor config + rules
//	PUT  /api/v1/config/hostguard                   – update sensor config
//	PUT  /api/v1/config/hostguard/rules/{id}         – enable/disable/adjust rule
//
//	GET  /api/v1/config/agentguard                  – agent rules
//	PUT  /api/v1/config/agentguard/rules/{id}        – enable/disable/adjust rule
//	GET  /api/v1/config/agentguard/tools             – per-agent tool allowlists
//	POST /api/v1/config/agentguard/tools             – add agent tool config
//	GET  /api/v1/config/agentguard/tools/{id}        – single agent tool config
//	PUT  /api/v1/config/agentguard/tools/{id}        – update agent tool config
//	DELETE /api/v1/config/agentguard/tools/{id}      – delete agent tool config
//
//	GET  /api/v1/config/commsguard                  – comms global settings + channels
//	PUT  /api/v1/config/commsguard                  – update global settings
//	PUT  /api/v1/config/commsguard/channels/{id}     – update a channel config
//
//	GET  /api/v1/config/modelguard                  – guardrail config
//	PUT  /api/v1/config/modelguard                  – update guardrail config
//
//	GET    /api/v1/config/policies                  – baseline policy rules
//	POST   /api/v1/config/policies                  – create a policy rule
//	PUT    /api/v1/config/policies/{id}              – update a policy rule
//	DELETE /api/v1/config/policies/{id}              – delete a policy rule
package consoleapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ─── Shared config types ──────────────────────────────────────────────────────

// ruleOverride holds mutable runtime overrides for a built-in detection rule.
type ruleOverride struct {
	Enabled  bool   `json:"enabled"`
	Severity string `json:"severity,omitempty"`
	Tier     string `json:"tier,omitempty"`
}

// hostSensorConfig holds HostGuard sensor threshold settings.
type hostSensorConfig struct {
	ScanIntervalSecs     int `json:"scan_interval_secs"`
	CPUAlertThresholdPct int `json:"cpu_alert_threshold_pct"`
	MemAlertThresholdMB  int `json:"mem_alert_threshold_mb"`
}

// agentToolCfg holds the tool/domain allowlist and quotas for a single agent.
type agentToolCfg struct {
	AgentID         string   `json:"agent_id"`
	AgentName       string   `json:"agent_name"`
	ApprovedTools   []string `json:"approved_tools"`
	ApprovedDomains []string `json:"approved_domains"`
	TokenQuota      int64    `json:"token_quota"`
	CallQuota       int64    `json:"call_quota"`
	CreatedAt       string   `json:"created_at"`
}

// policyRuleCfg is a mutable baseline policy rule.
type policyRuleCfg struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Action      string   `json:"action"` // "block" | "require_approval" | "allow"
	PolicyRef   string   `json:"policy_ref"`
	Enabled     bool     `json:"enabled"`
	Conditions  []string `json:"conditions"`
}

// ─── Domain config store ──────────────────────────────────────────────────────

// domainConfigStore holds all runtime-mutable configuration for all OpenGuard
// domains. It is initialised once in NewServer and mutated via the config API.
type domainConfigStore struct {
	mu sync.RWMutex

	// HostGuard
	hostRuleOverrides map[string]ruleOverride
	hostSensor        hostSensorConfig

	// AgentGuard
	agentRuleOverrides map[string]ruleOverride
	agentTools         map[string]*agentToolCfg
	agentToolOrder     []string

	// Baseline policies
	policyRules     map[string]*policyRuleCfg
	policyRuleOrder []string
}

func newDomainConfigStore() *domainConfigStore {
	now := time.Now().UTC().Format(time.RFC3339)

	tools := map[string]*agentToolCfg{
		"agent-finance": {
			AgentID:         "agent-finance",
			AgentName:       "FinanceAgent",
			ApprovedTools:   []string{"read_database", "generate_report", "send_internal_email"},
			ApprovedDomains: []string{"internal.corp"},
			TokenQuota:      50000,
			CallQuota:       200,
			CreatedAt:       now,
		},
		"agent-hr": {
			AgentID:         "agent-hr",
			AgentName:       "HRAgent",
			ApprovedTools:   []string{"read_hr_database", "schedule_meeting"},
			ApprovedDomains: []string{"calendar.corp", "hr.internal"},
			TokenQuota:      30000,
			CallQuota:       100,
			CreatedAt:       now,
		},
	}
	toolOrder := []string{"agent-finance", "agent-hr"}

	rules := map[string]*policyRuleCfg{
		"B-BLOCK-001":   {ID: "B-BLOCK-001", Description: "Prevent modification of policy files", Action: "block", PolicyRef: "C-008", Enabled: true, Conditions: []string{"target_file contains policy"}},
		"B-BLOCK-002":   {ID: "B-BLOCK-002", Description: "Prevent disabling logging or audit trails", Action: "block", PolicyRef: "C-004", Enabled: true, Conditions: []string{"action=disable_logging"}},
		"B-BLOCK-003":   {ID: "B-BLOCK-003", Description: "Prevent outbound transmission of secrets or credentials", Action: "block", PolicyRef: "C-002", Enabled: true, Conditions: []string{"content_type=credential", "destination=external"}},
		"B-BLOCK-004":   {ID: "B-BLOCK-004", Description: "Prevent unapproved privilege escalation", Action: "block", PolicyRef: "C-001", Enabled: true, Conditions: []string{"action=privilege_escalation", "approved=false"}},
		"B-APPROVE-001": {ID: "B-APPROVE-001", Description: "Require approval for bulk outbound (>100 recipients)", Action: "require_approval", PolicyRef: "C-003", Enabled: true, Conditions: []string{"recipient_count > 100"}},
		"B-APPROVE-002": {ID: "B-APPROVE-002", Description: "Require approval for first-time recipient with attachment", Action: "require_approval", PolicyRef: "C-003", Enabled: true, Conditions: []string{"first_time_recipient=true", "has_attachment=true"}},
		"B-APPROVE-003": {ID: "B-APPROVE-003", Description: "Require approval for token or credential revocation", Action: "require_approval", PolicyRef: "C-003", Enabled: true, Conditions: []string{"action=revoke_credential"}},
		"B-APPROVE-004": {ID: "B-APPROVE-004", Description: "Require approval to terminate critical services", Action: "require_approval", PolicyRef: "C-001", Enabled: true, Conditions: []string{"action=stop_service", "criticality=high"}},
		"B-APPROVE-005": {ID: "B-APPROVE-005", Description: "Require pre-authorisation for T4 emergency lockdown", Action: "require_approval", PolicyRef: "C-007", Enabled: true, Conditions: []string{"tier=T4", "action=emergency_lockdown"}},
		"B-ALLOW-001":   {ID: "B-ALLOW-001", Description: "Auto-allow signed templates sent to allowlisted recipients", Action: "allow", PolicyRef: "C-006", Enabled: true, Conditions: []string{"signed_template=true", "recipient=allowlisted"}},
		"B-ALLOW-002":   {ID: "B-ALLOW-002", Description: "Auto-allow low-risk allowlisted workflows within quota", Action: "allow", PolicyRef: "C-006", Enabled: true, Conditions: []string{"risk_level=low", "workflow=allowlisted", "within_quota=true"}},
		"B-ALLOW-003":   {ID: "B-ALLOW-003", Description: "Auto-allow read-only operations on public resources", Action: "allow", PolicyRef: "C-006", Enabled: true, Conditions: []string{"operation=read_only", "resource_scope=public"}},
	}
	ruleOrder := []string{
		"B-BLOCK-001", "B-BLOCK-002", "B-BLOCK-003", "B-BLOCK-004",
		"B-APPROVE-001", "B-APPROVE-002", "B-APPROVE-003", "B-APPROVE-004", "B-APPROVE-005",
		"B-ALLOW-001", "B-ALLOW-002", "B-ALLOW-003",
	}

	return &domainConfigStore{
		hostRuleOverrides:  make(map[string]ruleOverride),
		hostSensor:         hostSensorConfig{ScanIntervalSecs: 30, CPUAlertThresholdPct: 90, MemAlertThresholdMB: 2048},
		agentRuleOverrides: make(map[string]ruleOverride),
		agentTools:         tools,
		agentToolOrder:     toolOrder,
		policyRules:        rules,
		policyRuleOrder:    ruleOrder,
	}
}

// ─── Dispatcher ───────────────────────────────────────────────────────────────

// handleConfigPrefix dispatches all /api/v1/config/* requests to the
// domain-specific handler based on the first path segment.
func (s *Server) handleConfigPrefix(w http.ResponseWriter, r *http.Request) {
	// Trim the prefix and split into at most [domain, sub, id] segments.
	p := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/config"), "/")
	segs := strings.SplitN(p, "/", 3)

	domain := ""
	if len(segs) > 0 {
		domain = segs[0]
	}
	sub := ""
	if len(segs) > 1 {
		sub = segs[1]
	}
	id := ""
	if len(segs) > 2 {
		id = segs[2]
	}

	switch domain {
	case "hostguard":
		s.handleConfigHostGuard(w, r, sub, id)
	case "agentguard":
		s.handleConfigAgentGuard(w, r, sub, id)
	case "commsguard":
		s.handleConfigCommsGuard(w, r, sub, id)
	case "modelguard":
		s.handleConfigModelGuard(w, r)
	case "policies":
		// For /api/v1/config/policies, rule ID is in `sub`.
		s.handleConfigPolicies(w, r, sub)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown config domain"})
	}
}

// ─── HostGuard config ─────────────────────────────────────────────────────────

// hostRuleResp is the JSON shape returned for each HostGuard rule.
type hostRuleResp struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Tier        string   `json:"tier"`
	Responses   []string `json:"responses"`
	Enabled     bool     `json:"enabled"`
}

func (s *Server) handleConfigHostGuard(w http.ResponseWriter, r *http.Request, sub, id string) {
	switch {
	case sub == "":
		// GET /api/v1/config/hostguard  – return sensor config + rules with overrides applied.
		// PUT /api/v1/config/hostguard  – update sensor threshold settings.
		switch r.Method {
		case http.MethodGet:
			s.configStore.mu.RLock()
			sensor := s.configStore.hostSensor
			overrides := s.configStore.hostRuleOverrides
			s.configStore.mu.RUnlock()

			rules := make([]hostRuleResp, len(builtinHostRules))
			for i, rule := range builtinHostRules {
				rr := hostRuleResp{
					ID:          rule.ID,
					Name:        rule.Name,
					Description: rule.Description,
					Severity:    rule.Severity,
					Tier:        rule.Tier,
					Responses:   rule.Responses,
					Enabled:     rule.Enabled,
				}
				if ov, ok := overrides[rule.ID]; ok {
					rr.Enabled = ov.Enabled
					if ov.Severity != "" {
						rr.Severity = ov.Severity
					}
					if ov.Tier != "" {
						rr.Tier = ov.Tier
					}
				}
				rules[i] = rr
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"sensor_config": sensor,
				"rules":         rules,
			})

		case http.MethodPut:
			var cfg hostSensorConfig
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
				return
			}
			s.configStore.mu.Lock()
			if cfg.ScanIntervalSecs > 0 {
				s.configStore.hostSensor.ScanIntervalSecs = cfg.ScanIntervalSecs
			}
			if cfg.CPUAlertThresholdPct > 0 {
				s.configStore.hostSensor.CPUAlertThresholdPct = cfg.CPUAlertThresholdPct
			}
			if cfg.MemAlertThresholdMB > 0 {
				s.configStore.hostSensor.MemAlertThresholdMB = cfg.MemAlertThresholdMB
			}
			s.configStore.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})

		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}

	case sub == "rules" && id != "":
		// PUT /api/v1/config/hostguard/rules/{id}
		if r.Method != http.MethodPut {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		found := false
		for _, rule := range builtinHostRules {
			if rule.ID == id {
				found = true
				break
			}
		}
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
			return
		}
		var ov ruleOverride
		if err := json.NewDecoder(r.Body).Decode(&ov); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		s.configStore.mu.Lock()
		s.configStore.hostRuleOverrides[id] = ov
		s.configStore.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})

	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

// ─── AgentGuard config ────────────────────────────────────────────────────────

// agentRuleResp is the JSON shape returned for each AgentGuard rule.
type agentRuleResp struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Tier        string   `json:"tier"`
	Responses   []string `json:"responses"`
	Enabled     bool     `json:"enabled"`
}

func (s *Server) handleConfigAgentGuard(w http.ResponseWriter, r *http.Request, sub, id string) {
	switch {
	case sub == "":
		// GET /api/v1/config/agentguard – return agent rules with overrides applied.
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		s.configStore.mu.RLock()
		overrides := s.configStore.agentRuleOverrides
		s.configStore.mu.RUnlock()

		rules := make([]agentRuleResp, len(builtinAgentRules))
		for i, rule := range builtinAgentRules {
			rr := agentRuleResp{
				ID:          rule.ID,
				Name:        rule.Name,
				Description: rule.Description,
				Severity:    rule.Severity,
				Tier:        rule.Tier,
				Responses:   rule.Responses,
				Enabled:     rule.Enabled,
			}
			if ov, ok := overrides[rule.ID]; ok {
				rr.Enabled = ov.Enabled
				if ov.Severity != "" {
					rr.Severity = ov.Severity
				}
				if ov.Tier != "" {
					rr.Tier = ov.Tier
				}
			}
			rules[i] = rr
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"rules": rules})

	case sub == "rules" && id != "":
		// PUT /api/v1/config/agentguard/rules/{id}
		if r.Method != http.MethodPut {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		found := false
		for _, rule := range builtinAgentRules {
			if rule.ID == id {
				found = true
				break
			}
		}
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
			return
		}
		var ov ruleOverride
		if err := json.NewDecoder(r.Body).Decode(&ov); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		s.configStore.mu.Lock()
		s.configStore.agentRuleOverrides[id] = ov
		s.configStore.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})

	case sub == "tools":
		s.handleConfigAgentTools(w, r, id)

	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

// handleConfigAgentTools handles CRUD for per-agent tool allowlists.
func (s *Server) handleConfigAgentTools(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		// Collection-level operations.
		switch r.Method {
		case http.MethodGet:
			s.configStore.mu.RLock()
			tools := make([]agentToolCfg, 0, len(s.configStore.agentToolOrder))
			for _, aid := range s.configStore.agentToolOrder {
				if t, ok := s.configStore.agentTools[aid]; ok {
					tools = append(tools, *t)
				}
			}
			s.configStore.mu.RUnlock()
			writeJSON(w, http.StatusOK, map[string]interface{}{"tools": tools})

		case http.MethodPost:
			var cfg agentToolCfg
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
				return
			}
			if cfg.AgentID == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent_id is required"})
				return
			}
			cfg.CreatedAt = time.Now().UTC().Format(time.RFC3339)
			if cfg.ApprovedTools == nil {
				cfg.ApprovedTools = []string{}
			}
			if cfg.ApprovedDomains == nil {
				cfg.ApprovedDomains = []string{}
			}
			s.configStore.mu.Lock()
			if _, exists := s.configStore.agentTools[cfg.AgentID]; exists {
				s.configStore.mu.Unlock()
				writeJSON(w, http.StatusConflict, map[string]string{"error": "agent_id already exists"})
				return
			}
			clone := cfg
			s.configStore.agentTools[cfg.AgentID] = &clone
			s.configStore.agentToolOrder = append(s.configStore.agentToolOrder, cfg.AgentID)
			s.configStore.mu.Unlock()
			writeJSON(w, http.StatusCreated, map[string]string{"status": "created", "agent_id": cfg.AgentID})

		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
		return
	}

	// Single-item operations.
	switch r.Method {
	case http.MethodGet:
		s.configStore.mu.RLock()
		t, ok := s.configStore.agentTools[id]
		var snap agentToolCfg
		if ok {
			snap = *t
		}
		s.configStore.mu.RUnlock()
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeJSON(w, http.StatusOK, snap)

	case http.MethodPut:
		var patch agentToolCfg
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		s.configStore.mu.Lock()
		existing, ok := s.configStore.agentTools[id]
		if !ok {
			s.configStore.mu.Unlock()
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		if patch.AgentName != "" {
			existing.AgentName = patch.AgentName
		}
		if patch.ApprovedTools != nil {
			existing.ApprovedTools = patch.ApprovedTools
		}
		if patch.ApprovedDomains != nil {
			existing.ApprovedDomains = patch.ApprovedDomains
		}
		if patch.TokenQuota > 0 {
			existing.TokenQuota = patch.TokenQuota
		}
		if patch.CallQuota > 0 {
			existing.CallQuota = patch.CallQuota
		}
		s.configStore.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})

	case http.MethodDelete:
		s.configStore.mu.Lock()
		if _, ok := s.configStore.agentTools[id]; !ok {
			s.configStore.mu.Unlock()
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		delete(s.configStore.agentTools, id)
		newOrder := make([]string, 0, len(s.configStore.agentToolOrder))
		for _, aid := range s.configStore.agentToolOrder {
			if aid != id {
				newOrder = append(newOrder, aid)
			}
		}
		s.configStore.agentToolOrder = newOrder
		s.configStore.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// ─── CommsGuard config ────────────────────────────────────────────────────────

func (s *Server) handleConfigCommsGuard(w http.ResponseWriter, r *http.Request, sub, id string) {
	switch {
	case sub == "":
		switch r.Method {
		case http.MethodGet:
			s.commsConfig.mu.RLock()
			channels := make(map[string]interface{}, len(s.commsConfig.channels))
			for cid, cfg := range s.commsConfig.channels {
				channels[cid] = cfg
			}
			ca := s.commsConfig.ContentAnalysis
			bt := s.commsConfig.BulkThreshold
			bw := s.commsConfig.BulkWindowSec
			s.commsConfig.mu.RUnlock()
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"content_analysis": ca,
				"bulk_threshold":   bt,
				"bulk_window_sec":  bw,
				"channels":         channels,
			})

		case http.MethodPut:
			var body struct {
				ContentAnalysis *bool `json:"content_analysis"`
				BulkThreshold   *int  `json:"bulk_threshold"`
				BulkWindowSec   *int  `json:"bulk_window_sec"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
				return
			}
			s.commsConfig.mu.Lock()
			if body.ContentAnalysis != nil {
				s.commsConfig.ContentAnalysis = *body.ContentAnalysis
			}
			if body.BulkThreshold != nil && *body.BulkThreshold > 0 {
				s.commsConfig.BulkThreshold = *body.BulkThreshold
			}
			if body.BulkWindowSec != nil && *body.BulkWindowSec > 0 {
				s.commsConfig.BulkWindowSec = *body.BulkWindowSec
			}
			s.commsConfig.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})

		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}

	case sub == "channels" && id != "":
		// PUT /api/v1/config/commsguard/channels/{id}
		if r.Method != http.MethodPut {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var patch commsChannelConfig
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		s.commsConfig.mu.Lock()
		ch, ok := s.commsConfig.channels[id]
		if !ok {
			s.commsConfig.mu.Unlock()
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "channel not found"})
			return
		}
		ch.Enabled = patch.Enabled
		if patch.WebhookSecret != "" {
			ch.WebhookSecret = patch.WebhookSecret
		}
		if patch.VerifyToken != "" {
			ch.VerifyToken = patch.VerifyToken
		}
		if patch.AccountSID != "" {
			ch.AccountSID = patch.AccountSID
		}
		if patch.BearerToken != "" {
			ch.BearerToken = patch.BearerToken
		}
		if patch.BotToken != "" {
			ch.BotToken = patch.BotToken
		}
		if patch.WebhookURL != "" {
			ch.WebhookURL = patch.WebhookURL
		}
		s.commsConfig.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})

	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

// ─── ModelGuard config ────────────────────────────────────────────────────────

func (s *Server) handleConfigModelGuard(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snap := s.modelGuard.guardrails.snapshot()
		writeJSON(w, http.StatusOK, snap)

	case http.MethodPut:
		var patch guardrailConfig
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		s.modelGuard.guardrails.update(patch)
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// ─── Policies config ──────────────────────────────────────────────────────────

func (s *Server) handleConfigPolicies(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		// Collection-level operations.
		switch r.Method {
		case http.MethodGet:
			s.configStore.mu.RLock()
			policies := make([]policyRuleCfg, 0, len(s.configStore.policyRuleOrder))
			for _, rid := range s.configStore.policyRuleOrder {
				if rule, ok := s.configStore.policyRules[rid]; ok {
					policies = append(policies, *rule)
				}
			}
			s.configStore.mu.RUnlock()
			writeJSON(w, http.StatusOK, map[string]interface{}{"policies": policies})

		case http.MethodPost:
			var rule policyRuleCfg
			if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
				return
			}
			if rule.Description == "" || rule.Action == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "description and action are required"})
				return
			}
			if rule.Action != "block" && rule.Action != "require_approval" && rule.Action != "allow" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "action must be: block, require_approval, or allow"})
				return
			}
			if rule.ID == "" {
				prefix := "B-CUSTOM"
				switch rule.Action {
				case "block":
					prefix = "B-BLOCK"
				case "require_approval":
					prefix = "B-APPROVE"
				case "allow":
					prefix = "B-ALLOW"
				}
				rule.ID = fmt.Sprintf("%s-%05d", prefix, time.Now().UnixNano()%100000)
			}
			rule.Enabled = true
			if rule.Conditions == nil {
				rule.Conditions = []string{}
			}
			s.configStore.mu.Lock()
			if _, exists := s.configStore.policyRules[rule.ID]; exists {
				s.configStore.mu.Unlock()
				writeJSON(w, http.StatusConflict, map[string]string{"error": "policy ID already exists"})
				return
			}
			clone := rule
			s.configStore.policyRules[rule.ID] = &clone
			s.configStore.policyRuleOrder = append(s.configStore.policyRuleOrder, rule.ID)
			s.configStore.mu.Unlock()
			writeJSON(w, http.StatusCreated, map[string]interface{}{"status": "created", "id": rule.ID})

		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
		return
	}

	// Single-item operations.
	switch r.Method {
	case http.MethodPut:
		var patch policyRuleCfg
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		s.configStore.mu.Lock()
		existing, ok := s.configStore.policyRules[id]
		if !ok {
			s.configStore.mu.Unlock()
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy rule not found"})
			return
		}
		if patch.Description != "" {
			existing.Description = patch.Description
		}
		if patch.Action != "" {
			if patch.Action != "block" && patch.Action != "require_approval" && patch.Action != "allow" {
				s.configStore.mu.Unlock()
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid action"})
				return
			}
			existing.Action = patch.Action
		}
		if patch.PolicyRef != "" {
			existing.PolicyRef = patch.PolicyRef
		}
		if patch.Conditions != nil {
			existing.Conditions = patch.Conditions
		}
		existing.Enabled = patch.Enabled
		s.configStore.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})

	case http.MethodDelete:
		s.configStore.mu.Lock()
		if _, ok := s.configStore.policyRules[id]; !ok {
			s.configStore.mu.Unlock()
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy rule not found"})
			return
		}
		delete(s.configStore.policyRules, id)
		newOrder := make([]string, 0, len(s.configStore.policyRuleOrder))
		for _, rid := range s.configStore.policyRuleOrder {
			if rid != id {
				newOrder = append(newOrder, rid)
			}
		}
		s.configStore.policyRuleOrder = newOrder
		s.configStore.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}
