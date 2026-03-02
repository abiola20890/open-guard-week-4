// Package agentguardcommon provides shared types and utilities for the AgentGuard sensor.
package agentguardcommon

import (
	"sync"
	"time"
)

// AgentProfile represents a registered AI agent and its operational constraints.
type AgentProfile struct {
	// AgentID is the unique identifier for the agent.
	AgentID string
	// AgentName is the human-readable name of the agent.
	AgentName string
	// AgentType is the agent category (e.g. "llm_assistant", "automation_bot", "code_agent").
	AgentType string
	// ApprovedTools is the allowlist of tool names the agent may invoke.
	ApprovedTools []string
	// ApprovedDomains is the allowlist of outbound domains the agent may contact.
	ApprovedDomains []string
	// TokenQuota is the maximum tokens per quota window (0 = unlimited).
	TokenQuota int64
	// CallQuota is the maximum API calls per quota window (0 = unlimited).
	CallQuota int64
	// QuotaWindow is the duration of the quota measurement window.
	QuotaWindow time.Duration
	// Suspended indicates the agent is suspended and cannot perform actions.
	Suspended bool
	// Quarantined indicates the agent is quarantined due to a critical violation.
	Quarantined bool
}

// AgentRegistry is a thread-safe in-memory store of AgentProfiles.
type AgentRegistry struct {
	mu     sync.RWMutex
	agents map[string]*AgentProfile
}

// NewAgentRegistry creates a new empty AgentRegistry.
func NewAgentRegistry() *AgentRegistry {
	return &AgentRegistry{
		agents: make(map[string]*AgentProfile),
	}
}

// Register adds or replaces an AgentProfile in the registry.
func (r *AgentRegistry) Register(profile *AgentProfile) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.agents[profile.AgentID] = profile
}

// Get retrieves an AgentProfile by agent ID. Returns false if not found.
func (r *AgentRegistry) Get(agentID string) (*AgentProfile, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.agents[agentID]
	return p, ok
}

// Suspend marks the agent as suspended. Returns false if the agent is not found.
func (r *AgentRegistry) Suspend(agentID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.agents[agentID]
	if !ok {
		return false
	}
	p.Suspended = true
	return true
}

// Unsuspend clears the suspended flag for the agent. Returns false if not found.
func (r *AgentRegistry) Unsuspend(agentID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.agents[agentID]
	if !ok {
		return false
	}
	p.Suspended = false
	return true
}

// Quarantine marks the agent as quarantined. Returns false if the agent is not found.
func (r *AgentRegistry) Quarantine(agentID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.agents[agentID]
	if !ok {
		return false
	}
	p.Quarantined = true
	return true
}

// List returns all registered AgentProfiles.
func (r *AgentRegistry) List() []*AgentProfile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*AgentProfile, 0, len(r.agents))
	for _, p := range r.agents {
		result = append(result, p)
	}
	return result
}
