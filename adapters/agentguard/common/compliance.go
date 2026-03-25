// Package agentguardcommon provides shared types and utilities for the AgentGuard sensor.
package agentguardcommon

import "strings"

// ActionRequest describes an action submitted by an agent for policy evaluation.
type ActionRequest struct {
	// AgentID is the unique ID of the agent submitting the action.
	AgentID string
	// ActionType is the category of action the agent is attempting.
	ActionType string
	// ToolName is the name of the tool being invoked (empty if not a tool call).
	ToolName string
	// TargetDomain is the outbound domain being contacted (empty if not applicable).
	TargetDomain string
	// TargetResource is the resource or path targeted by the action.
	TargetResource string
	// Payload contains arbitrary action parameters for injection pattern scanning.
	Payload map[string]interface{}
}

// ViolationResult holds the outcome of a policy compliance check.
type ViolationResult struct {
	// Violations is the list of indicator strings describing each detected violation.
	Violations []string
	// ConditionsCount is the number of violation conditions matched.
	ConditionsCount int
	// PolicyMatch is "allow" if no violations, "deny" if any violations, "none" if unevaluated.
	PolicyMatch string
	// ShouldBlock indicates the action must be blocked.
	ShouldBlock bool
	// ShouldSuspend indicates the agent should be suspended.
	ShouldSuspend bool
	// ShouldQuarantine indicates the agent should be quarantined.
	// Triggered by self_policy_modification or ≥3 simultaneous violations.
	ShouldQuarantine bool
}

// PolicyComplianceChecker evaluates agent action requests against registered profiles.
type PolicyComplianceChecker struct{}

// NewPolicyComplianceChecker creates a new PolicyComplianceChecker.
func NewPolicyComplianceChecker() *PolicyComplianceChecker {
	return &PolicyComplianceChecker{}
}

// directChannelActions is the set of action types that constitute direct channel access.
var directChannelActions = map[string]bool{
	"send_whatsapp":      true,
	"send_telegram":      true,
	"send_sms":           true,
	"send_email_direct":  true,
	"post_twitter":       true,
	"post_facebook":      true,
}

// policyModificationActions is the set of action types that constitute self-policy modification.
var policyModificationActions = map[string]bool{
	"modify_policy":  true,
	"update_policy":  true,
	"patch_policy":   true,
	"delete_policy":  true,
	"disable_rule":   true,
}

// dataExfiltrationActions is the set of action types that constitute data exfiltration attempts.
var dataExfiltrationActions = map[string]bool{
	"bulk_export":          true,
	"upload_to_s3":         true,
	"write_to_external_db": true,
	"send_bulk_data":       true,
}

// promptInjectionPatterns is the list of known prompt injection strings.
var promptInjectionPatterns = []string{
	"ignore previous instructions",
	"disregard all prior",
	"system: ",
	"<|im_start|>",
	"###instruction",
	"you are now",
	"forget everything",
	"new instructions:",
}

// Check evaluates the given ActionRequest against the agent's profile and returns detected violations.
func (c *PolicyComplianceChecker) Check(profile *AgentProfile, req *ActionRequest) ViolationResult {
	// Early-return for agents that are already suspended or quarantined.
	// These states are unconditional hard blocks — no further checks are needed
	// and running additional checks on a suspended/quarantined agent would produce
	// misleading compound violations that confuse downstream event consumers.
	if profile.Quarantined {
		return ViolationResult{
			Violations:       []string{"agent_quarantined"},
			ConditionsCount:  1,
			PolicyMatch:      "deny",
			ShouldBlock:      true,
			ShouldSuspend:    false,
			ShouldQuarantine: false, // already quarantined
		}
	}
	if profile.Suspended {
		return ViolationResult{
			Violations:       []string{"agent_suspended"},
			ConditionsCount:  1,
			PolicyMatch:      "deny",
			ShouldBlock:      true,
			ShouldSuspend:    false, // already suspended
			ShouldQuarantine: false,
		}
	}

	var violations []string

	// 1. Unapproved tool use.
	if req.ToolName != "" && !containsString(profile.ApprovedTools, req.ToolName) {
		violations = append(violations, "unapproved_tool_use")
	}

	// 2. Unsanctioned outbound domain.
	if req.TargetDomain != "" && !containsString(profile.ApprovedDomains, req.TargetDomain) {
		violations = append(violations, "unsanctioned_outreach")
	}

	// 3. Direct channel access.
	if directChannelActions[req.ActionType] {
		violations = append(violations, "direct_channel_access")
	}

	// 4. Self-policy modification (critical — triggers immediate quarantine).
	if policyModificationActions[req.ActionType] {
		violations = append(violations, "self_policy_modification")
	}

	// 5. Prompt injection in payload and target resource (critical — triggers immediate suspension).
	if containsInjectionPattern(req.Payload, req.TargetResource) {
		violations = append(violations, "prompt_injection")
	}

	// 6. Data exfiltration attempt.
	if dataExfiltrationActions[req.ActionType] {
		violations = append(violations, "data_exfiltration")
	}

	conditionsCount := len(violations)
	policyMatch := "allow"
	if conditionsCount > 0 {
		policyMatch = "deny"
	}

	shouldBlock := conditionsCount > 0
	shouldSuspend := conditionsCount >= 2 ||
		containsString(violations, "self_policy_modification") ||
		containsString(violations, "prompt_injection")
	// Quarantine is triggered by self-policy modification (constitutional hard rule)
	// or by ≥3 simultaneous violations (multi-condition escalation).
	shouldQuarantine := containsString(violations, "self_policy_modification") || conditionsCount >= 3

	return ViolationResult{
		Violations:       violations,
		ConditionsCount:  conditionsCount,
		PolicyMatch:      policyMatch,
		ShouldBlock:      shouldBlock,
		ShouldSuspend:    shouldSuspend,
		ShouldQuarantine: shouldQuarantine,
	}
}

// containsString returns true if target is in the slice.
func containsString(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

// containsInjectionPattern checks payload values and targetResource for prompt injection patterns.
func containsInjectionPattern(payload map[string]interface{}, targetResource string) bool {
	check := func(s string) bool {
		lower := strings.ToLower(s)
		for _, pattern := range promptInjectionPatterns {
			if strings.Contains(lower, strings.ToLower(pattern)) {
				return true
			}
		}
		return false
	}

	if check(targetResource) {
		return true
	}
	for _, v := range payload {
		if s, ok := v.(string); ok {
			if check(s) {
				return true
			}
		}
	}
	return false
}
