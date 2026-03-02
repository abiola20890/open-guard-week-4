// Package guardrails provides prompt sanitization and output validation
// for the OpenGuard model gateway pipeline.
package guardrails

import (
	"fmt"

	mg "github.com/DiniMuhd7/openguard/model-gateway/interfaces"
)

// validSeverities holds the allowed RiskLevel values for classification results.
// "info" is included per the output validation spec even though it is not a
// named constant in the interfaces package.
var validSeverities = map[mg.RiskLevel]bool{
	"info":          true,
	mg.RiskLow:      true,
	mg.RiskMedium:   true,
	mg.RiskHigh:     true,
	mg.RiskCritical: true,
}

// ValidatorConfig holds configuration for the Validator.
type ValidatorConfig struct {
	// MinConfidenceThreshold, when greater than 0, requires all confidence
	// values to be >= this threshold.
	MinConfidenceThreshold float64
}

// Validator enforces output schemas for model provider results.
type Validator struct {
	cfg ValidatorConfig
}

// NewValidator constructs a Validator with the provided configuration.
func NewValidator(cfg ValidatorConfig) *Validator {
	return &Validator{cfg: cfg}
}

// ValidateAnalysis validates an AnalysisResult returned by a model provider.
// It requires a non-empty Summary and Confidence in [0.0, 1.0].
func (v *Validator) ValidateAnalysis(r *mg.AnalysisResult) error {
	if r == nil {
		return fmt.Errorf("output validation: analysis result is nil")
	}
	if r.Summary == "" {
		return fmt.Errorf("output validation: analysis summary is empty")
	}
	if r.Confidence < 0.0 || r.Confidence > 1.0 {
		return fmt.Errorf("output validation: confidence %.4g out of range [0,1]", r.Confidence)
	}
	if v.cfg.MinConfidenceThreshold > 0 && r.Confidence < v.cfg.MinConfidenceThreshold {
		return fmt.Errorf("output validation: confidence %.4g below minimum threshold %.4g",
			r.Confidence, v.cfg.MinConfidenceThreshold)
	}
	return nil
}

// ValidateClassification validates a ClassificationResult returned by a model provider.
// It requires a non-empty Rationale, Confidence in [0.0, 1.0], RiskScore in [0.0, 100.0],
// and RiskLevel to be one of info/low/medium/high/critical.
func (v *Validator) ValidateClassification(r *mg.ClassificationResult) error {
	if r == nil {
		return fmt.Errorf("output validation: classification result is nil")
	}
	if r.Rationale == "" {
		return fmt.Errorf("output validation: classification rationale is empty")
	}
	if r.Confidence < 0.0 || r.Confidence > 1.0 {
		return fmt.Errorf("output validation: confidence %.4g out of range [0,1]", r.Confidence)
	}
	if r.RiskScore < 0.0 || r.RiskScore > 100.0 {
		return fmt.Errorf("output validation: risk score %.4g out of range [0,100]", r.RiskScore)
	}
	if !validSeverities[r.RiskLevel] {
		return fmt.Errorf("output validation: invalid risk level %q", r.RiskLevel)
	}
	if v.cfg.MinConfidenceThreshold > 0 && r.Confidence < v.cfg.MinConfidenceThreshold {
		return fmt.Errorf("output validation: confidence %.4g below minimum threshold %.4g",
			r.Confidence, v.cfg.MinConfidenceThreshold)
	}
	return nil
}

// ValidateActions validates a slice of ActionProposals returned by a model provider.
// It requires at least one proposal and each proposal to have a non-empty Actions slice.
func (v *Validator) ValidateActions(proposals []mg.ActionProposal) error {
	if len(proposals) == 0 {
		return fmt.Errorf("output validation: action proposals list is empty")
	}
	for i, p := range proposals {
		if len(p.Actions) == 0 {
			return fmt.Errorf("output validation: proposal %d has no actions", i)
		}
		for j, a := range p.Actions {
			if a.Type == "" {
				return fmt.Errorf("output validation: proposal %d action %d has empty type", i, j)
			}
		}
	}
	return nil
}

// ValidateExplanation validates an Explanation returned by a model provider.
// It requires a non-empty EvidenceSummary and at least one PolicyCitation.
func (v *Validator) ValidateExplanation(e *mg.Explanation) error {
	if e == nil {
		return fmt.Errorf("output validation: explanation is nil")
	}
	if e.EvidenceSummary == "" {
		return fmt.Errorf("output validation: explanation summary is empty")
	}
	if len(e.PolicyCitations) == 0 {
		return fmt.Errorf("output validation: explanation policy citations are empty")
	}
	return nil
}
