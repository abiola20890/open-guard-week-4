package guardrails

import (
	"testing"

	mg "github.com/DiniMuhd7/openguard/model-gateway/interfaces"
)

// --- AnalysisResult ---

func TestValidateAnalysis_Valid(t *testing.T) {
	v := NewValidator(ValidatorConfig{})
	r := &mg.AnalysisResult{
		ProviderName: "test",
		Summary:      "Suspicious login detected",
		Confidence:   0.85,
		RiskLevel:    mg.RiskHigh,
	}
	if err := v.ValidateAnalysis(r); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidateAnalysis_MissingSummary(t *testing.T) {
	v := NewValidator(ValidatorConfig{})
	r := &mg.AnalysisResult{Confidence: 0.5}
	if err := v.ValidateAnalysis(r); err == nil {
		t.Fatal("expected error for empty summary")
	}
}

func TestValidateAnalysis_ConfidenceTooHigh(t *testing.T) {
	v := NewValidator(ValidatorConfig{})
	r := &mg.AnalysisResult{Summary: "ok", Confidence: 1.5}
	if err := v.ValidateAnalysis(r); err == nil {
		t.Fatal("expected error for confidence > 1")
	}
}

func TestValidateAnalysis_ConfidenceNegative(t *testing.T) {
	v := NewValidator(ValidatorConfig{})
	r := &mg.AnalysisResult{Summary: "ok", Confidence: -0.1}
	if err := v.ValidateAnalysis(r); err == nil {
		t.Fatal("expected error for confidence < 0")
	}
}

func TestValidateAnalysis_MinConfidenceThreshold(t *testing.T) {
	v := NewValidator(ValidatorConfig{MinConfidenceThreshold: 0.7})
	r := &mg.AnalysisResult{Summary: "ok", Confidence: 0.5}
	if err := v.ValidateAnalysis(r); err == nil {
		t.Fatal("expected error for confidence below threshold")
	}
}

func TestValidateAnalysis_MinConfidenceThreshold_Passes(t *testing.T) {
	v := NewValidator(ValidatorConfig{MinConfidenceThreshold: 0.7})
	r := &mg.AnalysisResult{Summary: "ok", Confidence: 0.9}
	if err := v.ValidateAnalysis(r); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// --- ClassificationResult ---

func TestValidateClassification_Valid(t *testing.T) {
	v := NewValidator(ValidatorConfig{})
	r := &mg.ClassificationResult{
		ProviderName: "test",
		RiskLevel:    mg.RiskHigh,
		RiskScore:    75.0,
		Confidence:   0.9,
		Rationale:    "Multiple failed login attempts",
	}
	if err := v.ValidateClassification(r); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidateClassification_MissingRationale(t *testing.T) {
	v := NewValidator(ValidatorConfig{})
	r := &mg.ClassificationResult{RiskLevel: mg.RiskLow, Confidence: 0.5, RiskScore: 10}
	if err := v.ValidateClassification(r); err == nil {
		t.Fatal("expected error for empty rationale")
	}
}

func TestValidateClassification_InvalidSeverity(t *testing.T) {
	v := NewValidator(ValidatorConfig{})
	r := &mg.ClassificationResult{
		Rationale:  "ok",
		RiskLevel:  "unknown",
		Confidence: 0.5,
		RiskScore:  50,
	}
	if err := v.ValidateClassification(r); err == nil {
		t.Fatal("expected error for invalid severity")
	}
}

func TestValidateClassification_RiskScoreOutOfRange(t *testing.T) {
	v := NewValidator(ValidatorConfig{})
	r := &mg.ClassificationResult{
		Rationale:  "ok",
		RiskLevel:  mg.RiskMedium,
		Confidence: 0.5,
		RiskScore:  150.0,
	}
	if err := v.ValidateClassification(r); err == nil {
		t.Fatal("expected error for risk score > 100")
	}
}

func TestValidateClassification_ConfidenceOutOfRange(t *testing.T) {
	v := NewValidator(ValidatorConfig{})
	r := &mg.ClassificationResult{
		Rationale:  "ok",
		RiskLevel:  mg.RiskMedium,
		Confidence: 1.5,
		RiskScore:  50,
	}
	if err := v.ValidateClassification(r); err == nil {
		t.Fatal("expected error for confidence out of range")
	}
}

// --- ActionProposal ---

func TestValidateActions_Valid(t *testing.T) {
	v := NewValidator(ValidatorConfig{})
	proposals := []mg.ActionProposal{
		{
			ProviderName: "test",
			Actions: []mg.ProposedAction{
				{ID: "1", Type: "isolate", Target: "host-1"},
			},
		},
	}
	if err := v.ValidateActions(proposals); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidateActions_EmptyList(t *testing.T) {
	v := NewValidator(ValidatorConfig{})
	if err := v.ValidateActions(nil); err == nil {
		t.Fatal("expected error for empty proposals list")
	}
	if err := v.ValidateActions([]mg.ActionProposal{}); err == nil {
		t.Fatal("expected error for empty proposals list")
	}
}

func TestValidateActions_EmptyActionsList(t *testing.T) {
	v := NewValidator(ValidatorConfig{})
	proposals := []mg.ActionProposal{{ProviderName: "test"}}
	if err := v.ValidateActions(proposals); err == nil {
		t.Fatal("expected error for proposal with no actions")
	}
}

func TestValidateActions_EmptyActionType(t *testing.T) {
	v := NewValidator(ValidatorConfig{})
	proposals := []mg.ActionProposal{
		{
			Actions: []mg.ProposedAction{{ID: "1", Type: ""}},
		},
	}
	if err := v.ValidateActions(proposals); err == nil {
		t.Fatal("expected error for action with empty type")
	}
}

// --- Explanation ---

func TestValidateExplanation_Valid(t *testing.T) {
	v := NewValidator(ValidatorConfig{})
	e := &mg.Explanation{
		ProviderName:    "test",
		EvidenceSummary: "User accessed sensitive resource",
		PolicyCitations: []string{"policy-001"},
	}
	if err := v.ValidateExplanation(e); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidateExplanation_MissingSummary(t *testing.T) {
	v := NewValidator(ValidatorConfig{})
	e := &mg.Explanation{PolicyCitations: []string{"policy-001"}}
	if err := v.ValidateExplanation(e); err == nil {
		t.Fatal("expected error for empty summary")
	}
}

func TestValidateExplanation_EmptyEvidence(t *testing.T) {
	v := NewValidator(ValidatorConfig{})
	e := &mg.Explanation{EvidenceSummary: "ok", PolicyCitations: nil}
	if err := v.ValidateExplanation(e); err == nil {
		t.Fatal("expected error for empty evidence")
	}
}

// --- MinConfidenceThreshold via Pipeline ---

func TestPipeline_MinConfidenceThreshold(t *testing.T) {
	p := NewPipeline(DefaultSanitizerConfig(), ValidatorConfig{MinConfidenceThreshold: 0.8})
	r := &mg.AnalysisResult{Summary: "test", Confidence: 0.5}
	if err := p.ValidateAnalysis(r); err == nil {
		t.Fatal("expected error when confidence below min threshold")
	}
}
