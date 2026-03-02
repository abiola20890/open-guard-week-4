// Package guardrails provides prompt sanitization and output validation
// for the OpenGuard model gateway pipeline.
package guardrails

import (
	"errors"
	"regexp"
)

// ErrPromptInjection is returned when a prompt injection attempt is detected
// and BlockOnInjection is enabled.
var ErrPromptInjection = errors.New("guardrails: prompt injection detected")

// SanitizerConfig holds configuration for the Sanitizer.
type SanitizerConfig struct {
	// BlockOnInjection causes Sanitize to return ErrPromptInjection when an
	// injection pattern is found. Defaults to true.
	BlockOnInjection bool
	// RedactCredentials enables redaction of credential patterns. Defaults to true.
	RedactCredentials bool
	// RedactPII enables redaction of PII patterns. Defaults to true.
	RedactPII bool
	// MaxPromptLength is the maximum allowed prompt length in bytes.
	// Prompts exceeding this length are truncated. Defaults to 8192.
	MaxPromptLength int
}

// DefaultSanitizerConfig returns a SanitizerConfig with safe defaults.
func DefaultSanitizerConfig() SanitizerConfig {
	return SanitizerConfig{
		BlockOnInjection:  true,
		RedactCredentials: true,
		RedactPII:         true,
		MaxPromptLength:   8192,
	}
}

// Sanitizer sanitizes prompts before dispatch to a model provider.
// It detects and redacts credentials and PII, and blocks prompt injection attempts.
type Sanitizer struct {
	cfg SanitizerConfig

	// credential patterns
	awsKey     *regexp.Regexp
	privateKey *regexp.Regexp
	bearer     *regexp.Regexp
	basicAuth  *regexp.Regexp

	// PII patterns
	email      *regexp.Regexp
	phone      *regexp.Regexp
	creditCard *regexp.Regexp

	// injection patterns
	injections []*regexp.Regexp
}

// NewSanitizer constructs a Sanitizer with the provided configuration.
// If MaxPromptLength is zero, the default of 8192 is used.
func NewSanitizer(cfg SanitizerConfig) *Sanitizer {
	if cfg.MaxPromptLength == 0 {
		cfg.MaxPromptLength = 8192
	}
	return &Sanitizer{
		cfg:        cfg,
		awsKey:     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		privateKey: regexp.MustCompile(`-----BEGIN.*PRIVATE KEY-----`),
		bearer:     regexp.MustCompile(`[Bb]earer\s+[A-Za-z0-9\-_\.]{20,}`),
		basicAuth:  regexp.MustCompile(`[Bb]asic\s+[A-Za-z0-9+/]{20,}`),
		email:      regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
		phone:      regexp.MustCompile(`\b\+?[1-9]\d{7,14}\b`),
		creditCard: regexp.MustCompile(`\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}\b`),
		injections: []*regexp.Regexp{
			regexp.MustCompile(`(?i)ignore previous instructions`),
			regexp.MustCompile(`(?i)disregard your system prompt`),
			regexp.MustCompile(`(?i)you are now`),
			regexp.MustCompile(`(?i)act as`),
			regexp.MustCompile(`(?i)jailbreak`),
		},
	}
}

// Sanitize inspects prompt for injection attempts, credentials, and PII.
// It returns the (possibly redacted) prompt, a deduplicated list of redaction
// reason codes, and ErrPromptInjection if the prompt is blocked entirely.
func (s *Sanitizer) Sanitize(prompt string) (string, []string, error) {
	// Check injection patterns first; blocked prompts are never passed through.
	if s.cfg.BlockOnInjection {
		for _, re := range s.injections {
			if re.MatchString(prompt) {
				return "", []string{"injection_detected"}, ErrPromptInjection
			}
		}
	}

	seen := make(map[string]bool)
	addReason := func(r string) {
		if !seen[r] {
			seen[r] = true
		}
	}

	// Redact credentials.
	if s.cfg.RedactCredentials {
		if s.awsKey.MatchString(prompt) {
			prompt = s.awsKey.ReplaceAllString(prompt, "[REDACTED]")
			addReason("credential_detected")
		}
		if s.privateKey.MatchString(prompt) {
			prompt = s.privateKey.ReplaceAllString(prompt, "[REDACTED]")
			addReason("credential_detected")
		}
		if s.bearer.MatchString(prompt) {
			prompt = s.bearer.ReplaceAllString(prompt, "[REDACTED]")
			addReason("credential_detected")
		}
		if s.basicAuth.MatchString(prompt) {
			prompt = s.basicAuth.ReplaceAllString(prompt, "[REDACTED]")
			addReason("credential_detected")
		}
	}

	// Redact PII.
	if s.cfg.RedactPII {
		if s.email.MatchString(prompt) {
			prompt = s.email.ReplaceAllString(prompt, "[REDACTED]")
			addReason("pii_email_detected")
		}
		if s.phone.MatchString(prompt) {
			prompt = s.phone.ReplaceAllString(prompt, "[REDACTED]")
			addReason("pii_phone_detected")
		}
		if s.creditCard.MatchString(prompt) {
			prompt = s.creditCard.ReplaceAllString(prompt, "[REDACTED]")
			addReason("pii_credit_card_detected")
		}
	}

	// Truncate if necessary.
	if s.cfg.MaxPromptLength > 0 && len(prompt) > s.cfg.MaxPromptLength {
		prompt = prompt[:s.cfg.MaxPromptLength] + "... [TRUNCATED]"
		addReason("truncated")
	}

	// Build ordered reasons slice from the seen set.
	order := []string{
		"credential_detected",
		"pii_email_detected",
		"pii_phone_detected",
		"pii_credit_card_detected",
		"truncated",
	}
	var reasons []string
	for _, r := range order {
		if seen[r] {
			reasons = append(reasons, r)
		}
	}

	// Ensure non-nil slice for callers that range over reasons.
	if reasons == nil {
		reasons = []string{}
	}

	return prompt, reasons, nil
}
