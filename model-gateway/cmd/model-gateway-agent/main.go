// main.go — ModelGuard Agent
// A deployable binary that subscribes to NATS model request messages,
// runs them through the prompt-sanitization and output-validation pipeline,
// dispatches to the configured AI model provider(s), and publishes results.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	mg "github.com/DiniMuhd7/openguard/model-gateway/interfaces"
	"github.com/DiniMuhd7/openguard/model-gateway/guardrails"
	"github.com/DiniMuhd7/openguard/model-gateway/providers/claude"
	"github.com/DiniMuhd7/openguard/model-gateway/providers/codex"
	"github.com/DiniMuhd7/openguard/model-gateway/providers/gemini"
	"github.com/DiniMuhd7/openguard/model-gateway/routing"
)

// modelRequest is the JSON schema for incoming NATS model requests.
type modelRequest struct {
	EventID    string   `json:"event_id"`
	Prompt     string   `json:"prompt"`
	RiskLevel  string   `json:"risk_level"`
	Domain     string   `json:"domain"`
	Indicators []string `json:"indicators"`
}

// modelResponse is the JSON schema published to the result topic.
type modelResponse struct {
	EventID    string             `json:"event_id"`
	Result     *mg.AnalysisResult `json:"result,omitempty"`
	Error      string             `json:"error,omitempty"`
	Redactions []string           `json:"redactions,omitempty"`
}

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic("model-gateway-agent: failed to init logger: " + err.Error())
	}
	defer logger.Sync() //nolint:errcheck

	// ── Read configuration from environment ─────────────────────────────────
	natsURL := envOr("OPENGUARD_NATS_URL", "nats://localhost:4222")
	modelTopic := envOr("OPENGUARD_MODEL_TOPIC", "openguard.modelguard.requests")
	resultTopic := envOr("OPENGUARD_RESULT_TOPIC", "openguard.modelguard.results")
	providerName := envOr("OPENGUARD_PROVIDER", "codex")
	strategy := envOr("OPENGUARD_RISK_STRATEGY", "single")

	openAIKey := os.Getenv("OPENGUARD_OPENAI_API_KEY")
	anthropicKey := os.Getenv("OPENGUARD_ANTHROPIC_API_KEY")
	geminiKey := os.Getenv("OPENGUARD_GEMINI_API_KEY")

	minConfidence := 0.0
	if v := os.Getenv("OPENGUARD_MIN_CONFIDENCE"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			minConfidence = f
		} else {
			logger.Warn("model-gateway-agent: invalid OPENGUARD_MIN_CONFIDENCE", zap.Error(err))
		}
	}

	maxPromptLength := 8192
	if v := os.Getenv("OPENGUARD_MAX_PROMPT_LENGTH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxPromptLength = n
		} else {
			logger.Warn("model-gateway-agent: invalid OPENGUARD_MAX_PROMPT_LENGTH", zap.Error(err))
		}
	}

	// ── Build provider list ──────────────────────────────────────────────────
	providers, primaryProvider := buildProviders(strategy, providerName, openAIKey, anthropicKey, geminiKey, logger)
	if len(providers) == 0 {
		logger.Fatal("model-gateway-agent: no providers configured")
	}

	// ── Build guardrails pipeline ────────────────────────────────────────────
	sanitizerCfg := guardrails.DefaultSanitizerConfig()
	sanitizerCfg.MaxPromptLength = maxPromptLength
	pipeline := guardrails.NewPipeline(sanitizerCfg, guardrails.ValidatorConfig{
		MinConfidenceThreshold: minConfidence,
	})

	// ── Build router ─────────────────────────────────────────────────────────
	router := routing.NewRouter(providers, routing.Config{PrimaryProviderIndex: 0}, logger)

	// ── Connect to NATS ──────────────────────────────────────────────────────
	nc, err := nats.Connect(natsURL)
	if err != nil {
		logger.Fatal("model-gateway-agent: failed to connect to NATS",
			zap.String("nats_url", natsURL), zap.Error(err))
	}
	defer nc.Drain() //nolint:errcheck

	logger.Info("model-gateway-agent: started",
		zap.String("provider", primaryProvider),
		zap.String("strategy", strategy),
		zap.String("nats_url", natsURL),
		zap.String("model_topic", modelTopic),
		zap.String("result_topic", resultTopic),
	)

	// ── Subscribe to model requests ──────────────────────────────────────────
	sub, err := nc.Subscribe(modelTopic, func(msg *nats.Msg) {
		handleMessage(msg, nc, resultTopic, pipeline, router, logger)
	})
	if err != nil {
		logger.Fatal("model-gateway-agent: failed to subscribe", zap.String("topic", modelTopic), zap.Error(err))
	}
	defer sub.Unsubscribe() //nolint:errcheck

	// ── Prometheus metrics endpoint ──────────────────────────────────────────
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{Addr: ":9093", Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Warn("model-gateway-agent: metrics server error", zap.Error(err))
		}
	}()

	// ── Health-check loop ────────────────────────────────────────────────────
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			for _, p := range providers {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				if err := p.HealthCheck(ctx); err != nil {
					logger.Warn("model-gateway-agent: health check failed",
						zap.String("provider", p.ProviderName()), zap.Error(err))
				} else {
					logger.Info("model-gateway-agent: health check ok",
						zap.String("provider", p.ProviderName()))
				}
				cancel()
			}
		}
	}()

	// ── Graceful shutdown ────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("model-gateway-agent: shutting down")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("model-gateway-agent: metrics server shutdown error", zap.Error(err))
	}
	logger.Info("model-gateway-agent: stopped")
}

// handleMessage processes a single NATS message: sanitize → dispatch → validate → publish.
func handleMessage(
	msg *nats.Msg,
	nc *nats.Conn,
	resultTopic string,
	pipeline *guardrails.Pipeline,
	router *routing.Router,
	logger *zap.Logger,
) {
	var req modelRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		logger.Warn("model-gateway-agent: failed to deserialize request", zap.Error(err))
		publishError(nc, resultTopic, "", fmt.Sprintf("deserialize: %v", err), logger)
		return
	}

	// Stage 1: Sanitize prompt.
	sanitized, redactions, err := pipeline.SanitizePrompt(req.Prompt)
	if err != nil {
		logger.Warn("model-gateway-agent: prompt blocked",
			zap.String("event_id", req.EventID), zap.Error(err))
		publishError(nc, resultTopic, req.EventID, fmt.Sprintf("prompt blocked: %v", err), logger)
		return
	}

	// Stage 2: Dispatch to router.
	eventCtx := mg.EventContext{
		EventID:    req.EventID,
		Domain:     req.Domain,
		RawPayload: sanitized,
		Indicators: req.Indicators,
		Timestamp:  time.Now(),
	}
	riskLevel := mg.RiskLevel(req.RiskLevel)
	if riskLevel == "" {
		riskLevel = mg.RiskLow
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := router.Route(ctx, eventCtx, riskLevel)
	if err != nil {
		logger.Warn("model-gateway-agent: router error",
			zap.String("event_id", req.EventID), zap.Error(err))
		publishError(nc, resultTopic, req.EventID, fmt.Sprintf("router: %v", err), logger)
		return
	}

	// Stage 4: Validate output.
	if err := pipeline.ValidateAnalysis(result); err != nil {
		logger.Warn("model-gateway-agent: output validation failed",
			zap.String("event_id", req.EventID), zap.Error(err))
		publishError(nc, resultTopic, req.EventID, fmt.Sprintf("validation: %v", err), logger)
		return
	}

	// Stage 5: Publish result.
	resp := modelResponse{
		EventID:    req.EventID,
		Result:     result,
		Redactions: redactions,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		logger.Warn("model-gateway-agent: failed to marshal response", zap.Error(err))
		return
	}
	if err := nc.Publish(resultTopic, data); err != nil {
		logger.Warn("model-gateway-agent: failed to publish result",
			zap.String("event_id", req.EventID), zap.Error(err))
	}
}

// publishError publishes an error response to the result topic.
func publishError(nc *nats.Conn, topic, eventID, errMsg string, logger *zap.Logger) {
	resp := modelResponse{EventID: eventID, Error: errMsg}
	data, err := json.Marshal(resp)
	if err != nil {
		logger.Warn("model-gateway-agent: failed to marshal error response", zap.Error(err))
		return
	}
	if err := nc.Publish(topic, data); err != nil {
		logger.Warn("model-gateway-agent: failed to publish error", zap.Error(err))
	}
}

// buildProviders constructs the appropriate model provider(s) based on the
// configured strategy and provider name.
func buildProviders(
	strategy, providerName, openAIKey, anthropicKey, geminiKey string,
	logger *zap.Logger,
) ([]mg.ModelProvider, string) {
	// For quorum strategy, instantiate all providers that have API keys.
	if strategy == "quorum" {
		var providers []mg.ModelProvider
		if openAIKey != "" {
			providers = append(providers, codex.NewCodexProvider(codex.Config{APIKey: openAIKey}, logger))
		}
		if anthropicKey != "" {
			providers = append(providers, claude.NewClaudeProvider(claude.Config{APIKey: anthropicKey}, logger))
		}
		if geminiKey != "" {
			providers = append(providers, gemini.NewGeminiProvider(gemini.Config{APIKey: geminiKey}, logger))
		}
		primary := providerName
		if len(providers) > 0 {
			primary = providers[0].ProviderName()
		}
		return providers, primary
	}

	// For single / fallback strategy, use the named primary provider.
	switch providerName {
	case "claude":
		p := claude.NewClaudeProvider(claude.Config{APIKey: anthropicKey}, logger)
		return []mg.ModelProvider{p}, p.ProviderName()
	case "gemini":
		p := gemini.NewGeminiProvider(gemini.Config{APIKey: geminiKey}, logger)
		return []mg.ModelProvider{p}, p.ProviderName()
	default: // "codex"
		p := codex.NewCodexProvider(codex.Config{APIKey: openAIKey}, logger)
		return []mg.ModelProvider{p}, p.ProviderName()
	}
}

// envOr returns the value of the environment variable key, or fallback if unset.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
