// Command agentguard-agent is the AgentGuard AI agent supervision sensor.
// It intercepts agent action submissions, evaluates them against policy,
// and emits audit events to NATS.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	common "github.com/DiniMuhd7/openguard/adapters/agentguard/common"
	agentguard "github.com/DiniMuhd7/openguard/adapters/agentguard"
	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic("failed to create logger: " + err.Error())
	}
	defer logger.Sync() //nolint:errcheck

	cfg := buildConfig()

	sensor, err := agentguard.NewAgentGuardSensor(cfg, logger)
	if err != nil {
		logger.Fatal("agentguard-agent: failed to create sensor", zap.Error(err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sensor.Start(ctx); err != nil {
		logger.Fatal("agentguard-agent: failed to start sensor", zap.Error(err))
	}

	logger.Info("agentguard-agent: started",
		zap.String("listen_addr", cfg.ListenAddr),
		zap.String("nats_url", cfg.NATSUrl),
		zap.String("topic", cfg.RawEventTopic),
	)

	// Wait for shutdown signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("agentguard-agent: shutting down")
	if err := sensor.Stop(); err != nil {
		logger.Warn("agentguard-agent: stop error", zap.Error(err))
	}
	logger.Info("agentguard-agent: stopped")
}

// buildConfig constructs a Config from environment variables.
func buildConfig() common.Config {
	cfg := common.DefaultConfig()

	if v := os.Getenv("OPENGUARD_NATS_URL"); v != "" {
		cfg.NATSUrl = v
	}
	if v := os.Getenv("OPENGUARD_AGENTGUARD_TOPIC"); v != "" {
		cfg.RawEventTopic = v
	}
	if v := os.Getenv("OPENGUARD_AGENTGUARD_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}

	return cfg
}
