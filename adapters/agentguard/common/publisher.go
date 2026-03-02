// Package agentguardcommon provides shared types and utilities for the AgentGuard sensor.
package agentguardcommon

import (
	"context"
	"fmt"

	nats "github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

// Publisher publishes AgentEvents to NATS as UnifiedEvent JSON payloads.
type Publisher struct {
	nc     *nats.Conn
	topic  string
	logger *zap.Logger
}

// NewPublisher creates a new Publisher connected to the given NATS URL
// and publishing to the given topic.
func NewPublisher(natsURL, topic string, logger *zap.Logger) (*Publisher, error) {
	nc, err := nats.Connect(natsURL,
		nats.Name("openguard-agentguard"),
		nats.MaxReconnects(-1),
	)
	if err != nil {
		return nil, fmt.Errorf("agentguard: connect to NATS at %s: %w", natsURL, err)
	}
	return &Publisher{nc: nc, topic: topic, logger: logger}, nil
}

// Publish converts the AgentEvent to a UnifiedEvent JSON payload and publishes it to NATS.
func (p *Publisher) Publish(_ context.Context, event *AgentEvent) error {
	payload, err := event.ToUnifiedEvent()
	if err != nil {
		return fmt.Errorf("agentguard: to unified event: %w", err)
	}
	if err := p.nc.Publish(p.topic, payload); err != nil {
		return fmt.Errorf("agentguard: NATS publish to %s: %w", p.topic, err)
	}
	p.logger.Debug("agentguard: published event",
		zap.String("topic", p.topic),
		zap.String("event_type", event.EventType),
		zap.String("agent_id", event.AgentID),
	)
	return nil
}

// Close drains and closes the underlying NATS connection.
func (p *Publisher) Close() {
	if p.nc != nil {
		p.nc.Drain() //nolint:errcheck
	}
}
