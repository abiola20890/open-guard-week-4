// Package agentguardcommon provides shared types and utilities for the AgentGuard sensor.
package agentguardcommon

// Config holds the configuration for the AgentGuard sensor.
type Config struct {
	// NATSUrl is the NATS server URL.
	NATSUrl string
	// RawEventTopic is the NATS topic for raw agent events.
	// Default: "openguard.agentguard.raw"
	RawEventTopic string
	// ListenAddr is the HTTP intercept listen address.
	// Default: ":8095"
	ListenAddr string
}

// DefaultConfig returns a Config with sensible defaults applied.
func DefaultConfig() Config {
	return Config{
		NATSUrl:       "nats://localhost:4222",
		RawEventTopic: "openguard.agentguard.raw",
		ListenAddr:    ":8095",
	}
}
