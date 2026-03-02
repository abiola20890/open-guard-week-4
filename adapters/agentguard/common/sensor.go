// Package agentguardcommon provides shared types and utilities for the AgentGuard sensor.
package agentguardcommon

import "context"

// Sensor is the interface all AgentGuard sensor implementations must satisfy.
type Sensor interface {
	// Start begins the sensor and returns immediately.
	Start(ctx context.Context) error
	// Stop gracefully shuts down the sensor.
	Stop() error
	// HealthCheck returns nil if the sensor is running correctly.
	HealthCheck(ctx context.Context) error
}
