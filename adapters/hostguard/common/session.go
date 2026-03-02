// Package hostguardcommon provides shared types and utilities for the HostGuard sensor.
package hostguardcommon

// LoginEvent represents a user login, logout, or authentication event.
type LoginEvent struct {
	Username     string
	TTY          string
	RemoteHost   string
	PID          uint32
	SessionID    uint32
	EventSubtype string // login, logout, sudo, ssh, rdp, failed_login
}
