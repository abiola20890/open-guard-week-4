// Package hostguardcommon provides shared types and utilities for the HostGuard sensor.
package hostguardcommon

// DNSQueryEvent represents a DNS query made by a process.
type DNSQueryEvent struct {
	PID         uint32
	ProcessName string
	QueryName   string
	QueryType   string // A, AAAA, MX, TXT, etc.
	Resolver    string // IP of the DNS resolver
	Response    string // resolved IP(s) or NXDOMAIN
}
