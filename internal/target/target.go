// Package target owns target identity, parsing, resolution, and scope checks.
package target

import (
	"fmt"
	"net/netip"
)

// IPVersion is the resolved network protocol version.
type IPVersion string

const (
	VersionUnknown IPVersion = "unknown"
	Version4       IPVersion = "ipv4"
	Version6       IPVersion = "ipv6"
)

// Target is a single, resolved endpoint. Original is retained for reporting.
type Target struct {
	Original   string            `json:"original"`
	Hostname   string            `json:"hostname"`
	ResolvedIP netip.Addr        `json:"resolved_ip"`
	Port       uint16            `json:"port"`
	IPVersion  IPVersion         `json:"ip_version"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// Endpoint returns an unambiguous host:port string, including IPv6 brackets.
func (t Target) Endpoint() string {
	return netip.AddrPortFrom(t.ResolvedIP, t.Port).String()
}

// Validate checks invariants expected after target resolution.
func (t Target) Validate() error {
	if t.Original == "" {
		return fmt.Errorf("original target input is required")
	}
	if t.Hostname == "" {
		return fmt.Errorf("target hostname is required")
	}
	if !t.ResolvedIP.IsValid() {
		return fmt.Errorf("resolved IP is required")
	}
	if t.Port == 0 {
		return fmt.Errorf("target port must be between 1 and 65535")
	}
	if t.ResolvedIP.Is4() && t.IPVersion != Version4 {
		return fmt.Errorf("IPv4 address has IP version %q", t.IPVersion)
	}
	if t.ResolvedIP.Is6() && t.IPVersion != Version6 {
		return fmt.Errorf("IPv6 address has IP version %q", t.IPVersion)
	}
	return nil
}
