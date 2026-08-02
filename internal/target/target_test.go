package target

import (
	"net/netip"
	"testing"
)

func TestEndpoint(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		port uint16
		want string
	}{
		{"IPv4", "192.0.2.1", 22, "192.0.2.1:22"},
		{"IPv6", "2001:db8::1", 2222, "[2001:db8::1]:2222"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := Target{ResolvedIP: netip.MustParseAddr(tt.ip), Port: tt.port}
			if got := target.Endpoint(); got != tt.want {
				t.Fatalf("Endpoint() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateIPVersion(t *testing.T) {
	target := Target{
		Original:   "example.test",
		Hostname:   "example.test",
		ResolvedIP: netip.MustParseAddr("192.0.2.1"),
		Port:       22,
		IPVersion:  Version6,
	}
	if err := target.Validate(); err == nil {
		t.Fatal("Validate() = nil, want address-family mismatch")
	}
}

func TestValidateRequiresHostname(t *testing.T) {
	target := Target{
		Original:   "192.0.2.1",
		ResolvedIP: netip.MustParseAddr("192.0.2.1"),
		Port:       22,
		IPVersion:  Version4,
	}
	if err := target.Validate(); err == nil {
		t.Fatal("Validate() = nil, want missing hostname")
	}
}
