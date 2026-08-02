package target

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestScopeCIDRExpansionAndDeduplication(t *testing.T) {
	parser := InputParser{}
	specs, err := parser.Parse(context.Background(), []string{"192.0.2.0/30", "192.0.2.1", "EXAMPLE.test", "example.test"}, 22)
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	got, err := (Scope{}).Validate(context.Background(), specs, 8)
	if err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("Validate() returned %d targets, want 5: %+v", len(got), got)
	}
	for index, want := range []string{"192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		if got[index].Host != want {
			t.Fatalf("target %d = %q, want %q", index, got[index].Host, want)
		}
	}
}

func TestScopeExpansionLimit(t *testing.T) {
	tests := []struct {
		cidr string
		max  int
	}{
		{"192.0.2.0/29", 7},
		{"2001:db8::/64", 256},
		{"0.0.0.0/0", 256},
	}
	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			specs, err := (InputParser{}).Parse(context.Background(), []string{tt.cidr}, 22)
			if err != nil {
				t.Fatalf("Parse() = %v", err)
			}
			_, err = (Scope{}).Validate(context.Background(), specs, tt.max)
			if err == nil || !strings.Contains(err.Error(), "target limit") {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestIsPublic(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{"8.8.8.8", true},
		{"2606:4700:4700::1111", true},
		{"10.0.0.1", false},
		{"100.64.0.1", false},
		{"127.0.0.1", false},
		{"192.0.2.1", false},
		{"198.51.100.1", false},
		{"203.0.113.1", false},
		{"2001:db8::1", false},
		{"::1", false},
	}
	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			if got := IsPublic(netip.MustParseAddr(tt.address)); got != tt.want {
				t.Fatalf("IsPublic() = %v, want %v", got, tt.want)
			}
		})
	}
}
