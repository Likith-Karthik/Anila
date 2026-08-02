package target

import (
	"context"
	"strings"
	"testing"
)

func TestInputParser(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantHost string
		wantPort uint16
		wantKind SpecKind
		wantErr  string
	}{
		{"hostname", "Example.COM", "example.com", 22, SpecHostname, ""},
		{"hostname port", "example.com:2222", "example.com", 2222, SpecHostname, ""},
		{"IPv4", "192.0.2.1", "192.0.2.1", 22, SpecAddress, ""},
		{"IPv4 port", "192.0.2.1:2200", "192.0.2.1", 2200, SpecAddress, ""},
		{"IPv6", "2001:db8::1", "2001:db8::1", 22, SpecAddress, ""},
		{"IPv6 port", "[2001:db8::1]:2200", "2001:db8::1", 2200, SpecAddress, ""},
		{"mapped IPv4", "::ffff:192.0.2.1", "192.0.2.1", 22, SpecAddress, ""},
		{"CIDR masked", "192.0.2.7/29", "192.0.2.0/29", 22, SpecCIDR, ""},
		{"bad CIDR", "192.0.2.1/99", "", 0, "", "invalid CIDR"},
		{"URL", "ssh://example.com", "", 0, "", "invalid"},
		{"userinfo", "root@example.com", "", 0, "", "user-info"},
		{"zero port", "example.com:0", "", 0, "", "invalid port"},
		{"unbracketed IPv6 port is address", "2001:db8::1:22", "2001:db8::1:22", 22, SpecAddress, ""},
	}
	parser := InputParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			specs, err := parser.Parse(context.Background(), []string{tt.input}, 22)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Parse() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse() = %v", err)
			}
			got := specs[0]
			if got.Host != tt.wantHost || got.Port != tt.wantPort || got.Kind != tt.wantKind {
				t.Fatalf("Parse() = %+v", got)
			}
		})
	}
}

func TestInputParserIgnoresCommentsAndBlankLines(t *testing.T) {
	specs, err := (InputParser{}).Parse(context.Background(), []string{"", "  # comment", "example.test"}, 22)
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	if len(specs) != 1 || specs[0].Host != "example.test" {
		t.Fatalf("Parse() = %+v", specs)
	}
}

func TestInputParserCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (InputParser{}).Parse(ctx, []string{"example.test"}, 22)
	if err == nil {
		t.Fatal("Parse() = nil error after cancellation")
	}
}
