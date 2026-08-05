package web

import (
	"context"
	"strings"
	"testing"

	"github.com/sshscope/sshscope/internal/config"
)

func TestScanRequiresAuthorization(t *testing.T) {
	service := NewService("test")
	_, err := service.Scan(context.Background(), ScanInput{Targets: "127.0.0.1"})
	if err == nil || !strings.Contains(err.Error(), "authorization") {
		t.Fatalf("Scan() error = %v, want authorization failure", err)
	}
}

func TestConfigFromInputAppliesDefaultsAndLimits(t *testing.T) {
	cfg, err := configFromInput(ScanInput{
		Port:              2222,
		TargetTimeout:     "3s",
		ConnectionTimeout: "1s",
		Concurrency:       2,
		PerHost:           1,
		RateLimit:         1.5,
		MaximumTargets:    4,
		IPPreference:      string(config.IPv4),
		AuthProbeEnabled:  true,
		AuditUser:         "audit",
		FailureThreshold:  string(config.FailOnNever),
	})
	if err != nil {
		t.Fatalf("configFromInput() = %v", err)
	}
	if cfg.Port != 2222 || cfg.Concurrency != 2 || cfg.AuditUser != "audit" || cfg.OutputFormat != config.OutputJSON {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestTargetLinesIgnoresBlanksAndComments(t *testing.T) {
	got := targetLines("\n# comment\n127.0.0.1\n\nexample.com\n")
	want := []string{"127.0.0.1", "example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("targetLines() = %#v, want %#v", got, want)
	}
}
