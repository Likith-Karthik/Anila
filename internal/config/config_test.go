package config

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDefaultIsValidAndConservative(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Default().Validate() = %v", err)
	}
	if cfg.Retries != 0 || cfg.MaximumTargets != 256 || cfg.Concurrency != 10 || cfg.RateLimit <= 0 {
		t.Fatalf("unexpected safety defaults: %+v", cfg)
	}
}

func TestJSONRoundTripUsesDurationStrings(t *testing.T) {
	want := Default()
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal() = %v", err)
	}
	encoded := string(data)
	if !strings.Contains(encoded, `"target_timeout":"10s"`) {
		t.Fatalf("JSON has no duration string: %s", data)
	}
	var got Config
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"zero port", func(c *Config) { c.Port = 0 }, "port"},
		{"long connect timeout", func(c *Config) { c.ConnectionTimeout = c.TargetTimeout + time.Second }, "must not exceed"},
		{"zero concurrency", func(c *Config) { c.Concurrency = 0 }, "concurrency"},
		{"excess concurrency", func(c *Config) { c.Concurrency = MaximumConcurrency + 1 }, "must not exceed"},
		{"per-host exceeds global", func(c *Config) { c.PerHostConnections = c.Concurrency + 1 }, "per-host"},
		{"zero rate", func(c *Config) { c.RateLimit = 0 }, "rate limit"},
		{"non-finite rate", func(c *Config) { c.RateLimit = math.Inf(1) }, "finite"},
		{"target hard limit", func(c *Config) { c.MaximumTargets = AbsoluteMaximumTargets + 1 }, "hard limit"},
		{"retries", func(c *Config) { c.Retries = 1 }, "retries"},
		{"missing audit user", func(c *Config) { c.AuditUser = "" }, "audit user"},
		{"bad output", func(c *Config) { c.OutputFormat = "xml" }, "output format"},
		{"bad failure threshold", func(c *Config) { c.FailureThreshold = "low" }, "failure threshold"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			tt.edit(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.want)
			}
		})
	}
}
