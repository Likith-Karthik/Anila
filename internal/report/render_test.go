package report

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sshscope/sshscope/internal/config"
	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/finding"
	"github.com/sshscope/sshscope/internal/probe"
	"github.com/sshscope/sshscope/internal/target"
)

func TestJSONRendererIsDeterministicAndDoesNotMutate(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	input := Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   "test",
		StartedAt:     now,
		FinishedAt:    now.Add(time.Second),
		Configuration: config.Default(),
		Targets: []TargetResult{
			minimalTargetResult("192.0.2.2", now),
			minimalTargetResult("192.0.2.1", now),
		},
		Errors: []probe.Error{},
		Status: probe.StatusComplete,
	}
	var first, second bytes.Buffer
	renderer := JSONRenderer{}
	if err := renderer.Render(context.Background(), &first, input); err != nil {
		t.Fatalf("first Render() = %v", err)
	}
	if err := renderer.Render(context.Background(), &second, input); err != nil {
		t.Fatalf("second Render() = %v", err)
	}
	if first.String() != second.String() {
		t.Fatal("JSON output is not deterministic")
	}
	if strings.Index(first.String(), "192.0.2.1") > strings.Index(first.String(), "192.0.2.2") {
		t.Fatalf("targets are not sorted: %s", first.String())
	}
	if input.Targets[0].Target.ResolvedIP.String() != "192.0.2.2" {
		t.Fatal("renderer mutated input target ordering")
	}
}

func TestTerminalRenderer(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	input := Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   "test",
		StartedAt:     now,
		FinishedAt:    now,
		Configuration: config.Default(),
		Targets:       []TargetResult{minimalTargetResult("192.0.2.1", now)},
		Errors:        []probe.Error{},
		Status:        probe.StatusComplete,
	}
	var output bytes.Buffer
	if err := (TerminalRenderer{}).Render(context.Background(), &output, input); err != nil {
		t.Fatalf("Render() = %v", err)
	}
	for _, want := range []string{"Target: 192.0.2.1", "Reachable: true", "Findings: critical=0"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("terminal output %q does not contain %q", output.String(), want)
		}
	}
}

func minimalTargetResult(address string, observedAt time.Time) TargetResult {
	return TargetResult{
		Target: target.Target{
			Original:   address,
			Hostname:   address,
			ResolvedIP: netip.MustParseAddr(address),
			Port:       22,
			IPVersion:  target.Version4,
		},
		ProbeResults: []ProbeResult{},
		Observations: []evidence.Observation{{
			ID:         evidence.ObservationTCPReachable,
			Value:      evidence.BooleanValue(true),
			Probe:      "tcp",
			ObservedAt: observedAt,
			Confidence: evidence.ConfidenceHigh,
		}},
		Findings: []finding.Finding{},
		Errors:   []probe.Error{},
		Status:   probe.StatusComplete,
	}
}
