package report

import (
	"bytes"
	"context"
	"net/netip"
	"slices"
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
	shuffled := input
	shuffled.Targets = slices.Clone(input.Targets)
	slices.Reverse(shuffled.Targets)
	var reordered bytes.Buffer
	if err := renderer.Render(context.Background(), &reordered, shuffled); err != nil {
		t.Fatalf("reordered Render() = %v", err)
	}
	if first.String() != reordered.String() {
		t.Fatal("JSON output depends on report collection ordering")
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
	for _, want := range []string{"Target: 192.0.2.1", "Reachable: true", "Severity totals: critical=0", "Exit status: 0"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("terminal output %q does not contain %q", output.String(), want)
		}
	}
}

func TestTerminalRendererShowsHostKeyFingerprintAndTrustState(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	targetResult := minimalTargetResult("192.0.2.1", now)
	targetResult.Observations = append(targetResult.Observations, evidence.Observation{
		ID: evidence.ObservationHostKeys,
		Value: evidence.HostKeysValue([]evidence.HostKey{{
			Algorithm:         "ssh-ed25519",
			FingerprintSHA256: "SHA256:fixture",
			PublicKeyType:     "ssh-ed25519",
			Bits:              256,
			KnownHostsStatus:  evidence.KnownHostsMismatch,
		}}),
		Probe:      "hostkey",
		ObservedAt: now,
		Confidence: evidence.ConfidenceHigh,
	})
	input := Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   "test",
		StartedAt:     now,
		FinishedAt:    now,
		Configuration: config.Default(),
		Targets:       []TargetResult{targetResult},
		Errors:        []probe.Error{},
		Status:        probe.StatusComplete,
	}
	var output bytes.Buffer
	if err := (TerminalRenderer{}).Render(context.Background(), &output, input); err != nil {
		t.Fatalf("Render() = %v", err)
	}
	for _, want := range []string{"Host key: SHA256:fixture", "known_hosts=mismatch", "bits=256"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("terminal output %q does not contain %q", output.String(), want)
		}
	}
}

func TestTerminalRendererShowsAuthenticationMethods(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	targetResult := minimalTargetResult("192.0.2.1", now)
	targetResult.Observations = append(targetResult.Observations, evidence.Observation{
		ID:         evidence.ObservationAuthMethods,
		Value:      evidence.StringsValue([]string{"publickey", "password"}),
		Probe:      "auth",
		ObservedAt: now,
		Confidence: evidence.ConfidenceHigh,
	})
	input := Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   "test",
		StartedAt:     now,
		FinishedAt:    now,
		Configuration: config.Default(),
		Targets:       []TargetResult{targetResult},
		Errors:        []probe.Error{},
		Status:        probe.StatusComplete,
	}
	var output bytes.Buffer
	if err := (TerminalRenderer{}).Render(context.Background(), &output, input); err != nil {
		t.Fatalf("Render() = %v", err)
	}
	want := "Authentication methods (sshscope-audit): publickey, password"
	if !strings.Contains(output.String(), want) {
		t.Fatalf("terminal output %q does not contain %q", output.String(), want)
	}
}

func TestTerminalRendererEscapesUntrustedControlCharacters(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	targetResult := minimalTargetResult("192.0.2.1", now)
	targetResult.Target.Original = "target\x1b[2J\u202e"
	targetResult.Observations = append(targetResult.Observations, evidence.Observation{
		ID:         evidence.ObservationBannerRaw,
		Value:      evidence.StringValue("SSH-2.0-test\x1b[2J\nforged\u202e"),
		Probe:      "banner",
		ObservedAt: now,
		Confidence: evidence.ConfidenceHigh,
	})
	input := Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   "test\x1b[2J",
		StartedAt:     now,
		FinishedAt:    now,
		Configuration: config.Default(),
		Targets:       []TargetResult{targetResult},
		Errors:        []probe.Error{},
		Status:        probe.StatusComplete,
	}
	var output bytes.Buffer
	if err := (TerminalRenderer{}).Render(context.Background(), &output, input); err != nil {
		t.Fatalf("Render() = %v", err)
	}
	got := output.String()
	for _, unsafe := range []string{"\x1b", "\u202e", "SSH-2.0-test\x1b[2J\nforged"} {
		if strings.Contains(got, unsafe) {
			t.Fatalf("terminal output contains unescaped control text %q: %q", unsafe, got)
		}
	}
	for _, escaped := range []string{`\x1b`, `\n`, `\u202e`} {
		if !strings.Contains(got, escaped) {
			t.Fatalf("terminal output %q does not contain escaped text %q", got, escaped)
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
