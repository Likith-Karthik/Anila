package report

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sshscope/sshscope/internal/config"
	"github.com/sshscope/sshscope/internal/finding"
	"github.com/sshscope/sshscope/internal/probe"
	"github.com/sshscope/sshscope/internal/target"
)

func TestCanonicalModelJSONUsesReadableDurations(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	report := Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   "test",
		StartedAt:     now,
		FinishedAt:    now.Add(time.Second),
		Configuration: config.Default(),
		Authorization: config.Authorization{OperatorConfirmed: true, ScopeReference: "lab-001"},
		Targets: []TargetResult{{
			Target: target.Target{
				Original:   "example.test",
				Hostname:   "example.test",
				ResolvedIP: netip.MustParseAddr("192.0.2.1"),
				Port:       22,
				IPVersion:  target.Version4,
			},
			ProbeResults: []ProbeResult{{
				Name: "tcp",
				Result: probe.Result{
					Duration: probe.Duration(2 * time.Millisecond),
					Status:   probe.StatusComplete,
				},
			}},
			Status: probe.StatusComplete,
		}},
		Status: probe.StatusComplete,
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal() = %v", err)
	}
	encoded := string(data)
	for _, want := range []string{`"target_timeout":"10s"`, `"duration":"2ms"`, `"scope_reference":"lab-001"`} {
		if !strings.Contains(encoded, want) {
			t.Fatalf("JSON %s does not contain %s", data, want)
		}
	}
}

func TestTargetResultRejectsDuplicateProbeNames(t *testing.T) {
	result := TargetResult{
		Target: target.Target{
			Original:   "192.0.2.1",
			Hostname:   "192.0.2.1",
			ResolvedIP: netip.MustParseAddr("192.0.2.1"),
			Port:       22,
			IPVersion:  target.Version4,
		},
		ProbeResults: []ProbeResult{
			{Name: "tcp", Result: probe.Result{Status: probe.StatusComplete}},
			{Name: "tcp", Result: probe.Result{Status: probe.StatusComplete}},
		},
		Status: probe.StatusComplete,
	}
	if err := result.Validate(); err == nil {
		t.Fatal("Validate() = nil, want duplicate probe name")
	}
}

func TestReportRejectsDuplicateTargetEndpoints(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	input := Report{
		SchemaVersion: SchemaVersion, ToolVersion: "test", StartedAt: now, FinishedAt: now,
		Configuration: config.Default(),
		Targets:       []TargetResult{minimalTargetResult("192.0.2.1", now), minimalTargetResult("192.0.2.1", now)},
		Errors:        []probe.Error{}, Status: probe.StatusComplete,
	}
	if err := input.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate target endpoint") {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestTargetResultRejectsMissingFindingEvidence(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	result := minimalTargetResult("192.0.2.1", now)
	result.Findings = []finding.Finding{{
		RuleID: "TEST-001", Title: "Test", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceHigh,
		Description: "Test description", Recommendation: "Test recommendation",
		Evidence: []finding.EvidenceReference{{ObservationID: "missing", Probe: "kex"}},
	}}
	if err := result.Validate(); err == nil || !strings.Contains(err.Error(), "references missing observation") {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestReportRejectsMisleadingCompletionStatuses(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	targetResult := minimalTargetResult("192.0.2.1", now)
	probeErr := probe.Error{Kind: probe.ErrorProtocol, Probe: "kex", Message: "invalid"}
	targetResult.ProbeResults = []ProbeResult{{
		Name:   "kex",
		Result: probe.Result{Errors: []probe.Error{probeErr}, Status: probe.StatusFailed},
	}}
	targetResult.Errors = []probe.Error{probeErr}
	targetResult.Status = probe.StatusComplete
	input := Report{
		SchemaVersion: SchemaVersion, ToolVersion: "test", StartedAt: now, FinishedAt: now,
		Configuration: config.Default(), Targets: []TargetResult{targetResult}, Errors: []probe.Error{}, Status: probe.StatusComplete,
	}
	if err := input.Validate(); err == nil || !strings.Contains(err.Error(), "complete target") {
		t.Fatalf("Validate() = %v", err)
	}

	targetResult.Status = probe.StatusFailed
	input.Targets = []TargetResult{targetResult}
	if err := input.Validate(); err == nil || !strings.Contains(err.Error(), "complete report") {
		t.Fatalf("Validate() report status = %v", err)
	}
}
