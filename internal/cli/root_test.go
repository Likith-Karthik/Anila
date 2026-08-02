package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sshscope/sshscope/internal/config"
	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/finding"
	"github.com/sshscope/sshscope/internal/probe"
	"github.com/sshscope/sshscope/internal/report"
	"github.com/sshscope/sshscope/internal/scheduler"
	"github.com/sshscope/sshscope/internal/target"
)

func TestCommandTree(t *testing.T) {
	root := NewRootCommand("test-version")
	for _, path := range [][]string{{"scan"}, {"report"}, {"compare"}, {"policy", "validate"}, {"version"}} {
		if _, _, err := root.Find(path); err != nil {
			t.Fatalf("Find(%v) = %v", path, err)
		}
	}
}

func TestReadTargetLines(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		maximum int
		want    int
		wantErr string
	}{
		{"targets", "# comment\nexample.test\n\n192.0.2.1\n", 4, 2, ""},
		{"empty", "# only comments\n", 4, 0, "no targets"},
		{"count limit", "one.test\ntwo.test\n", 1, 0, "exceeds maximum"},
		{"line limit", strings.Repeat("a", maximumTargetLineBytes+1), 4, 0, "token too long"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readTargetLines(strings.NewReader(tt.input), tt.maximum)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("readTargetLines() error = %v", err)
				}
				return
			}
			if err != nil || len(got) != tt.want {
				t.Fatalf("readTargetLines() = %v, %v", got, err)
			}
		})
	}
}

func TestRenderOutputAtomicallyWritesPrivateFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "report.txt")
	renderer := staticRenderer("report data")
	if err := renderOutput(context.Background(), io.Discard, path, renderer, report.Report{}); err != nil {
		t.Fatalf("renderOutput() = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() = %v", err)
	}
	if string(data) != "report data" {
		t.Fatalf("output = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permissions = %o", info.Mode().Perm())
	}
}

type staticRenderer string

func (r staticRenderer) Render(_ context.Context, writer io.Writer, _ report.Report) error {
	_, err := io.WriteString(writer, string(r))
	return err
}

func TestExitCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"success", nil, ExitSuccess},
		{"invalid input", errors.New("bad flag"), ExitInvalidInput},
		{"findings", WithExitCode(ExitFindings, errors.New("findings")), ExitFindings},
		{"scan failure", WithExitCode(ExitScanFailed, errors.New("failed")), ExitScanFailed},
		{"interrupted", fmt.Errorf("wrapped: %w", context.Canceled), ExitInterrupted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExitCode(tt.err); got != tt.want {
				t.Fatalf("ExitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestScanResultExitBehavior(t *testing.T) {
	tests := []struct {
		name      string
		status    probe.Status
		threshold config.FailureThreshold
		severity  *finding.Severity
		want      int
	}{
		{name: "no findings", status: probe.StatusComplete, threshold: config.FailOnHigh, want: ExitSuccess},
		{name: "high finding", status: probe.StatusComplete, threshold: config.FailOnHigh, severity: severityPointer(finding.SeverityHigh), want: ExitFindings},
		{name: "medium below high", status: probe.StatusPartial, threshold: config.FailOnHigh, severity: severityPointer(finding.SeverityMedium), want: ExitSuccess},
		{name: "never", status: probe.StatusComplete, threshold: config.FailOnNever, severity: severityPointer(finding.SeverityCritical), want: ExitSuccess},
		{name: "failed scan takes precedence", status: probe.StatusFailed, threshold: config.FailOnHigh, severity: severityPointer(finding.SeverityHigh), want: ExitScanFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanReport := cliTestReport()
			scanReport.Status = tt.status
			scanReport.Targets[0].Status = tt.status
			scanReport.Configuration.FailureThreshold = tt.threshold
			if tt.severity != nil {
				scanReport.Targets[0].Findings = []finding.Finding{cliTestFinding(*tt.severity)}
			}
			if got := ExitCode(scanResultError(scanReport)); got != tt.want {
				t.Fatalf("exit code = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	output, err := ExecuteForTest(NewRootCommand("1.2.3"), "version")
	if err != nil {
		t.Fatalf("version error = %v", err)
	}
	if output != "1.2.3\n" {
		t.Fatalf("version output = %q", output)
	}
}

func TestPolicyValidate(t *testing.T) {
	valid := `version: 1
rules:
  - id: TEST-001
    title: Test rule
    severity: info
    confidence: high
    description: Test description
    match:
      field: ssh.protocol_version
      equals: "2.0"
    recommendation: Test recommendation
`
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatalf("WriteFile() = %v", err)
	}
	output, err := ExecuteForTest(NewRootCommand("test"), "policy", "validate", path)
	if err != nil {
		t.Fatalf("policy validate = %v", err)
	}
	if output != "Policy valid: 1 rules\n" {
		t.Fatalf("output = %q", output)
	}
}

func TestReportCommandLoadsAndRendersCanonicalReport(t *testing.T) {
	path := writeCLIReport(t, cliTestReport())
	output, err := ExecuteForTest(NewRootCommand("test"), "report", path)
	if err != nil {
		t.Fatalf("report = %v", err)
	}
	for _, want := range []string{"sshscope phase7-test", "Target: 192.0.2.1", "Exit status: 0"} {
		if !strings.Contains(output, want) {
			t.Fatalf("report output %q does not contain %q", output, want)
		}
	}
	jsonOutput, err := ExecuteForTest(NewRootCommand("test"), "report", path, "--format", "json")
	if err != nil {
		t.Fatalf("report --format json = %v", err)
	}
	if !strings.Contains(jsonOutput, `"schema_version": "1"`) {
		t.Fatalf("JSON report output = %q", jsonOutput)
	}
}

func TestReportCommandReplaysFindingExitStatus(t *testing.T) {
	scanReport := cliTestReport()
	scanReport.Targets[0].Findings = []finding.Finding{cliTestFinding(finding.SeverityHigh)}
	output, err := ExecuteForTest(NewRootCommand("test"), "report", writeCLIReport(t, scanReport))
	if ExitCode(err) != ExitFindings {
		t.Fatalf("report exit = %d, error=%v", ExitCode(err), err)
	}
	if !strings.Contains(output, "Exit status: 1") {
		t.Fatalf("report output = %q", output)
	}
}

func TestCompareCommandShowsSemanticChanges(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	before := cliTestReport()
	after := cliTestReport()
	before.Targets[0].Observations = append(before.Targets[0].Observations, evidence.Observation{
		ID: evidence.ObservationBannerRaw, Value: evidence.StringValue("SSH-2.0-Old"), Probe: "banner",
		ObservedAt: now, Confidence: evidence.ConfidenceHigh,
	})
	after.Targets[0].Observations = append(after.Targets[0].Observations, evidence.Observation{
		ID: evidence.ObservationBannerRaw, Value: evidence.StringValue("SSH-2.0-New"), Probe: "banner",
		ObservedAt: now, Confidence: evidence.ConfidenceHigh,
	})
	output, err := ExecuteForTest(NewRootCommand("test"), "compare", writeCLIReport(t, before), writeCLIReport(t, after))
	if err != nil {
		t.Fatalf("compare = %v", err)
	}
	if !strings.Contains(output, "Banner change (self-reported, not a verified package change)") {
		t.Fatalf("compare output = %q", output)
	}
}

func TestReportCommandRejectsUnknownFields(t *testing.T) {
	path := writeCLIReport(t, cliTestReport())
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() = %v", err)
	}
	data = bytes.Replace(data, []byte(`"tool_version": "phase7-test",`), []byte(`"unexpected": true,`), 1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile() = %v", err)
	}
	_, err = ExecuteForTest(NewRootCommand("test"), "report", path)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("report error = %v", err)
	}
}

func TestPolicyValidateRejectsUnknownSchemaField(t *testing.T) {
	invalid := `version: 1
unknown: true
rules: []
`
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
		t.Fatalf("WriteFile() = %v", err)
	}
	_, err := ExecuteForTest(NewRootCommand("test"), "policy", "validate", path)
	if err == nil || !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("policy validate error = %v", err)
	}
}

func TestLoadPolicyDocumentUsesEmbeddedDefault(t *testing.T) {
	document, err := loadPolicyDocument(context.Background(), "")
	if err != nil {
		t.Fatalf("loadPolicyDocument() = %v", err)
	}
	if len(document.Rules) == 0 {
		t.Fatal("embedded policy has no rules")
	}
}

func TestScanValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing target", []string{"scan"}, "provide TARGET"},
		{"two target sources", []string{"scan", "host", "--targets", "targets.txt"}, "mutually exclusive"},
		{"two IP families", []string{"scan", "host", "--ipv4", "--ipv6"}, "mutually exclusive"},
		{"unsafe concurrency", []string{"scan", "host", "--concurrency", "0"}, "concurrency"},
		{"bad threshold", []string{"scan", "host", "--fail-on", "low"}, "unsupported --fail-on"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExecuteForTest(NewRootCommand("test"), tt.args...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Execute() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestAppendAuthenticationProbeHonorsConfiguration(t *testing.T) {
	gate, err := scheduler.NewConnectionGate(1000, 1)
	if err != nil {
		t.Fatalf("NewConnectionGate() = %v", err)
	}
	base := []probe.Probe{fakeNamedProbe("hostkey")}
	tests := []struct {
		name     string
		enabled  bool
		wantSize int
		wantLast string
	}{
		{name: "enabled", enabled: true, wantSize: 2, wantLast: "auth"},
		{name: "disabled", enabled: false, wantSize: 1, wantLast: "hostkey"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.AuthProbeEnabled = tt.enabled
			got, err := appendAuthenticationProbe(base, cfg, gate)
			if err != nil {
				t.Fatalf("appendAuthenticationProbe() = %v", err)
			}
			if len(got) != tt.wantSize || got[len(got)-1].Name() != tt.wantLast {
				t.Fatalf("pipeline size=%d last=%q", len(got), got[len(got)-1].Name())
			}
		})
	}
}

type fakeNamedProbe string

func (p fakeNamedProbe) Name() string { return string(p) }
func (fakeNamedProbe) Run(context.Context, target.Target) probe.Result {
	return probe.Result{}
}

func cliTestReport() report.Report {
	now := time.Unix(1, 0).UTC()
	return report.Report{
		SchemaVersion: report.SchemaVersion, ToolVersion: "phase7-test", StartedAt: now, FinishedAt: now.Add(time.Second),
		Configuration: config.Default(), Authorization: config.Authorization{},
		Targets: []report.TargetResult{{
			Target: target.Target{
				Original: "192.0.2.1", Hostname: "192.0.2.1", ResolvedIP: netip.MustParseAddr("192.0.2.1"),
				Port: 22, IPVersion: target.Version4,
			},
			ProbeResults: []report.ProbeResult{},
			Observations: []evidence.Observation{{
				ID: evidence.ObservationTCPReachable, Value: evidence.BooleanValue(true), Probe: "tcp",
				ObservedAt: now, Confidence: evidence.ConfidenceHigh,
			}},
			Findings: []finding.Finding{}, Errors: []probe.Error{}, Status: probe.StatusComplete,
		}},
		Errors: []probe.Error{}, Status: probe.StatusComplete,
	}
}

func cliTestFinding(severity finding.Severity) finding.Finding {
	return finding.Finding{
		RuleID: "TEST-001", Title: "Test finding", Severity: severity, Confidence: finding.ConfidenceHigh,
		Description:    "Test description",
		Evidence:       []finding.EvidenceReference{{ObservationID: evidence.ObservationTCPReachable, Probe: "tcp"}},
		Recommendation: "Test recommendation",
	}
}

func writeCLIReport(t *testing.T, input report.Report) string {
	t.Helper()
	var data bytes.Buffer
	if err := (report.JSONRenderer{}).Render(context.Background(), &data, input); err != nil {
		t.Fatalf("Render() = %v", err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, data.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile() = %v", err)
	}
	return path
}

func severityPointer(value finding.Severity) *finding.Severity { return &value }
