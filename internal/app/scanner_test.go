package app

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/sshscope/sshscope/internal/config"
	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/finding"
	"github.com/sshscope/sshscope/internal/probe"
	"github.com/sshscope/sshscope/internal/target"
)

type fakeProbe struct {
	name string
	run  func(context.Context, target.Target) probe.Result
}

type fakeEvidenceAwareProbe struct {
	name string
	run  func(context.Context, target.Target, []evidence.Observation) probe.Result
}

type fakeEvaluator struct {
	evaluate func(context.Context, []evidence.Observation) ([]finding.Finding, error)
}

func (e fakeEvaluator) Evaluate(ctx context.Context, observations []evidence.Observation) ([]finding.Finding, error) {
	return e.evaluate(ctx, observations)
}

func (p fakeEvidenceAwareProbe) Name() string { return p.name }
func (p fakeEvidenceAwareProbe) Run(ctx context.Context, item target.Target) probe.Result {
	return p.run(ctx, item, nil)
}
func (p fakeEvidenceAwareProbe) RunWithEvidence(ctx context.Context, item target.Target, prior []evidence.Observation) probe.Result {
	return p.run(ctx, item, prior)
}

func (p fakeProbe) Name() string { return p.name }
func (p fakeProbe) Run(ctx context.Context, item target.Target) probe.Result {
	return p.run(ctx, item)
}

func TestScanPreservesPartialProbeEvidence(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	tcpProbe := fakeProbe{name: "tcp", run: func(context.Context, target.Target) probe.Result {
		return probe.Result{
			Observations: []evidence.Observation{{ID: evidence.ObservationTCPReachable, Value: evidence.BooleanValue(true), Probe: "tcp", ObservedAt: now, Confidence: evidence.ConfidenceHigh}},
			Errors:       []probe.Error{},
			Status:       probe.StatusComplete,
		}
	}}
	bannerProbe := fakeProbe{name: "banner", run: func(context.Context, target.Target) probe.Result {
		probeErr := probe.Error{Kind: probe.ErrorInvalidBanner, Probe: "banner", Message: "invalid banner"}
		return probe.Result{Observations: []evidence.Observation{}, Errors: []probe.Error{probeErr}, Status: probe.StatusFailed}
	}}
	scanner, err := newScannerForTest(t, []probe.Probe{tcpProbe, bannerProbe})
	if err != nil {
		t.Fatalf("NewScanner() = %v", err)
	}
	report, err := scanner.Scan(context.Background(), ScanRequest{
		Targets:       []target.Target{testTarget()},
		Configuration: config.Default(),
	})
	if err != nil {
		t.Fatalf("Scan() = %v", err)
	}
	if report.Status != probe.StatusPartial || report.Targets[0].Status != probe.StatusPartial || len(report.Targets[0].Observations) != 1 {
		t.Fatalf("Scan() = %+v", report)
	}
}

func TestScanEvaluatesNormalizedEvidence(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	collector := fakeProbe{name: "tcp", run: func(context.Context, target.Target) probe.Result {
		return probe.Result{
			Observations: []evidence.Observation{{
				ID: evidence.ObservationTCPReachable, Value: evidence.BooleanValue(true), Probe: "tcp",
				ObservedAt: now, Confidence: evidence.ConfidenceHigh,
			}},
			Errors: []probe.Error{}, Status: probe.StatusComplete,
		}
	}}
	evaluator := fakeEvaluator{evaluate: func(_ context.Context, observations []evidence.Observation) ([]finding.Finding, error) {
		if len(observations) != 1 || observations[0].ID != evidence.ObservationTCPReachable {
			t.Fatalf("evaluator observations = %+v", observations)
		}
		return []finding.Finding{{
			RuleID: "TEST-001", Title: "Test finding", Severity: finding.SeverityInfo,
			Confidence: finding.ConfidenceHigh, Description: "Test description",
			Evidence:       []finding.EvidenceReference{{ObservationID: evidence.ObservationTCPReachable, Probe: "tcp"}},
			Recommendation: "Test recommendation",
		}}, nil
	}}
	scanner, err := NewScanner("test", []probe.Probe{collector}, evidence.StableNormalizer{}, evaluator)
	if err != nil {
		t.Fatalf("NewScanner() = %v", err)
	}
	scanReport, err := scanner.Scan(context.Background(), ScanRequest{Targets: []target.Target{testTarget()}, Configuration: config.Default()})
	if err != nil {
		t.Fatalf("Scan() = %v", err)
	}
	if len(scanReport.Targets[0].Findings) != 1 || scanReport.Targets[0].Findings[0].RuleID != "TEST-001" {
		t.Fatalf("findings = %+v", scanReport.Targets[0].Findings)
	}
}

func TestScanRecordsPolicyEvaluationFailure(t *testing.T) {
	collector := fakeProbe{name: "tcp", run: func(context.Context, target.Target) probe.Result {
		return probe.Result{Observations: []evidence.Observation{}, Errors: []probe.Error{}, Status: probe.StatusComplete}
	}}
	evaluator := fakeEvaluator{evaluate: func(context.Context, []evidence.Observation) ([]finding.Finding, error) {
		return nil, errors.New("evaluation failed")
	}}
	scanner, err := NewScanner("test", []probe.Probe{collector}, evidence.StableNormalizer{}, evaluator)
	if err != nil {
		t.Fatalf("NewScanner() = %v", err)
	}
	scanReport, err := scanner.Scan(context.Background(), ScanRequest{Targets: []target.Target{testTarget()}, Configuration: config.Default()})
	if err != nil {
		t.Fatalf("Scan() = %v", err)
	}
	result := scanReport.Targets[0]
	if result.Status != probe.StatusPartial || len(result.Errors) != 1 || result.Errors[0].Kind != probe.ErrorPolicy {
		t.Fatalf("target result = %+v", result)
	}
}

func TestScanPassesDefensiveCopyToEvidenceAwareProbe(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	kexProbe := fakeProbe{name: "kex", run: func(context.Context, target.Target) probe.Result {
		return probe.Result{
			Observations: []evidence.Observation{{
				ID:         evidence.ObservationHostKeyAlgorithms,
				Value:      evidence.StringsValue([]string{"ssh-ed25519"}),
				Probe:      "kex",
				ObservedAt: now,
				Confidence: evidence.ConfidenceHigh,
			}},
			Errors: []probe.Error{},
			Status: probe.StatusComplete,
		}
	}}
	received := false
	hostKeyProbe := fakeEvidenceAwareProbe{name: "hostkey", run: func(_ context.Context, _ target.Target, prior []evidence.Observation) probe.Result {
		if len(prior) == 1 && prior[0].Value.Strings[0] == "ssh-ed25519" {
			received = true
			prior[0].Value.Strings[0] = "mutated"
		}
		return probe.Result{Observations: []evidence.Observation{}, Errors: []probe.Error{}, Status: probe.StatusComplete}
	}}
	scanner, err := newScannerForTest(t, []probe.Probe{kexProbe, hostKeyProbe})
	if err != nil {
		t.Fatalf("NewScanner() = %v", err)
	}
	scanReport, err := scanner.Scan(context.Background(), ScanRequest{Targets: []target.Target{testTarget()}, Configuration: config.Default()})
	if err != nil {
		t.Fatalf("Scan() = %v", err)
	}
	if !received || scanReport.Targets[0].Observations[0].Value.Strings[0] != "ssh-ed25519" {
		t.Fatalf("evidence handoff received=%v, observations=%+v", received, scanReport.Targets[0].Observations)
	}
}

func TestScanStopsAfterTCPFailure(t *testing.T) {
	called := false
	tcpProbe := fakeProbe{name: "tcp", run: func(context.Context, target.Target) probe.Result {
		probeErr := probe.Error{Kind: probe.ErrorConnectionRefused, Probe: "tcp", Message: "connection refused"}
		return probe.Result{Observations: []evidence.Observation{}, Errors: []probe.Error{probeErr}, Status: probe.StatusFailed}
	}}
	bannerProbe := fakeProbe{name: "banner", run: func(context.Context, target.Target) probe.Result {
		called = true
		return probe.Result{Status: probe.StatusComplete}
	}}
	scanner, err := newScannerForTest(t, []probe.Probe{tcpProbe, bannerProbe})
	if err != nil {
		t.Fatalf("NewScanner() = %v", err)
	}
	report, err := scanner.Scan(context.Background(), ScanRequest{Targets: []target.Target{testTarget()}, Configuration: config.Default()})
	if err != nil {
		t.Fatalf("Scan() = %v", err)
	}
	if called || report.Status != probe.StatusFailed {
		t.Fatalf("banner called = %v, status = %s", called, report.Status)
	}
}

func TestScanReportsResolutionFailure(t *testing.T) {
	unused := fakeProbe{name: "tcp", run: func(context.Context, target.Target) probe.Result { return probe.Result{} }}
	scanner, err := newScannerForTest(t, []probe.Probe{unused})
	if err != nil {
		t.Fatalf("NewScanner() = %v", err)
	}
	report, err := scanner.Scan(context.Background(), ScanRequest{
		PreparationErrors: []target.ResolutionError{{Kind: target.ResolutionDNS, Host: "bad.test", Message: "DNS resolution failed for bad.test"}},
		Configuration:     config.Default(),
	})
	if err != nil {
		t.Fatalf("Scan() = %v", err)
	}
	if report.Status != probe.StatusFailed || len(report.Errors) != 1 || report.Errors[0].Kind != probe.ErrorDNS {
		t.Fatalf("Scan() = %+v", report)
	}
}

func TestScanEnforcesPerTargetDeadline(t *testing.T) {
	blocking := fakeProbe{name: "tcp", run: func(ctx context.Context, _ target.Target) probe.Result {
		<-ctx.Done()
		probeErr := probe.Error{Kind: probe.ErrorCancelled, Probe: "tcp", Message: "cancelled", Cause: ctx.Err()}
		return probe.Result{Observations: []evidence.Observation{}, Errors: []probe.Error{probeErr}, Status: probe.StatusFailed}
	}}
	scanner, err := newScannerForTest(t, []probe.Probe{blocking})
	if err != nil {
		t.Fatalf("NewScanner() = %v", err)
	}
	cfg := config.Default()
	cfg.TargetTimeout = 10 * time.Millisecond
	cfg.ConnectionTimeout = 5 * time.Millisecond
	started := time.Now()
	scanReport, err := scanner.Scan(context.Background(), ScanRequest{Targets: []target.Target{testTarget()}, Configuration: cfg})
	if err != nil {
		t.Fatalf("Scan() = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("target deadline took %v", elapsed)
	}
	if scanReport.Status != probe.StatusFailed {
		t.Fatalf("status = %s", scanReport.Status)
	}
}

func testTarget() target.Target {
	return target.Target{
		Original:   "192.0.2.1",
		Hostname:   "192.0.2.1",
		ResolvedIP: netip.MustParseAddr("192.0.2.1"),
		Port:       22,
		IPVersion:  target.Version4,
	}
}

func newScannerForTest(t *testing.T, probes []probe.Probe) (*ScanService, error) {
	t.Helper()
	return NewScanner("test", probes, evidence.StableNormalizer{}, fakeEvaluator{
		evaluate: func(context.Context, []evidence.Observation) ([]finding.Finding, error) {
			return []finding.Finding{}, nil
		},
	})
}
