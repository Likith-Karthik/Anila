package app

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sshscope/sshscope/internal/config"
	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/probe"
	"github.com/sshscope/sshscope/internal/target"
)

type fakeProbe struct {
	name string
	run  func(context.Context, target.Target) probe.Result
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
	scanner, err := NewScanner("test", []probe.Probe{tcpProbe, bannerProbe}, evidence.StableNormalizer{})
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
	scanner, err := NewScanner("test", []probe.Probe{tcpProbe, bannerProbe}, evidence.StableNormalizer{})
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
	scanner, err := NewScanner("test", []probe.Probe{unused}, evidence.StableNormalizer{})
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
	scanner, err := NewScanner("test", []probe.Probe{blocking}, evidence.StableNormalizer{})
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
