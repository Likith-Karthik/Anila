// Package tcp implements a single-attempt TCP reachability probe.
package tcp

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/probe"
	"github.com/sshscope/sshscope/internal/target"
)

const name = "tcp"

// Probe performs one bounded TCP connection attempt and immediately closes a
// successful connection.
type Probe struct {
	connectTimeout time.Duration
	dialer         probe.Dialer
	gate           probe.ConnectionGate
}

func New(connectTimeout time.Duration, dialer probe.Dialer, gate probe.ConnectionGate) (*Probe, error) {
	if connectTimeout <= 0 {
		return nil, errors.New("TCP connect timeout must be positive")
	}
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	if gate == nil {
		return nil, errors.New("TCP connection gate is required")
	}
	return &Probe{connectTimeout: connectTimeout, dialer: dialer, gate: gate}, nil
}

func (*Probe) Name() string { return name }

func (p *Probe) Run(ctx context.Context, item target.Target) probe.Result {
	started := time.Now()
	release, err := p.gate.Acquire(ctx, item.ResolvedIP.String())
	if err != nil {
		probeErr := gateError(err)
		return failedResult(started, probeErr)
	}
	defer release()

	dialCtx, cancel := context.WithTimeout(ctx, p.connectTimeout)
	defer cancel()
	dialStarted := time.Now()
	connection, err := p.dialer.DialContext(dialCtx, "tcp", item.Endpoint())
	latency := time.Since(dialStarted)
	observedAt := time.Now().UTC()
	if err != nil {
		probeErr := probe.ClassifyNetworkError(name, err)
		confidence := evidence.ConfidenceMedium
		if probeErr.Kind == probe.ErrorConnectionRefused {
			confidence = evidence.ConfidenceHigh
		}
		observation := evidence.Observation{
			ID:         evidence.ObservationTCPReachable,
			Value:      evidence.BooleanValue(false),
			Probe:      name,
			ObservedAt: observedAt,
			Confidence: confidence,
			Error: &evidence.ErrorInfo{
				Kind:    string(probeErr.Kind),
				Message: probeErr.Message,
			},
		}
		return probe.Result{
			Observations: []evidence.Observation{observation},
			Errors:       []probe.Error{probeErr},
			Duration:     probe.Duration(time.Since(started)),
			Status:       probe.StatusFailed,
		}
	}
	_ = connection.Close()
	return probe.Result{
		Observations: []evidence.Observation{
			{
				ID:         evidence.ObservationTCPReachable,
				Value:      evidence.BooleanValue(true),
				Probe:      name,
				ObservedAt: observedAt,
				Confidence: evidence.ConfidenceHigh,
			},
			{
				ID:         evidence.ObservationTCPLatency,
				Value:      evidence.MeasurementValue(float64(latency)/float64(time.Millisecond), "milliseconds"),
				Probe:      name,
				ObservedAt: observedAt,
				Confidence: evidence.ConfidenceHigh,
			},
		},
		Errors:   []probe.Error{},
		Duration: probe.Duration(time.Since(started)),
		Status:   probe.StatusComplete,
	}
}

func gateError(err error) probe.Error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return probe.ClassifyNetworkError(name, err)
	}
	return probe.Error{
		Kind:      probe.ErrorRateLimited,
		Probe:     name,
		Message:   "connection start was rate limited",
		Retryable: true,
		Cause:     err,
	}
}

func failedResult(started time.Time, probeErr probe.Error) probe.Result {
	return probe.Result{
		Observations: []evidence.Observation{},
		Errors:       []probe.Error{probeErr},
		Duration:     probe.Duration(time.Since(started)),
		Status:       probe.StatusFailed,
	}
}
