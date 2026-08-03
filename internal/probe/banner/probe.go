package banner

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/probe"
	"github.com/sshscope/sshscope/internal/target"
)

const name = "banner"

// Probe opens one bounded connection and reads only through the server's SSH
// identification line.
type Probe struct {
	operationTimeout time.Duration
	dialer           probe.Dialer
	gate             probe.ConnectionGate
	limits           Limits
}

func New(operationTimeout time.Duration, dialer probe.Dialer, gate probe.ConnectionGate, limits Limits) (*Probe, error) {
	if operationTimeout <= 0 {
		return nil, errors.New("banner operation timeout must be positive")
	}
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	if gate == nil {
		return nil, errors.New("banner connection gate is required")
	}
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}
	if limits.MaxLineBytes < 8 || limits.MaxPreBannerLines < 0 || limits.MaxTotalBytes < limits.MaxLineBytes {
		return nil, errors.New("invalid banner limits")
	}
	return &Probe{operationTimeout: operationTimeout, dialer: dialer, gate: gate, limits: limits}, nil
}

func (*Probe) Name() string { return name }

func (p *Probe) Run(ctx context.Context, item target.Target) probe.Result {
	started := time.Now()
	release, err := p.gate.Acquire(ctx, item.ResolvedIP.String())
	if err != nil {
		return failed(started, gateError(err), nil)
	}
	defer release()

	operationCtx, cancel := context.WithTimeout(ctx, p.operationTimeout)
	defer cancel()
	connection, err := p.dialer.DialContext(operationCtx, "tcp", item.Endpoint())
	if err != nil {
		return failed(started, probe.ClassifyNetworkError(name, err), nil)
	}
	defer connection.Close()
	stopConnectionContext, err := probe.BindConnectionToContext(operationCtx, connection)
	if err != nil {
		return failed(started, probe.ClassifyNetworkError(name, err), nil)
	}
	defer stopConnectionContext()

	identification, err := ParseIdentification(connection, p.limits)
	observedAt := time.Now().UTC()
	observations := []evidence.Observation{}
	if len(identification.PreBannerLines) > 0 {
		observations = preBannerObservation(identification.PreBannerLines, observedAt)
	}
	if err != nil {
		var probeErr probe.Error
		if isLimitOrFormatError(err) {
			probeErr = probe.Error{
				Kind:      probe.ErrorInvalidBanner,
				Probe:     name,
				Message:   "server identification is invalid or exceeds safety limits",
				Retryable: false,
				Cause:     err,
			}
		} else {
			probeErr = probe.ClassifyNetworkError(name, err)
		}
		return failed(started, probeErr, observations)
	}
	if len(observations) == 0 {
		observations = preBannerObservation([]string{}, observedAt)
	}

	observations = append(observations,
		evidence.Observation{
			ID:         evidence.ObservationBannerRaw,
			Value:      evidence.StringValue(identification.Raw),
			Probe:      name,
			ObservedAt: observedAt,
			Confidence: evidence.ConfidenceHigh,
			Raw:        identification.Raw,
		},
		evidence.Observation{
			ID:         evidence.ObservationProtocolVersion,
			Value:      evidence.StringValue(identification.ProtocolVersion),
			Probe:      name,
			ObservedAt: observedAt,
			Confidence: evidence.ConfidenceHigh,
		},
		evidence.Observation{
			ID:         evidence.ObservationSoftwareVersion,
			Value:      evidence.StringValue(identification.SoftwareVersion),
			Probe:      name,
			ObservedAt: observedAt,
			Confidence: evidence.ConfidenceHigh,
		},
		evidence.Observation{
			ID:         evidence.ObservationSoftwareComment,
			Value:      evidence.StringValue(identification.Comment),
			Probe:      name,
			ObservedAt: observedAt,
			Confidence: evidence.ConfidenceHigh,
		},
	)
	return probe.Result{
		Observations: observations,
		Errors:       []probe.Error{},
		Duration:     probe.Duration(time.Since(started)),
		Status:       probe.StatusComplete,
	}
}

func preBannerObservation(lines []string, observedAt time.Time) []evidence.Observation {
	return []evidence.Observation{{
		ID:         evidence.ObservationBannerPreLines,
		Value:      evidence.StringsValue(lines),
		Probe:      name,
		ObservedAt: observedAt,
		Confidence: evidence.ConfidenceHigh,
	}}
}

func failed(started time.Time, probeErr probe.Error, observations []evidence.Observation) probe.Result {
	status := probe.StatusFailed
	if len(observations) > 0 {
		status = probe.StatusPartial
	}
	if observations == nil {
		observations = []evidence.Observation{}
	}
	return probe.Result{
		Observations: observations,
		Errors:       []probe.Error{probeErr},
		Duration:     probe.Duration(time.Since(started)),
		Status:       status,
	}
}

func gateError(err error) probe.Error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return probe.ClassifyNetworkError(name, err)
	}
	return probe.Error{Kind: probe.ErrorRateLimited, Probe: name, Message: "connection start was rate limited", Retryable: true, Cause: err}
}

func isLimitOrFormatError(err error) bool {
	return errors.Is(err, ErrLineTooLong) || errors.Is(err, ErrTooManyPreLines) ||
		errors.Is(err, ErrTotalLimit) || errors.Is(err, ErrNoIdentification) ||
		errors.Is(err, ErrInvalidFormat)
}
