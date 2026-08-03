// Package probe defines collection interfaces and typed operational errors.
package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/target"
)

const (
	maximumProbeObservations = 256
	maximumProbeErrors       = 256
	maximumProbeNameBytes    = 128
	maximumProbeMessageBytes = 4 * 1024
)

// Status describes whether a probe produced all intended evidence.
type Status string

const (
	StatusComplete Status = "complete"
	StatusPartial  Status = "partial"
	StatusFailed   Status = "failed"
)

// Valid reports whether the completion status is supported.
func (s Status) Valid() bool {
	return s == StatusComplete || s == StatusPartial || s == StatusFailed
}

// ErrorKind classifies failures without relying on platform-specific messages.
type ErrorKind string

const (
	ErrorDNS                ErrorKind = "dns_error"
	ErrorConnectionTimeout  ErrorKind = "connection_timeout"
	ErrorConnectionRefused  ErrorKind = "connection_refused"
	ErrorNetworkUnreachable ErrorKind = "network_unreachable"
	ErrorNetwork            ErrorKind = "network_error"
	ErrorProtocol           ErrorKind = "protocol_error"
	ErrorInvalidBanner      ErrorKind = "invalid_banner"
	ErrorInvalidPacket      ErrorKind = "invalid_packet"
	ErrorUnexpectedMessage  ErrorKind = "unexpected_message"
	ErrorHandshake          ErrorKind = "handshake_error"
	ErrorAuthProbe          ErrorKind = "auth_probe_error"
	ErrorPolicy             ErrorKind = "policy_error"
	ErrorRateLimited        ErrorKind = "rate_limited"
	ErrorCancelled          ErrorKind = "cancelled"
	ErrorUnsupported        ErrorKind = "unsupported"
)

// Error is a typed probe error. Cause is retained for diagnostics but omitted
// from serialized reports.
type Error struct {
	Kind      ErrorKind `json:"kind"`
	Probe     string    `json:"probe"`
	Message   string    `json:"message"`
	Retryable bool      `json:"retryable"`
	Cause     error     `json:"-"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Kind, e.Message)
}

func (e Error) Unwrap() error { return e.Cause }

// Validate checks stable, reportable error fields.
func (e Error) Validate() error {
	var errs []error
	if !e.Kind.Valid() {
		errs = append(errs, fmt.Errorf("unsupported probe error kind %q", e.Kind))
	}
	if e.Probe == "" {
		errs = append(errs, errors.New("probe error source is required"))
	} else if len(e.Probe) > maximumProbeNameBytes {
		errs = append(errs, errors.New("probe error source is oversized"))
	}
	if e.Message == "" {
		errs = append(errs, errors.New("probe error message is required"))
	} else if len(e.Message) > maximumProbeMessageBytes {
		errs = append(errs, errors.New("probe error message is oversized"))
	}
	return errors.Join(errs...)
}

// Valid reports whether the error kind is part of the stable error taxonomy.
func (k ErrorKind) Valid() bool {
	switch k {
	case ErrorDNS, ErrorConnectionTimeout, ErrorConnectionRefused,
		ErrorNetworkUnreachable, ErrorNetwork, ErrorProtocol, ErrorInvalidBanner,
		ErrorInvalidPacket, ErrorUnexpectedMessage, ErrorHandshake,
		ErrorAuthProbe, ErrorPolicy, ErrorRateLimited, ErrorCancelled, ErrorUnsupported:
		return true
	default:
		return false
	}
}

// Duration encodes elapsed time as a Go duration string rather than an opaque
// nanosecond count in canonical JSON.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	if d < 0 {
		return nil, errors.New("probe duration must not be negative")
	}
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("probe duration must be a string: %w", err)
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("parse probe duration: %w", err)
	}
	if parsed < 0 {
		return errors.New("probe duration must not be negative")
	}
	*d = Duration(parsed)
	return nil
}

// TimeDuration returns the standard-library duration value.
func (d Duration) TimeDuration() time.Duration { return time.Duration(d) }

// Result preserves successful observations even when another step fails.
type Result struct {
	Observations []evidence.Observation `json:"observations"`
	Errors       []Error                `json:"errors"`
	Duration     Duration               `json:"duration"`
	Status       Status                 `json:"status"`
}

// Validate checks result invariants without interpreting the evidence.
func (r Result) Validate() error {
	var errs []error
	if !r.Status.Valid() {
		errs = append(errs, fmt.Errorf("unsupported probe status %q", r.Status))
	}
	if r.Duration < 0 {
		errs = append(errs, errors.New("probe duration must not be negative"))
	}
	if len(r.Observations) > maximumProbeObservations {
		errs = append(errs, fmt.Errorf("probe result exceeds %d observations", maximumProbeObservations))
	}
	if len(r.Errors) > maximumProbeErrors {
		errs = append(errs, fmt.Errorf("probe result exceeds %d errors", maximumProbeErrors))
	}
	switch r.Status {
	case StatusComplete:
		if len(r.Errors) != 0 {
			errs = append(errs, errors.New("complete probe result must not contain errors"))
		}
	case StatusPartial:
		if len(r.Observations) == 0 || len(r.Errors) == 0 {
			errs = append(errs, errors.New("partial probe result requires observations and errors"))
		}
	case StatusFailed:
		if len(r.Errors) == 0 {
			errs = append(errs, errors.New("failed probe result requires an error"))
		}
	}
	for i, observation := range r.Observations {
		if err := observation.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("observation %d: %w", i, err))
		}
	}
	for i, probeErr := range r.Errors {
		if err := probeErr.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("error %d: %w", i, err))
		}
	}
	return errors.Join(errs...)
}

// Probe observes one target and must honor context cancellation and deadlines.
type Probe interface {
	Name() string
	Run(context.Context, target.Target) Result
}

// EvidenceAwareProbe is implemented by probes whose bounded behavior depends
// on observations produced earlier in the ordered pipeline. Prior evidence is
// a defensive copy and must still be treated as read-only.
type EvidenceAwareProbe interface {
	Probe
	RunWithEvidence(context.Context, target.Target, []evidence.Observation) Result
}
