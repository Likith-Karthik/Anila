// Package report defines canonical reports and presentation interfaces.
package report

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/sshscope/sshscope/internal/config"
	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/finding"
	"github.com/sshscope/sshscope/internal/probe"
	"github.com/sshscope/sshscope/internal/target"
)

const SchemaVersion = "1"

// TargetResult contains evidence and conclusions for one endpoint.
type TargetResult struct {
	Target       target.Target          `json:"target"`
	ProbeResults []ProbeResult          `json:"probe_results"`
	Observations []evidence.Observation `json:"observations"`
	Findings     []finding.Finding      `json:"findings"`
	Errors       []probe.Error          `json:"errors"`
	Status       probe.Status           `json:"status"`
}

// ProbeResult is a named result. A sorted slice avoids relying on map ordering
// in canonical reports.
type ProbeResult struct {
	Name   string       `json:"name"`
	Result probe.Result `json:"result"`
}

// Report is the canonical versioned scan result.
type Report struct {
	SchemaVersion string               `json:"schema_version"`
	ToolVersion   string               `json:"tool_version"`
	StartedAt     time.Time            `json:"started_at"`
	FinishedAt    time.Time            `json:"finished_at"`
	Configuration config.Config        `json:"configuration"`
	Authorization config.Authorization `json:"authorization"`
	Targets       []TargetResult       `json:"targets"`
	Errors        []probe.Error        `json:"errors"`
	Status        probe.Status         `json:"status"`
}

// Validate checks cross-package invariants before a report is rendered or
// compared. Deterministic sorting is performed by the concrete canonicalizer.
func (r Report) Validate() error {
	var errs []error
	if r.SchemaVersion != SchemaVersion {
		errs = append(errs, fmt.Errorf("unsupported report schema %q", r.SchemaVersion))
	}
	if r.ToolVersion == "" {
		errs = append(errs, errors.New("tool version is required"))
	}
	if r.StartedAt.IsZero() || r.FinishedAt.IsZero() {
		errs = append(errs, errors.New("report start and finish times are required"))
	} else if r.FinishedAt.Before(r.StartedAt) {
		errs = append(errs, errors.New("report finish time precedes start time"))
	}
	if err := r.Configuration.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("invalid report configuration: %w", err))
	}
	if !r.Status.Valid() {
		errs = append(errs, fmt.Errorf("unsupported report status %q", r.Status))
	}
	if len(r.Targets) > config.AbsoluteMaximumTargets {
		errs = append(errs, fmt.Errorf("report exceeds maximum of %d targets", config.AbsoluteMaximumTargets))
	}
	if r.Configuration.MaximumTargets > 0 && len(r.Targets) > r.Configuration.MaximumTargets {
		errs = append(errs, fmt.Errorf("report target count %d exceeds configured maximum %d", len(r.Targets), r.Configuration.MaximumTargets))
	}
	targets := make(map[string]struct{}, len(r.Targets))
	for i, result := range r.Targets {
		endpoint := result.Target.Endpoint()
		if _, exists := targets[endpoint]; exists {
			errs = append(errs, fmt.Errorf("duplicate target endpoint %q", endpoint))
		}
		targets[endpoint] = struct{}{}
		if err := result.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("target result %d: %w", i, err))
		}
	}
	for i, reportErr := range r.Errors {
		if err := reportErr.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("report error %d: %w", i, err))
		}
	}
	return errors.Join(errs...)
}

// Validate checks target-level provenance and typed result invariants.
func (r TargetResult) Validate() error {
	var errs []error
	if err := r.Target.Validate(); err != nil {
		errs = append(errs, err)
	}
	if !r.Status.Valid() {
		errs = append(errs, fmt.Errorf("unsupported target status %q", r.Status))
	}
	probeNames := make(map[string]struct{}, len(r.ProbeResults))
	for i, named := range r.ProbeResults {
		if named.Name == "" {
			errs = append(errs, fmt.Errorf("probe result %d has no name", i))
		} else if _, exists := probeNames[named.Name]; exists {
			errs = append(errs, fmt.Errorf("duplicate probe result %q", named.Name))
		}
		probeNames[named.Name] = struct{}{}
		if err := named.Result.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("probe result %q: %w", named.Name, err))
		}
	}
	observations := make(map[string]struct{}, len(r.Observations))
	for i, observation := range r.Observations {
		key := observation.ID + "\x00" + observation.Probe
		if _, exists := observations[key]; exists {
			errs = append(errs, fmt.Errorf("duplicate normalized observation %q from %q", observation.ID, observation.Probe))
		}
		observations[key] = struct{}{}
		if err := observation.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("normalized observation %d: %w", i, err))
		}
	}
	findings := make(map[string]struct{}, len(r.Findings))
	for i, item := range r.Findings {
		if _, exists := findings[item.RuleID]; exists {
			errs = append(errs, fmt.Errorf("duplicate finding rule ID %q", item.RuleID))
		}
		findings[item.RuleID] = struct{}{}
		if err := item.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("finding %d: %w", i, err))
		}
		for _, reference := range item.Evidence {
			key := reference.ObservationID + "\x00" + reference.Probe
			if reference.Probe != "not_observed" {
				if _, exists := observations[key]; !exists {
					errs = append(errs, fmt.Errorf(
						"finding %q references missing observation %q from %q", item.RuleID, reference.ObservationID, reference.Probe,
					))
				}
			}
		}
	}
	for i, probeErr := range r.Errors {
		if err := probeErr.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("target error %d: %w", i, err))
		}
	}
	return errors.Join(errs...)
}

// Renderer writes a report without changing its semantics.
type Renderer interface {
	Render(context.Context, io.Writer, Report) error
}

// Decoder reads and validates a canonical report from persistent storage.
type Decoder interface {
	Decode(context.Context, io.Reader) (Report, error)
}

// Canonicalizer validates and returns a deterministically ordered report. It
// must copy slices before sorting so server preference order is never mutated.
type Canonicalizer interface {
	Canonicalize(Report) (Report, error)
}
