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

const (
	maximumToolVersionBytes      = 256
	maximumProbeResultsPerTarget = 32
	maximumObservationsPerTarget = 256
	maximumFindingsPerTarget     = 1024
	maximumErrorsPerTarget       = 256
	maximumReportErrors          = 4096
)

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
	} else if len(r.ToolVersion) > maximumToolVersionBytes {
		errs = append(errs, errors.New("tool version is oversized"))
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
		return fmt.Errorf("report exceeds maximum of %d targets", config.AbsoluteMaximumTargets)
	}
	if r.Configuration.MaximumTargets > 0 && len(r.Targets) > r.Configuration.MaximumTargets {
		errs = append(errs, fmt.Errorf("report target count %d exceeds configured maximum %d", len(r.Targets), r.Configuration.MaximumTargets))
	}
	if len(r.Errors) > maximumReportErrors {
		return fmt.Errorf("report exceeds maximum of %d errors", maximumReportErrors)
	}
	targets := make(map[string]struct{}, len(r.Targets))
	completeTargets := 0
	meaningfulTargets := 0
	for i, result := range r.Targets {
		endpoint := result.Target.Endpoint()
		if _, exists := targets[endpoint]; exists {
			errs = append(errs, fmt.Errorf("duplicate target endpoint %q", endpoint))
		}
		targets[endpoint] = struct{}{}
		if err := result.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("target result %d: %w", i, err))
		}
		if result.Status == probe.StatusComplete {
			completeTargets++
			meaningfulTargets++
		} else if result.Status == probe.StatusPartial {
			meaningfulTargets++
		}
	}
	for i, reportErr := range r.Errors {
		if err := reportErr.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("report error %d: %w", i, err))
		}
	}
	switch r.Status {
	case probe.StatusComplete:
		if len(r.Targets) == 0 || len(r.Errors) != 0 || completeTargets != len(r.Targets) {
			errs = append(errs, errors.New("complete report requires at least one complete target and no report errors"))
		}
	case probe.StatusPartial:
		if meaningfulTargets == 0 || len(r.Errors) == 0 && completeTargets == len(r.Targets) {
			errs = append(errs, errors.New("partial report requires meaningful incomplete results or report errors"))
		}
	case probe.StatusFailed:
		if meaningfulTargets != 0 {
			errs = append(errs, errors.New("failed report must not contain meaningful target results"))
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
	if len(r.ProbeResults) > maximumProbeResultsPerTarget {
		return fmt.Errorf("target exceeds maximum of %d probe results", maximumProbeResultsPerTarget)
	}
	if len(r.Observations) > maximumObservationsPerTarget {
		return fmt.Errorf("target exceeds maximum of %d normalized observations", maximumObservationsPerTarget)
	}
	if len(r.Findings) > maximumFindingsPerTarget {
		return fmt.Errorf("target exceeds maximum of %d findings", maximumFindingsPerTarget)
	}
	if len(r.Errors) > maximumErrorsPerTarget {
		return fmt.Errorf("target exceeds maximum of %d errors", maximumErrorsPerTarget)
	}
	probeNames := make(map[string]struct{}, len(r.ProbeResults))
	completeProbes := 0
	meaningfulProbes := 0
	for i, named := range r.ProbeResults {
		if named.Name == "" {
			errs = append(errs, fmt.Errorf("probe result %d has no name", i))
		} else if len(named.Name) > 128 {
			errs = append(errs, fmt.Errorf("probe result %d name is oversized", i))
		} else if _, exists := probeNames[named.Name]; exists {
			errs = append(errs, fmt.Errorf("duplicate probe result %q", named.Name))
		}
		probeNames[named.Name] = struct{}{}
		if err := named.Result.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("probe result %q: %w", named.Name, err))
		}
		for _, observation := range named.Result.Observations {
			if observation.Probe != named.Name {
				errs = append(errs, fmt.Errorf("probe result %q contains observation from %q", named.Name, observation.Probe))
			}
		}
		for _, probeErr := range named.Result.Errors {
			if probeErr.Probe != named.Name {
				errs = append(errs, fmt.Errorf("probe result %q contains error from %q", named.Name, probeErr.Probe))
			}
		}
		if named.Result.Status == probe.StatusComplete {
			completeProbes++
			meaningfulProbes++
		} else if named.Result.Status == probe.StatusPartial {
			meaningfulProbes++
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
	switch r.Status {
	case probe.StatusComplete:
		if len(r.Errors) != 0 || len(r.ProbeResults) > 0 && completeProbes != len(r.ProbeResults) {
			errs = append(errs, errors.New("complete target result requires complete probes and no target errors"))
		}
	case probe.StatusPartial:
		if len(r.ProbeResults) > 0 && meaningfulProbes == 0 || len(r.Errors) == 0 && completeProbes == len(r.ProbeResults) {
			errs = append(errs, errors.New("partial target result requires meaningful incomplete probes or target errors"))
		}
	case probe.StatusFailed:
		if meaningfulProbes != 0 {
			errs = append(errs, errors.New("failed target result must not contain complete or partial probes"))
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
