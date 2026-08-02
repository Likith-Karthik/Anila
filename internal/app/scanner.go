// Package app coordinates independent target, probe, policy, and reporting layers.
package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sshscope/sshscope/internal/config"
	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/finding"
	"github.com/sshscope/sshscope/internal/policy"
	"github.com/sshscope/sshscope/internal/probe"
	"github.com/sshscope/sshscope/internal/report"
	"github.com/sshscope/sshscope/internal/scheduler"
	"github.com/sshscope/sshscope/internal/target"
)

// ScanRequest carries resolved, scope-checked endpoints and invocation metadata.
type ScanRequest struct {
	Targets           []target.Target
	PreparationErrors []target.ResolutionError
	Configuration     config.Config
	Authorization     config.Authorization
}

// Scanner coordinates scanning without owning CLI presentation concerns.
type Scanner interface {
	Scan(context.Context, ScanRequest) (report.Report, error)
}

// ScanService runs an ordered probe pipeline through the bounded scheduler.
type ScanService struct {
	version    string
	probes     []probe.Probe
	normalizer evidence.Normalizer
	evaluator  policy.Evaluator
	now        func() time.Time
}

func NewScanner(version string, probes []probe.Probe, normalizer evidence.Normalizer, evaluator policy.Evaluator) (*ScanService, error) {
	if version == "" {
		return nil, errors.New("scanner version is required")
	}
	if len(probes) == 0 {
		return nil, errors.New("at least one probe is required")
	}
	for index, item := range probes {
		if item == nil || item.Name() == "" {
			return nil, fmt.Errorf("probe %d is invalid", index)
		}
	}
	if normalizer == nil {
		return nil, errors.New("evidence normalizer is required")
	}
	if evaluator == nil {
		return nil, errors.New("policy evaluator is required")
	}
	return &ScanService{
		version: version, probes: append([]probe.Probe(nil), probes...), normalizer: normalizer, evaluator: evaluator, now: time.Now,
	}, nil
}

func (s *ScanService) Scan(ctx context.Context, request ScanRequest) (report.Report, error) {
	startedAt := s.now().UTC()
	if err := request.Configuration.Validate(); err != nil {
		return report.Report{}, fmt.Errorf("invalid scan configuration: %w", err)
	}
	if len(request.Targets) > request.Configuration.MaximumTargets {
		return report.Report{}, fmt.Errorf("resolved target count %d exceeds maximum %d", len(request.Targets), request.Configuration.MaximumTargets)
	}
	for index, item := range request.Targets {
		if err := item.Validate(); err != nil {
			return report.Report{}, fmt.Errorf("target %d: %w", index, err)
		}
	}
	if len(request.Targets) == 0 && len(request.PreparationErrors) == 0 {
		return report.Report{}, errors.New("scan request contains no targets")
	}

	results, err := scheduler.Run(ctx, request.Configuration.Concurrency, request.Targets, func(workerCtx context.Context, item target.Target) report.TargetResult {
		return s.scanTarget(workerCtx, item, request.Configuration.TargetTimeout)
	})
	if err != nil {
		return report.Report{}, err
	}
	reportErrors := make([]probe.Error, 0, len(request.PreparationErrors))
	for _, preparationError := range request.PreparationErrors {
		kind := probe.ErrorDNS
		if preparationError.Kind == target.ResolutionNoAddresses {
			kind = probe.ErrorUnsupported
		}
		reportErrors = append(reportErrors, probe.Error{
			Kind:      kind,
			Probe:     "resolver",
			Message:   preparationError.Message,
			Retryable: preparationError.Retryable,
			Cause:     preparationError.Cause,
		})
	}
	status := overallStatus(results, reportErrors)
	output := report.Report{
		SchemaVersion: report.SchemaVersion,
		ToolVersion:   s.version,
		StartedAt:     startedAt,
		FinishedAt:    s.now().UTC(),
		Configuration: request.Configuration,
		Authorization: request.Authorization,
		Targets:       results,
		Errors:        reportErrors,
		Status:        status,
	}
	if err := output.Validate(); err != nil {
		return report.Report{}, fmt.Errorf("constructed report is invalid: %w", err)
	}
	return output, nil
}

func (s *ScanService) scanTarget(ctx context.Context, item target.Target, timeout time.Duration) report.TargetResult {
	targetCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result := report.TargetResult{
		Target:       item,
		ProbeResults: make([]report.ProbeResult, 0, len(s.probes)),
		Observations: []evidence.Observation{},
		Findings:     []finding.Finding{},
		Errors:       []probe.Error{},
	}
	for index, collector := range s.probes {
		if err := targetCtx.Err(); err != nil {
			cancelled := probe.Error{Kind: probe.ErrorCancelled, Probe: collector.Name(), Message: "probe cancelled by target deadline", Cause: err}
			result.ProbeResults = append(result.ProbeResults, report.ProbeResult{
				Name:   collector.Name(),
				Result: probe.Result{Observations: []evidence.Observation{}, Errors: []probe.Error{cancelled}, Status: probe.StatusFailed},
			})
			result.Errors = append(result.Errors, cancelled)
			continue
		}
		probeResult := probe.Result{}
		if aware, ok := collector.(probe.EvidenceAwareProbe); ok {
			prior := make([]evidence.Observation, len(result.Observations))
			for observationIndex := range result.Observations {
				prior[observationIndex] = evidence.CloneObservation(result.Observations[observationIndex])
			}
			probeResult = aware.RunWithEvidence(targetCtx, item, prior)
		} else {
			probeResult = collector.Run(targetCtx, item)
		}
		result.ProbeResults = append(result.ProbeResults, report.ProbeResult{Name: collector.Name(), Result: probeResult})
		result.Observations = append(result.Observations, probeResult.Observations...)
		result.Errors = append(result.Errors, probeResult.Errors...)
		// TCP failure is sufficient evidence that further connection attempts in
		// this scan would add load without a reasonable chance of success.
		if index == 0 && collector.Name() == "tcp" && probeResult.Status == probe.StatusFailed {
			break
		}
	}
	normalized, err := s.normalizer.Normalize(result.Observations)
	if err != nil {
		normalizeError := probe.Error{Kind: probe.ErrorProtocol, Probe: "normalizer", Message: "collected evidence could not be normalized", Cause: err}
		result.Errors = append(result.Errors, normalizeError)
		result.Observations = []evidence.Observation{}
	} else {
		result.Observations = normalized
		findings, evaluationErr := s.evaluator.Evaluate(targetCtx, result.Observations)
		if evaluationErr != nil {
			result.Errors = append(result.Errors, probe.Error{
				Kind: probe.ErrorPolicy, Probe: "policy", Message: "normalized evidence could not be evaluated", Cause: evaluationErr,
			})
		} else {
			result.Findings = findings
		}
	}
	result.Status = targetStatus(result.ProbeResults, result.Errors)
	return result
}

func targetStatus(results []report.ProbeResult, errors []probe.Error) probe.Status {
	complete := 0
	partial := 0
	for _, result := range results {
		switch result.Result.Status {
		case probe.StatusComplete:
			complete++
		case probe.StatusPartial:
			partial++
		}
	}
	if len(errors) == 0 && len(results) > 0 && complete == len(results) {
		return probe.StatusComplete
	}
	if complete > 0 || partial > 0 {
		return probe.StatusPartial
	}
	return probe.StatusFailed
}

func overallStatus(results []report.TargetResult, errors []probe.Error) probe.Status {
	if len(results) == 0 {
		return probe.StatusFailed
	}
	complete := 0
	meaningful := 0
	for _, result := range results {
		if result.Status == probe.StatusComplete {
			complete++
			meaningful++
		} else if result.Status == probe.StatusPartial {
			meaningful++
		}
	}
	if len(errors) == 0 && complete == len(results) {
		return probe.StatusComplete
	}
	if meaningful > 0 {
		return probe.StatusPartial
	}
	return probe.StatusFailed
}
