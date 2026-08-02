package report

import (
	"maps"
	"slices"
	"sort"

	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/finding"
	"github.com/sshscope/sshscope/internal/probe"
)

// StableCanonicalizer deep-copies and deterministically orders report-level
// collections. It never sorts lists whose order was supplied by the server.
type StableCanonicalizer struct{}

func (StableCanonicalizer) Canonicalize(input Report) (Report, error) {
	if err := input.Validate(); err != nil {
		return Report{}, err
	}
	result := input
	result.Targets = make([]TargetResult, len(input.Targets))
	for index, targetResult := range input.Targets {
		result.Targets[index] = cloneTargetResult(targetResult)
	}
	result.Errors = cloneErrors(input.Errors)
	sort.SliceStable(result.Targets, func(i, j int) bool {
		left, right := result.Targets[i].Target, result.Targets[j].Target
		if left.Endpoint() != right.Endpoint() {
			return left.Endpoint() < right.Endpoint()
		}
		return left.Original < right.Original
	})
	sortErrors(result.Errors)
	return result, nil
}

func cloneTargetResult(input TargetResult) TargetResult {
	result := input
	result.Target.Metadata = maps.Clone(input.Target.Metadata)
	result.ProbeResults = make([]ProbeResult, len(input.ProbeResults))
	for index, named := range input.ProbeResults {
		result.ProbeResults[index] = ProbeResult{Name: named.Name, Result: cloneProbeResult(named.Result)}
	}
	result.Observations = make([]evidence.Observation, len(input.Observations))
	for index, observation := range input.Observations {
		result.Observations[index] = evidence.CloneObservation(observation)
		sortHostKeys(result.Observations[index].Value.HostKeys)
	}
	result.Findings = cloneFindings(input.Findings)
	result.Errors = cloneErrors(input.Errors)

	sort.SliceStable(result.ProbeResults, func(i, j int) bool { return result.ProbeResults[i].Name < result.ProbeResults[j].Name })
	sortObservations(result.Observations)
	sort.SliceStable(result.Findings, func(i, j int) bool {
		left, right := result.Findings[i], result.Findings[j]
		if severityRank(left.Severity) != severityRank(right.Severity) {
			return severityRank(left.Severity) < severityRank(right.Severity)
		}
		if left.RuleID != right.RuleID {
			return left.RuleID < right.RuleID
		}
		return left.Title < right.Title
	})
	sortErrors(result.Errors)
	return result
}

func cloneProbeResult(input probe.Result) probe.Result {
	result := input
	result.Observations = make([]evidence.Observation, len(input.Observations))
	for index, observation := range input.Observations {
		result.Observations[index] = evidence.CloneObservation(observation)
		sortHostKeys(result.Observations[index].Value.HostKeys)
	}
	result.Errors = cloneErrors(input.Errors)
	sortObservations(result.Observations)
	sortErrors(result.Errors)
	return result
}

func cloneFindings(input []finding.Finding) []finding.Finding {
	if input == nil {
		return []finding.Finding{}
	}
	result := slices.Clone(input)
	for index := range result {
		result[index].Evidence = slices.Clone(input[index].Evidence)
		result[index].References = slices.Clone(input[index].References)
		result[index].AffectedValues = slices.Clone(input[index].AffectedValues)
		sort.SliceStable(result[index].Evidence, func(i, j int) bool {
			if result[index].Evidence[i].ObservationID != result[index].Evidence[j].ObservationID {
				return result[index].Evidence[i].ObservationID < result[index].Evidence[j].ObservationID
			}
			return result[index].Evidence[i].Probe < result[index].Evidence[j].Probe
		})
		slices.Sort(result[index].References)
		slices.Sort(result[index].AffectedValues)
	}
	return result
}

func sortHostKeys(keys []evidence.HostKey) {
	sort.SliceStable(keys, func(i, j int) bool {
		if keys[i].FingerprintSHA256 != keys[j].FingerprintSHA256 {
			return keys[i].FingerprintSHA256 < keys[j].FingerprintSHA256
		}
		if keys[i].Algorithm != keys[j].Algorithm {
			return keys[i].Algorithm < keys[j].Algorithm
		}
		return keys[i].KnownHostsStatus < keys[j].KnownHostsStatus
	})
}

func cloneErrors(input []probe.Error) []probe.Error {
	if input == nil {
		return []probe.Error{}
	}
	return slices.Clone(input)
}

func sortObservations(observations []evidence.Observation) {
	sort.SliceStable(observations, func(i, j int) bool {
		if observations[i].ID != observations[j].ID {
			return observations[i].ID < observations[j].ID
		}
		return observations[i].Probe < observations[j].Probe
	})
}

func sortErrors(errors []probe.Error) {
	sort.SliceStable(errors, func(i, j int) bool {
		if errors[i].Probe != errors[j].Probe {
			return errors[i].Probe < errors[j].Probe
		}
		if errors[i].Kind != errors[j].Kind {
			return errors[i].Kind < errors[j].Kind
		}
		return errors[i].Message < errors[j].Message
	})
}

func severityRank(severity finding.Severity) int {
	switch severity {
	case finding.SeverityCritical:
		return 0
	case finding.SeverityHigh:
		return 1
	case finding.SeverityMedium:
		return 2
	case finding.SeverityLow:
		return 3
	default:
		return 4
	}
}
