package report

import (
	"fmt"

	"github.com/sshscope/sshscope/internal/config"
	"github.com/sshscope/sshscope/internal/finding"
)

// FindingsMeetThreshold reports whether any finding triggers the configured
// process-failure threshold.
func FindingsMeetThreshold(input Report) (bool, error) {
	threshold := input.Configuration.FailureThreshold
	if threshold == config.FailOnNever {
		return false, nil
	}
	minimum, ok := thresholdSeverityRank(threshold)
	if !ok {
		return false, fmt.Errorf("unsupported failure threshold %q", threshold)
	}
	for _, targetResult := range input.Targets {
		for _, item := range targetResult.Findings {
			rank, ok := findingSeverityRank(item.Severity)
			if !ok {
				return false, fmt.Errorf("unsupported finding severity %q", item.Severity)
			}
			if rank <= minimum {
				return true, nil
			}
		}
	}
	return false, nil
}

func thresholdSeverityRank(threshold config.FailureThreshold) (int, bool) {
	switch threshold {
	case config.FailOnCritical:
		return 0, true
	case config.FailOnHigh:
		return 1, true
	case config.FailOnMedium:
		return 2, true
	default:
		return 0, false
	}
}

func findingSeverityRank(severity finding.Severity) (int, bool) {
	switch severity {
	case finding.SeverityCritical:
		return 0, true
	case finding.SeverityHigh:
		return 1, true
	case finding.SeverityMedium:
		return 2, true
	case finding.SeverityLow:
		return 3, true
	case finding.SeverityInfo:
		return 4, true
	default:
		return 0, false
	}
}
