// Package finding defines policy conclusions derived from evidence.
package finding

import (
	"errors"
	"fmt"
	"strings"
)

const (
	maximumFindingStringBytes = 16 * 1024
	maximumFindingRuleIDBytes = 128
	maximumFindingEvidence    = 256
	maximumFindingReferences  = 256
	maximumAffectedValues     = 4096
)

// Severity is finding impact; it is intentionally independent of confidence.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Confidence is the policy engine's confidence in a conclusion.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Finding is a policy conclusion linked to normalized observations.
type Finding struct {
	RuleID         string              `json:"rule_id"`
	Title          string              `json:"title"`
	Severity       Severity            `json:"severity"`
	Confidence     Confidence          `json:"confidence"`
	Description    string              `json:"description"`
	Evidence       []EvidenceReference `json:"evidence"`
	Recommendation string              `json:"recommendation"`
	References     []string            `json:"references,omitempty"`
	AffectedValues []string            `json:"affected_values,omitempty"`
}

// EvidenceReference links a finding to a normalized observation without
// copying raw evidence into the conclusion.
type EvidenceReference struct {
	ObservationID string `json:"observation_id"`
	Probe         string `json:"probe"`
}

// Valid reports whether the severity is supported.
func (s Severity) Valid() bool {
	return s == SeverityCritical || s == SeverityHigh || s == SeverityMedium ||
		s == SeverityLow || s == SeverityInfo
}

// Valid reports whether the confidence is supported.
func (c Confidence) Valid() bool {
	return c == ConfidenceHigh || c == ConfidenceMedium || c == ConfidenceLow
}

// Validate checks fields required for stable reporting and comparison.
func (f Finding) Validate() error {
	var errs []error
	if f.RuleID == "" {
		errs = append(errs, errors.New("finding rule ID is required"))
	} else if len(f.RuleID) > maximumFindingRuleIDBytes || strings.ContainsAny(f.RuleID, "\x00\r\n\t ") {
		errs = append(errs, errors.New("finding rule ID is oversized or contains whitespace/control characters"))
	}
	if f.Title == "" {
		errs = append(errs, errors.New("finding title is required"))
	}
	if !f.Severity.Valid() {
		errs = append(errs, fmt.Errorf("unsupported finding severity %q", f.Severity))
	}
	if !f.Confidence.Valid() {
		errs = append(errs, fmt.Errorf("unsupported finding confidence %q", f.Confidence))
	}
	if f.Description == "" {
		errs = append(errs, errors.New("finding description is required"))
	}
	if f.Recommendation == "" {
		errs = append(errs, errors.New("finding recommendation is required"))
	}
	if len(f.Evidence) == 0 {
		errs = append(errs, errors.New("finding requires at least one evidence reference"))
	} else if len(f.Evidence) > maximumFindingEvidence {
		errs = append(errs, fmt.Errorf("finding exceeds %d evidence references", maximumFindingEvidence))
	}
	for i, reference := range f.Evidence {
		if reference.ObservationID == "" || reference.Probe == "" {
			errs = append(errs, fmt.Errorf("evidence reference %d requires observation ID and probe", i))
		} else if len(reference.ObservationID) > maximumFindingStringBytes || len(reference.Probe) > maximumFindingStringBytes {
			errs = append(errs, fmt.Errorf("evidence reference %d is oversized", i))
		}
	}
	for _, field := range []struct {
		name  string
		value string
	}{{"title", f.Title}, {"description", f.Description}, {"recommendation", f.Recommendation}} {
		if len(field.value) > maximumFindingStringBytes {
			errs = append(errs, fmt.Errorf("finding %s is oversized", field.name))
		}
	}
	if len(f.References) > maximumFindingReferences {
		errs = append(errs, fmt.Errorf("finding exceeds %d references", maximumFindingReferences))
	}
	if len(f.AffectedValues) > maximumAffectedValues {
		errs = append(errs, fmt.Errorf("finding exceeds %d affected values", maximumAffectedValues))
	}
	for index, value := range f.References {
		if len(value) > maximumFindingStringBytes {
			errs = append(errs, fmt.Errorf("finding reference %d is oversized", index))
		}
	}
	for index, value := range f.AffectedValues {
		if len(value) > maximumFindingStringBytes {
			errs = append(errs, fmt.Errorf("finding affected value %d is oversized", index))
		}
	}
	return errors.Join(errs...)
}
