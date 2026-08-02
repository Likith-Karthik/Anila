// Package finding defines policy conclusions derived from evidence.
package finding

import (
	"errors"
	"fmt"
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
	}
	for i, reference := range f.Evidence {
		if reference.ObservationID == "" || reference.Probe == "" {
			errs = append(errs, fmt.Errorf("evidence reference %d requires observation ID and probe", i))
		}
	}
	return errors.Join(errs...)
}
