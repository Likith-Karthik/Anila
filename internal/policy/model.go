// Package policy evaluates normalized observations without performing probes.
package policy

import (
	"errors"
	"fmt"
	"math"

	"github.com/sshscope/sshscope/internal/finding"
)

// ScalarKind identifies a typed YAML scalar used by equals and not_equals.
type ScalarKind string

const (
	ScalarString  ScalarKind = "string"
	ScalarBoolean ScalarKind = "boolean"
	ScalarNumber  ScalarKind = "number"
)

// Scalar represents policy equality operands without using untyped maps. The
// policy loader will decode compact YAML scalars into this form.
type Scalar struct {
	Kind    ScalarKind `json:"kind"`
	String  string     `json:"string,omitempty"`
	Boolean bool       `json:"boolean,omitempty"`
	Number  float64    `json:"number,omitempty"`
}

func StringScalar(value string) Scalar {
	return Scalar{Kind: ScalarString, String: value}
}

func BooleanScalar(value bool) Scalar {
	return Scalar{Kind: ScalarBoolean, Boolean: value}
}

func NumberScalar(value float64) Scalar {
	return Scalar{Kind: ScalarNumber, Number: value}
}

// Validate rejects unknown kinds and non-finite numbers that JSON cannot
// represent canonically.
func (s Scalar) Validate() error {
	switch s.Kind {
	case ScalarString, ScalarBoolean:
		return nil
	case ScalarNumber:
		if math.IsNaN(s.Number) || math.IsInf(s.Number, 0) {
			return errors.New("numeric policy scalar must be finite")
		}
		return nil
	default:
		return fmt.Errorf("unsupported policy scalar kind %q", s.Kind)
	}
}

// Condition is a declarative expression. Exactly one leaf operator or compound
// operator is expected; validation is the policy loader's responsibility.
type Condition struct {
	Field       string      `yaml:"field,omitempty" json:"field,omitempty"`
	Equals      *Scalar     `yaml:"equals,omitempty" json:"equals,omitempty"`
	NotEquals   *Scalar     `yaml:"not_equals,omitempty" json:"not_equals,omitempty"`
	Contains    *string     `yaml:"contains,omitempty" json:"contains,omitempty"`
	ContainsAny []string    `yaml:"contains_any,omitempty" json:"contains_any,omitempty"`
	ContainsAll []string    `yaml:"contains_all,omitempty" json:"contains_all,omitempty"`
	Prefix      *string     `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Suffix      *string     `yaml:"suffix,omitempty" json:"suffix,omitempty"`
	Regex       *string     `yaml:"regex,omitempty" json:"regex,omitempty"`
	Exists      *bool       `yaml:"exists,omitempty" json:"exists,omitempty"`
	NotExists   *bool       `yaml:"not_exists,omitempty" json:"not_exists,omitempty"`
	GreaterThan *float64    `yaml:"greater_than,omitempty" json:"greater_than,omitempty"`
	AtLeast     *float64    `yaml:"at_least,omitempty" json:"at_least,omitempty"`
	LessThan    *float64    `yaml:"less_than,omitempty" json:"less_than,omitempty"`
	AtMost      *float64    `yaml:"at_most,omitempty" json:"at_most,omitempty"`
	All         []Condition `yaml:"all,omitempty" json:"all,omitempty"`
	Any         []Condition `yaml:"any,omitempty" json:"any,omitempty"`
	Not         *Condition  `yaml:"not,omitempty" json:"not,omitempty"`
}

// Rule maps a declarative condition to one finding.
type Rule struct {
	ID             string             `yaml:"id" json:"id"`
	Title          string             `yaml:"title" json:"title"`
	Severity       finding.Severity   `yaml:"severity" json:"severity"`
	Confidence     finding.Confidence `yaml:"confidence" json:"confidence"`
	Description    string             `yaml:"description" json:"description"`
	Match          Condition          `yaml:"match" json:"match"`
	Recommendation string             `yaml:"recommendation" json:"recommendation"`
	References     []string           `yaml:"references,omitempty" json:"references,omitempty"`
}

// Document is the versioned on-disk policy model.
type Document struct {
	Version int    `yaml:"version" json:"version"`
	Rules   []Rule `yaml:"rules" json:"rules"`
}

// ValidateHeader validates invariants that do not depend on matcher semantics.
// Full condition validation belongs to the policy loader in Phase 6.
func (d Document) ValidateHeader() error {
	if d.Version != 1 {
		return fmt.Errorf("unsupported policy version %d", d.Version)
	}
	if len(d.Rules) == 0 {
		return errors.New("policy must contain at least one rule")
	}
	seen := make(map[string]struct{}, len(d.Rules))
	for i, rule := range d.Rules {
		if rule.ID == "" {
			return fmt.Errorf("rule %d has no ID", i)
		}
		if _, exists := seen[rule.ID]; exists {
			return fmt.Errorf("duplicate rule ID %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		if !rule.Severity.Valid() {
			return fmt.Errorf("rule %q has invalid severity %q", rule.ID, rule.Severity)
		}
		if !rule.Confidence.Valid() {
			return fmt.Errorf("rule %q has invalid confidence %q", rule.ID, rule.Confidence)
		}
	}
	return nil
}
