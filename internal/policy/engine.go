package policy

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/finding"
)

// Evaluator converts observations into findings according to a loaded policy.
type Evaluator interface {
	Evaluate(context.Context, []evidence.Observation) ([]finding.Finding, error)
}

// Engine is an immutable, concurrency-safe policy evaluator.
type Engine struct {
	document Document
	regexes  map[string]*regexp.Regexp
}

// NewEngine validates and compiles an immutable policy document.
func NewEngine(document Document) (*Engine, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	engine := &Engine{document: cloneDocument(document), regexes: make(map[string]*regexp.Regexp)}
	for _, rule := range document.Rules {
		collectRegexes(rule.Match, engine.regexes)
	}
	return engine, nil
}

// Evaluate applies every rule to validated normalized observations.
func (e *Engine) Evaluate(ctx context.Context, observations []evidence.Observation) ([]finding.Finding, error) {
	if e == nil {
		return nil, errors.New("policy engine is required")
	}
	index := make(map[string][]evidence.Observation, len(observations))
	seen := make(map[string]struct{}, len(observations))
	for observationIndex, observation := range observations {
		if err := observation.Validate(); err != nil {
			return nil, fmt.Errorf("observation %d: %w", observationIndex, err)
		}
		key := observation.ID + "\x00" + observation.Probe
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("observations are not normalized: duplicate %q from %q", observation.ID, observation.Probe)
		}
		seen[key] = struct{}{}
		index[observation.ID] = append(index[observation.ID], observation)
	}

	findings := make([]finding.Finding, 0)
	for _, rule := range e.document.Rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		matched, err := e.match(ctx, rule.Match, index)
		if err != nil {
			return nil, fmt.Errorf("evaluate rule %q: %w", rule.ID, err)
		}
		if !matched.matched {
			continue
		}
		item := finding.Finding{
			RuleID:         rule.ID,
			Title:          rule.Title,
			Severity:       rule.Severity,
			Confidence:     rule.Confidence,
			Description:    rule.Description,
			Evidence:       deduplicateReferences(matched.references),
			Recommendation: rule.Recommendation,
			References:     slices.Clone(rule.References),
			AffectedValues: deduplicateStrings(matched.affected),
		}
		if err := item.Validate(); err != nil {
			return nil, fmt.Errorf("rule %q produced an invalid finding: %w", rule.ID, err)
		}
		findings = append(findings, item)
	}
	return findings, nil
}

type atom struct {
	kind    ScalarKind
	string  string
	boolean bool
	number  float64
}

func (a atom) display() string {
	switch a.kind {
	case ScalarString:
		return a.string
	case ScalarBoolean:
		return strconv.FormatBool(a.boolean)
	case ScalarNumber:
		return strconv.FormatFloat(a.number, 'g', -1, 64)
	default:
		return ""
	}
}

type projection struct {
	shape      fieldShape
	exists     bool
	atoms      []atom
	references []finding.EvidenceReference
}

type matchResult struct {
	matched    bool
	references []finding.EvidenceReference
	affected   []string
}

func (e *Engine) match(ctx context.Context, condition Condition, index map[string][]evidence.Observation) (matchResult, error) {
	if err := ctx.Err(); err != nil {
		return matchResult{}, err
	}
	if condition.All != nil {
		result := matchResult{matched: true}
		for _, child := range condition.All {
			childResult, err := e.match(ctx, child, index)
			if err != nil {
				return matchResult{}, err
			}
			result.matched = result.matched && childResult.matched
			result.references = append(result.references, childResult.references...)
			result.affected = append(result.affected, childResult.affected...)
		}
		return result, nil
	}
	if condition.Any != nil {
		result := matchResult{}
		allReferences := make([]finding.EvidenceReference, 0)
		for _, child := range condition.Any {
			childResult, err := e.match(ctx, child, index)
			if err != nil {
				return matchResult{}, err
			}
			allReferences = append(allReferences, childResult.references...)
			if childResult.matched {
				result.matched = true
				result.references = append(result.references, childResult.references...)
				result.affected = append(result.affected, childResult.affected...)
			}
		}
		if !result.matched {
			// A parent not(any(...)) still needs provenance for the observations
			// that established that no child matched.
			result.references = allReferences
		}
		return result, nil
	}
	if condition.Not != nil {
		result, err := e.match(ctx, *condition.Not, index)
		result.matched = !result.matched
		return result, err
	}
	return e.matchLeaf(condition, projectField(condition.Field, index)), nil
}

func (e *Engine) matchLeaf(condition Condition, field projection) matchResult {
	base := matchResult{references: field.references}
	if condition.Exists != nil {
		base.matched = field.exists == *condition.Exists
		return ensureAbsenceReference(base, condition.Field, field.exists)
	}
	if condition.NotExists != nil {
		base.matched = !field.exists == *condition.NotExists
		return ensureAbsenceReference(base, condition.Field, field.exists)
	}
	if !field.exists {
		return ensureAbsenceReference(base, condition.Field, false)
	}

	if condition.Equals != nil || condition.NotEquals != nil {
		operand := condition.Equals
		negated := false
		if condition.NotEquals != nil {
			operand = condition.NotEquals
			negated = true
		}
		equal := false
		for _, value := range field.atoms {
			if atomEquals(value, *operand) {
				equal = true
				base.affected = append(base.affected, value.display())
			}
		}
		base.matched = equal
		if negated {
			base.matched = !equal
			if base.matched {
				base.affected = atomDisplays(field.atoms)
			}
		}
		return base
	}
	if condition.Contains != nil {
		base.affected = matchingStrings(field, func(value string) bool {
			if field.shape == shapeString {
				return strings.Contains(value, *condition.Contains)
			}
			return value == *condition.Contains
		})
		base.matched = len(base.affected) > 0
		return base
	}
	if condition.ContainsAny != nil || condition.ContainsAll != nil {
		operands := condition.ContainsAny
		requireAll := false
		if condition.ContainsAll != nil {
			operands = condition.ContainsAll
			requireAll = true
		}
		matchedOperands := 0
		for _, operand := range operands {
			values := matchingStrings(field, func(value string) bool {
				if field.shape == shapeString {
					return strings.Contains(value, operand)
				}
				return value == operand
			})
			if len(values) > 0 {
				matchedOperands++
				base.affected = append(base.affected, values...)
			}
		}
		base.matched = matchedOperands > 0
		if requireAll {
			base.matched = matchedOperands == len(operands)
		}
		return base
	}
	if condition.Prefix != nil || condition.Suffix != nil || condition.Regex != nil {
		base.affected = matchingStrings(field, func(value string) bool {
			switch {
			case condition.Prefix != nil:
				return strings.HasPrefix(value, *condition.Prefix)
			case condition.Suffix != nil:
				return strings.HasSuffix(value, *condition.Suffix)
			default:
				return e.regexes[*condition.Regex].MatchString(value)
			}
		})
		base.matched = len(base.affected) > 0
		return base
	}

	for _, value := range field.atoms {
		if value.kind != ScalarNumber {
			continue
		}
		matched := condition.GreaterThan != nil && value.number > *condition.GreaterThan ||
			condition.AtLeast != nil && value.number >= *condition.AtLeast ||
			condition.LessThan != nil && value.number < *condition.LessThan ||
			condition.AtMost != nil && value.number <= *condition.AtMost
		if matched {
			base.affected = append(base.affected, value.display())
		}
	}
	base.matched = len(base.affected) > 0
	return base
}

func projectField(field string, index map[string][]evidence.Observation) projection {
	shape := supportedFields[field]
	baseID := field
	derived := ""
	if strings.HasPrefix(field, evidence.ObservationHostKeys+".") {
		baseID = evidence.ObservationHostKeys
		derived = strings.TrimPrefix(field, evidence.ObservationHostKeys+".")
	}
	observations := index[baseID]
	result := projection{shape: shape, exists: len(observations) > 0, atoms: []atom{}, references: []finding.EvidenceReference{}}
	for _, observation := range observations {
		result.references = append(result.references, finding.EvidenceReference{ObservationID: observation.ID, Probe: observation.Probe})
		if derived != "" {
			appendHostKeyAtoms(&result, observation.Value.HostKeys, derived)
			continue
		}
		appendObservationAtoms(&result, observation.Value)
	}
	if derived != "" {
		result.exists = len(result.atoms) > 0
	}
	return result
}

func appendObservationAtoms(result *projection, value evidence.Value) {
	switch value.Kind {
	case evidence.ValueString:
		result.atoms = append(result.atoms, atom{kind: ScalarString, string: *value.String})
	case evidence.ValueBoolean:
		result.atoms = append(result.atoms, atom{kind: ScalarBoolean, boolean: *value.Boolean})
	case evidence.ValueNumber:
		result.atoms = append(result.atoms, atom{kind: ScalarNumber, number: *value.Number})
	case evidence.ValueStrings:
		for _, item := range value.Strings {
			result.atoms = append(result.atoms, atom{kind: ScalarString, string: item})
		}
	}
}

func appendHostKeyAtoms(result *projection, keys []evidence.HostKey, derived string) {
	for _, key := range keys {
		switch derived {
		case "algorithm":
			result.atoms = append(result.atoms, atom{kind: ScalarString, string: key.Algorithm})
		case "fingerprint_sha256":
			result.atoms = append(result.atoms, atom{kind: ScalarString, string: key.FingerprintSHA256})
		case "public_key_type":
			result.atoms = append(result.atoms, atom{kind: ScalarString, string: key.PublicKeyType})
		case "bits":
			if key.Bits > 0 {
				result.atoms = append(result.atoms, atom{kind: ScalarNumber, number: float64(key.Bits)})
			}
		case "rsa_bits":
			if key.PublicKeyType == "ssh-rsa" && key.Bits > 0 {
				result.atoms = append(result.atoms, atom{kind: ScalarNumber, number: float64(key.Bits)})
			}
		case "certificate":
			result.atoms = append(result.atoms, atom{kind: ScalarBoolean, boolean: key.Certificate})
		case "ca_fingerprint_sha256":
			if key.CAFingerprintSHA256 != "" {
				result.atoms = append(result.atoms, atom{kind: ScalarString, string: key.CAFingerprintSHA256})
			}
		case "known_hosts_status":
			result.atoms = append(result.atoms, atom{kind: ScalarString, string: string(key.KnownHostsStatus)})
		}
	}
}

func matchingStrings(field projection, predicate func(string) bool) []string {
	values := make([]string, 0)
	for _, value := range field.atoms {
		if value.kind == ScalarString && predicate(value.string) {
			values = append(values, value.string)
		}
	}
	return values
}

func atomEquals(value atom, scalar Scalar) bool {
	if value.kind != scalar.Kind {
		return false
	}
	switch value.kind {
	case ScalarString:
		return value.string == scalar.String
	case ScalarBoolean:
		return value.boolean == scalar.Boolean
	case ScalarNumber:
		return value.number == scalar.Number
	default:
		return false
	}
}

func atomDisplays(values []atom) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.display())
	}
	return result
}

func ensureAbsenceReference(result matchResult, field string, exists bool) matchResult {
	if !exists && len(result.references) == 0 {
		result.references = append(result.references, finding.EvidenceReference{ObservationID: field, Probe: "not_observed"})
	}
	return result
}

func deduplicateReferences(input []finding.EvidenceReference) []finding.EvidenceReference {
	result := make([]finding.EvidenceReference, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for _, reference := range input {
		key := reference.ObservationID + "\x00" + reference.Probe
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, reference)
	}
	return result
}

func deduplicateStrings(input []string) []string {
	result := make([]string, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for _, value := range input {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func collectRegexes(condition Condition, destination map[string]*regexp.Regexp) {
	if condition.Regex != nil {
		destination[*condition.Regex] = regexp.MustCompile(*condition.Regex)
	}
	for _, child := range condition.All {
		collectRegexes(child, destination)
	}
	for _, child := range condition.Any {
		collectRegexes(child, destination)
	}
	if condition.Not != nil {
		collectRegexes(*condition.Not, destination)
	}
}

func cloneDocument(document Document) Document {
	result := document
	result.Rules = slices.Clone(document.Rules)
	for index := range result.Rules {
		result.Rules[index].References = slices.Clone(document.Rules[index].References)
		result.Rules[index].Match = cloneCondition(document.Rules[index].Match)
	}
	return result
}

func cloneCondition(condition Condition) Condition {
	result := condition
	result.Equals = clonePointer(condition.Equals)
	result.NotEquals = clonePointer(condition.NotEquals)
	result.Contains = clonePointer(condition.Contains)
	result.Prefix = clonePointer(condition.Prefix)
	result.Suffix = clonePointer(condition.Suffix)
	result.Regex = clonePointer(condition.Regex)
	result.Exists = clonePointer(condition.Exists)
	result.NotExists = clonePointer(condition.NotExists)
	result.GreaterThan = clonePointer(condition.GreaterThan)
	result.AtLeast = clonePointer(condition.AtLeast)
	result.LessThan = clonePointer(condition.LessThan)
	result.AtMost = clonePointer(condition.AtMost)
	result.ContainsAny = slices.Clone(condition.ContainsAny)
	result.ContainsAll = slices.Clone(condition.ContainsAll)
	if condition.All != nil {
		result.All = make([]Condition, len(condition.All))
		for index := range condition.All {
			result.All[index] = cloneCondition(condition.All[index])
		}
	}
	if condition.Any != nil {
		result.Any = make([]Condition, len(condition.Any))
		for index := range condition.Any {
			result.Any[index] = cloneCondition(condition.Any[index])
		}
	}
	if condition.Not != nil {
		cloned := cloneCondition(*condition.Not)
		result.Not = &cloned
	}
	return result
}

func clonePointer[T any](input *T) *T {
	if input == nil {
		return nil
	}
	value := *input
	return &value
}
