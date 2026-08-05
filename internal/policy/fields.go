package policy

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/sshscope/sshscope/internal/evidence"
)

const (
	maximumPolicyString     = 16 * 1024
	maximumPolicyRules      = 512
	maximumPolicyReferences = 64
	maximumConditionDepth   = 16
	maximumConditionFanout  = 64
	maximumRegexBytes       = 512
)

type fieldShape string

const (
	shapeBoolean fieldShape = "boolean"
	shapeString  fieldShape = "string"
	shapeNumber  fieldShape = "number"
	shapeStrings fieldShape = "strings"
)

var supportedFields = map[string]fieldShape{
	evidence.ObservationTCPReachable:                        shapeBoolean,
	evidence.ObservationTCPLatency:                          shapeNumber,
	evidence.ObservationBannerRaw:                           shapeString,
	evidence.ObservationBannerPreLines:                      shapeStrings,
	evidence.ObservationProtocolVersion:                     shapeString,
	evidence.ObservationSoftwareVersion:                     shapeString,
	evidence.ObservationSoftwareComment:                     shapeString,
	evidence.ObservationKEXAlgorithms:                       shapeStrings,
	evidence.ObservationHostKeyAlgorithms:                   shapeStrings,
	evidence.ObservationCiphersClientToServer:               shapeStrings,
	evidence.ObservationCiphersServerToClient:               shapeStrings,
	evidence.ObservationMACsClientToServer:                  shapeStrings,
	evidence.ObservationMACsServerToClient:                  shapeStrings,
	evidence.ObservationCompressionClientToServer:           shapeStrings,
	evidence.ObservationCompressionServerToClient:           shapeStrings,
	evidence.ObservationLanguagesClientToServer:             shapeStrings,
	evidence.ObservationLanguagesServerToClient:             shapeStrings,
	evidence.ObservationFirstKEXPacketFollows:               shapeBoolean,
	evidence.ObservationKEXReserved:                         shapeNumber,
	evidence.ObservationProtocolExtensions:                  shapeStrings,
	evidence.ObservationAuthMethods:                         shapeStrings,
	evidence.ObservationAuthNoneAccepted:                    shapeBoolean,
	evidence.ObservationHostKeys + ".algorithm":             shapeStrings,
	evidence.ObservationHostKeys + ".fingerprint_sha256":    shapeStrings,
	evidence.ObservationHostKeys + ".public_key_type":       shapeStrings,
	evidence.ObservationHostKeys + ".bits":                  shapeNumber,
	evidence.ObservationHostKeys + ".rsa_bits":              shapeNumber,
	evidence.ObservationHostKeys + ".certificate":           shapeBoolean,
	evidence.ObservationHostKeys + ".ca_fingerprint_sha256": shapeStrings,
	evidence.ObservationHostKeys + ".known_hosts_status":    shapeStrings,
}

// Validate performs complete policy schema and matcher validation.
func (d Document) Validate() error {
	if err := d.ValidateHeader(); err != nil {
		return err
	}
	if len(d.Rules) > maximumPolicyRules {
		return fmt.Errorf("policy exceeds %d rules", maximumPolicyRules)
	}
	for index, rule := range d.Rules {
		if err := validateRule(rule); err != nil {
			return fmt.Errorf("rule %d (%q): %w", index, rule.ID, err)
		}
	}
	return nil
}

func validateRule(rule Rule) error {
	var errs []error
	for label, value := range map[string]string{
		"id": rule.ID, "title": rule.Title, "description": rule.Description, "recommendation": rule.Recommendation,
	} {
		if value == "" {
			errs = append(errs, fmt.Errorf("%s is required", label))
		}
		if len(value) > maximumPolicyString || strings.ContainsRune(value, '\x00') {
			errs = append(errs, fmt.Errorf("%s is oversized or contains NUL", label))
		}
	}
	if strings.ContainsAny(rule.ID, " \t\r\n") {
		errs = append(errs, errors.New("id must not contain whitespace"))
	}
	if len(rule.References) > maximumPolicyReferences {
		errs = append(errs, fmt.Errorf("references exceed %d entries", maximumPolicyReferences))
	}
	for i, reference := range rule.References {
		if reference == "" || len(reference) > maximumPolicyString || strings.ContainsRune(reference, '\x00') {
			errs = append(errs, fmt.Errorf("reference %d is empty, oversized, or contains NUL", i))
		}
	}
	if err := validateCondition(rule.Match, 0); err != nil {
		errs = append(errs, fmt.Errorf("match: %w", err))
	}
	return errors.Join(errs...)
}

func validateCondition(condition Condition, depth int) error {
	if depth > maximumConditionDepth {
		return fmt.Errorf("condition exceeds maximum depth %d", maximumConditionDepth)
	}
	operators := 0
	if condition.All != nil {
		operators++
		if len(condition.All) == 0 || len(condition.All) > maximumConditionFanout {
			return fmt.Errorf("all must contain 1-%d conditions", maximumConditionFanout)
		}
		for i, child := range condition.All {
			if err := validateCondition(child, depth+1); err != nil {
				return fmt.Errorf("all[%d]: %w", i, err)
			}
		}
	}
	if condition.Any != nil {
		operators++
		if len(condition.Any) == 0 || len(condition.Any) > maximumConditionFanout {
			return fmt.Errorf("any must contain 1-%d conditions", maximumConditionFanout)
		}
		for i, child := range condition.Any {
			if err := validateCondition(child, depth+1); err != nil {
				return fmt.Errorf("any[%d]: %w", i, err)
			}
		}
	}
	if condition.Not != nil {
		operators++
		if err := validateCondition(*condition.Not, depth+1); err != nil {
			return fmt.Errorf("not: %w", err)
		}
	}
	leafOperators := countLeafOperators(condition)
	operators += leafOperators
	if operators != 1 {
		return fmt.Errorf("condition must contain exactly one operator, got %d", operators)
	}
	if leafOperators == 0 {
		if condition.Field != "" {
			return errors.New("field is only valid on leaf conditions")
		}
		return nil
	}
	shape, exists := supportedFields[condition.Field]
	if !exists {
		return fmt.Errorf("unsupported field %q", condition.Field)
	}
	return validateLeafOperator(condition, shape)
}

func countLeafOperators(condition Condition) int {
	count := 0
	for _, present := range []bool{
		condition.Equals != nil, condition.NotEquals != nil, condition.Contains != nil,
		condition.ContainsAny != nil, condition.ContainsAll != nil, condition.Prefix != nil,
		condition.Suffix != nil, condition.Regex != nil, condition.Exists != nil,
		condition.NotExists != nil, condition.GreaterThan != nil, condition.AtLeast != nil,
		condition.LessThan != nil, condition.AtMost != nil,
	} {
		if present {
			count++
		}
	}
	return count
}

func validateLeafOperator(condition Condition, shape fieldShape) error {
	if condition.Equals != nil {
		return validateScalarForShape(*condition.Equals, shape)
	}
	if condition.NotEquals != nil {
		return validateScalarForShape(*condition.NotEquals, shape)
	}
	if condition.Contains != nil {
		return validateStringOperator(*condition.Contains, shape)
	}
	if condition.ContainsAny != nil {
		return validateStringListOperator(condition.ContainsAny, shape, "contains_any")
	}
	if condition.ContainsAll != nil {
		return validateStringListOperator(condition.ContainsAll, shape, "contains_all")
	}
	if condition.Prefix != nil {
		return validateStringOperator(*condition.Prefix, shape)
	}
	if condition.Suffix != nil {
		return validateStringOperator(*condition.Suffix, shape)
	}
	if condition.Regex != nil {
		if err := validateStringOperator(*condition.Regex, shape); err != nil {
			return err
		}
		if len(*condition.Regex) > maximumRegexBytes {
			return fmt.Errorf("regex exceeds %d bytes", maximumRegexBytes)
		}
		if _, err := regexp.Compile(*condition.Regex); err != nil {
			return fmt.Errorf("compile regex: %w", err)
		}
	}
	if condition.Exists != nil || condition.NotExists != nil {
		return nil
	}
	if condition.GreaterThan != nil || condition.AtLeast != nil || condition.LessThan != nil || condition.AtMost != nil {
		if shape != shapeNumber {
			return fmt.Errorf("numeric comparison is not valid for %s field", shape)
		}
		for _, value := range []*float64{condition.GreaterThan, condition.AtLeast, condition.LessThan, condition.AtMost} {
			if value != nil {
				if err := NumberScalar(*value).Validate(); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateScalarForShape(scalar Scalar, shape fieldShape) error {
	if err := scalar.Validate(); err != nil {
		return err
	}
	switch scalar.Kind {
	case ScalarString:
		if shape != shapeString && shape != shapeStrings {
			return fmt.Errorf("string scalar is not valid for %s field", shape)
		}
	case ScalarBoolean:
		if shape != shapeBoolean {
			return fmt.Errorf("boolean scalar is not valid for %s field", shape)
		}
	case ScalarNumber:
		if shape != shapeNumber {
			return fmt.Errorf("number scalar is not valid for %s field", shape)
		}
	}
	return nil
}

func validateStringOperator(value string, shape fieldShape) error {
	if shape != shapeString && shape != shapeStrings {
		return fmt.Errorf("string operator is not valid for %s field", shape)
	}
	if value == "" || len(value) > maximumPolicyString || strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("string operator is empty, exceeds %d bytes, or contains NUL", maximumPolicyString)
	}
	return nil
}

func validateStringListOperator(values []string, shape fieldShape, label string) error {
	if shape != shapeString && shape != shapeStrings {
		return fmt.Errorf("%s is not valid for %s field", label, shape)
	}
	if len(values) == 0 || len(values) > maximumConditionFanout {
		return fmt.Errorf("%s must contain 1-%d strings", label, maximumConditionFanout)
	}
	for index, value := range values {
		if value == "" || len(value) > maximumPolicyString || strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("%s[%d] is empty, oversized, or contains NUL", label, index)
		}
	}
	return nil
}
