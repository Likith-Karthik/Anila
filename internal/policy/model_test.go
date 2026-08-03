package policy

import (
	"math"
	"strings"
	"testing"

	"github.com/sshscope/sshscope/internal/finding"
)

func TestScalarValidate(t *testing.T) {
	for _, scalar := range []Scalar{StringScalar("ssh-rsa"), BooleanScalar(false), NumberScalar(1024)} {
		if err := scalar.Validate(); err != nil {
			t.Fatalf("Validate(%+v) = %v", scalar, err)
		}
	}
	if err := NumberScalar(math.Inf(1)).Validate(); err == nil {
		t.Fatal("Validate(infinity) = nil")
	}
	if err := StringScalar(strings.Repeat("a", maximumPolicyString+1)).Validate(); err == nil {
		t.Fatal("Validate(oversized string) = nil")
	}
}

func TestDocumentValidateHeader(t *testing.T) {
	document := Document{
		Version: 1,
		Rules: []Rule{{
			ID:         "SSH-TEST-001",
			Severity:   finding.SeverityHigh,
			Confidence: finding.ConfidenceHigh,
		}},
	}
	if err := document.ValidateHeader(); err != nil {
		t.Fatalf("ValidateHeader() = %v", err)
	}
	document.Rules = append(document.Rules, document.Rules[0])
	if err := document.ValidateHeader(); err == nil {
		t.Fatal("ValidateHeader() = nil, want duplicate ID")
	}
}
