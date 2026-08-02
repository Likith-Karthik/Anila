package finding

import "testing"

func TestFindingValidate(t *testing.T) {
	finding := Finding{
		RuleID:         "SSH-TEST-001",
		Title:          "Test finding",
		Severity:       SeverityMedium,
		Confidence:     ConfidenceHigh,
		Description:    "A test observation matched.",
		Evidence:       []EvidenceReference{{ObservationID: "ssh.test", Probe: "test"}},
		Recommendation: "Review the test configuration.",
	}
	if err := finding.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}

	finding.Severity = "urgent"
	if err := finding.Validate(); err == nil {
		t.Fatal("Validate() = nil, want invalid severity")
	}
}
