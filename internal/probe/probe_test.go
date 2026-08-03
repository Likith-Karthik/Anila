package probe

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sshscope/sshscope/internal/evidence"
)

func TestDurationJSONRoundTrip(t *testing.T) {
	want := Duration(1250 * time.Millisecond)
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal() = %v", err)
	}
	if string(data) != `"1.25s"` {
		t.Fatalf("Marshal() = %s", data)
	}
	var got Duration
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() = %v", err)
	}
	if got != want {
		t.Fatalf("round trip = %v, want %v", got, want)
	}
}

func TestResultValidate(t *testing.T) {
	result := Result{Status: StatusComplete, Duration: Duration(time.Millisecond)}
	if err := result.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}

	result.Status = "done"
	if err := result.Validate(); err == nil {
		t.Fatal("Validate() = nil, want invalid status")
	}
}

func TestResultValidateRejectsInconsistentStatus(t *testing.T) {
	probeErr := Error{Kind: ErrorProtocol, Probe: "test", Message: "failed"}
	tests := []Result{
		{Status: StatusComplete, Errors: []Error{probeErr}},
		{Status: StatusPartial, Errors: []Error{probeErr}},
		{Status: StatusPartial, Observations: []evidence.Observation{}},
		{Status: StatusFailed},
	}
	for _, result := range tests {
		if err := result.Validate(); err == nil {
			t.Fatalf("Validate(%+v) = nil", result)
		}
	}
}
