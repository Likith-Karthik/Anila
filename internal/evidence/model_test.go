package evidence

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestValueValidate(t *testing.T) {
	tests := []struct {
		name    string
		value   Value
		wantErr string
	}{
		{"boolean", BooleanValue(false), ""},
		{"empty strings", StringsValue(nil), ""},
		{"missing member", Value{Kind: ValueString}, "exactly one"},
		{"multiple members", Value{Kind: ValueString, String: stringPointer("x"), Number: numberPointer(1)}, "exactly one"},
		{"kind mismatch", Value{Kind: ValueNumber, String: stringPointer("x")}, "does not match"},
		{"unknown kind", Value{Kind: "object", String: stringPointer("x")}, "unsupported"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.value.Validate()
			if tt.wantErr == "" && err != nil {
				t.Fatalf("Validate() = %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("Validate() = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestValueJSONRoundTripPreservesEmptyList(t *testing.T) {
	want := StringsValue(nil)
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal() = %v", err)
	}
	if !strings.Contains(string(data), `"strings":[]`) {
		t.Fatalf("Marshal() = %s", data)
	}
	var got Value
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() = %v", err)
	}
	if err := got.Validate(); err != nil || got.Strings == nil || len(got.Strings) != 0 {
		t.Fatalf("round trip = %+v, error = %v", got, err)
	}
}

func TestObservationValidate(t *testing.T) {
	observation := Observation{
		ID:         ObservationTCPReachable,
		Value:      BooleanValue(true),
		Probe:      "tcp",
		ObservedAt: time.Unix(1, 0).UTC(),
		Confidence: ConfidenceHigh,
	}
	if err := observation.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}

	observation.Confidence = "certain"
	if err := observation.Validate(); err == nil {
		t.Fatal("Validate() = nil, want invalid confidence")
	}
}

func TestHostKeyValidate(t *testing.T) {
	key := HostKey{
		Algorithm:         "ssh-ed25519",
		FingerprintSHA256: "SHA256:test",
		PublicKeyType:     "ssh-ed25519",
		KnownHostsStatus:  KnownHostsNotChecked,
	}
	if err := key.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	key.KnownHostsStatus = "trusted"
	if err := key.Validate(); err == nil {
		t.Fatal("Validate() = nil, want unsupported trust status")
	}
}

func stringPointer(value string) *string   { return &value }
func numberPointer(value float64) *float64 { return &value }
