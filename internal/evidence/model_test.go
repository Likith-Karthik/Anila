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

func TestValueJSONRejectsUnknownNestedFields(t *testing.T) {
	tests := []string{
		`{"kind":"host_keys","host_keys":[{"algorithm":"ssh-ed25519","fingerprint_sha256":"SHA256:test","public_key_type":"ssh-ed25519","certificate":false,"known_hosts_status":"not_checked","unexpected":true}]}`,
		`{"kind":"kex_proposal","kex_proposal":{"key_exchanges":[],"server_host_keys":[],"ciphers_client_to_server":[],"ciphers_server_to_client":[],"macs_client_to_server":[],"macs_server_to_client":[],"compression_client_to_server":[],"compression_server_to_client":[],"languages_client_to_server":[],"languages_server_to_client":[],"extensions":[],"first_kex_packet_follows":false,"reserved":0,"unexpected":true}}`,
	}
	for _, input := range tests {
		var value Value
		if err := json.Unmarshal([]byte(input), &value); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("Unmarshal(%s) error = %v", input, err)
		}
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

func TestObservationValidateEnforcesKnownShapeAndBounds(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	tests := []struct {
		name  string
		value Observation
		want  string
	}{
		{
			name:  "known kind mismatch",
			value: Observation{ID: ObservationTCPReachable, Value: StringValue("true"), Probe: "tcp", ObservedAt: now, Confidence: ConfidenceHigh},
			want:  "requires value kind",
		},
		{
			name:  "oversized algorithm list",
			value: Observation{ID: ObservationKEXAlgorithms, Value: StringsValue([]string{strings.Repeat("a", maximumSSHNameListBytes+1)}), Probe: "kex", ObservedAt: now, Confidence: ConfidenceHigh},
			want:  "exceeds",
		},
		{
			name:  "invalid authentication method",
			value: Observation{ID: ObservationAuthMethods, Value: StringsValue([]string{"bad method"}), Probe: "auth", ObservedAt: now, Confidence: ConfidenceHigh},
			want:  "invalid byte",
		},
		{
			name:  "invalid latency unit",
			value: Observation{ID: ObservationTCPLatency, Value: MeasurementValue(1, "seconds"), Probe: "tcp", ObservedAt: now, Confidence: ConfidenceHigh},
			want:  "millisecond",
		},
		{
			name:  "wrong known probe provenance",
			value: Observation{ID: ObservationTCPReachable, Value: BooleanValue(true), Probe: "banner", ObservedAt: now, Confidence: ConfidenceHigh},
			want:  "must originate",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.value.Validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want %q", err, tt.want)
			}
		})
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
