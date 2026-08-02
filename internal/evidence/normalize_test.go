package evidence

import (
	"reflect"
	"testing"
	"time"
)

func TestStableNormalizerSortsWithoutMutatingLists(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	input := []Observation{
		{ID: "z", Probe: "test", ObservedAt: now, Confidence: ConfidenceHigh, Value: StringsValue([]string{"server-first", "server-second"})},
		{ID: "a", Probe: "test", ObservedAt: now, Confidence: ConfidenceHigh, Value: StringValue("value")},
	}
	got, err := (StableNormalizer{}).Normalize(input)
	if err != nil {
		t.Fatalf("Normalize() = %v", err)
	}
	if got[0].ID != "a" || !reflect.DeepEqual(got[1].Value.Strings, []string{"server-first", "server-second"}) {
		t.Fatalf("Normalize() = %+v", got)
	}
	got[1].Value.Strings[0] = "changed"
	if input[0].Value.Strings[0] != "server-first" {
		t.Fatal("Normalize() did not deep-copy list evidence")
	}
}

func TestStableNormalizerRejectsDuplicates(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	observation := Observation{ID: "same", Probe: "test", ObservedAt: now, Confidence: ConfidenceHigh, Value: StringValue("value")}
	if _, err := (StableNormalizer{}).Normalize([]Observation{observation, observation}); err == nil {
		t.Fatal("Normalize() = nil error for duplicate observation")
	}
}
