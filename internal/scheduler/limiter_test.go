package scheduler

import (
	"context"
	"testing"
	"time"
)

func TestConnectionGatePerHostLimit(t *testing.T) {
	gate, err := NewConnectionGate(1000, 1)
	if err != nil {
		t.Fatalf("NewConnectionGate() = %v", err)
	}
	release, err := gate.Acquire(context.Background(), "192.0.2.1")
	if err != nil {
		t.Fatalf("Acquire() = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := gate.Acquire(ctx, "192.0.2.1"); err == nil {
		t.Fatal("second Acquire() bypassed per-host limit")
	}
	release()
	release() // release is intentionally idempotent
}

func TestConnectionGateRateAndCancellation(t *testing.T) {
	gate, err := NewConnectionGate(20, 2)
	if err != nil {
		t.Fatalf("NewConnectionGate() = %v", err)
	}
	release, err := gate.Acquire(context.Background(), "192.0.2.1")
	if err != nil {
		t.Fatalf("first Acquire() = %v", err)
	}
	release()
	started := time.Now()
	release, err = gate.Acquire(context.Background(), "192.0.2.2")
	if err != nil {
		t.Fatalf("second Acquire() = %v", err)
	}
	release()
	if elapsed := time.Since(started); elapsed < 35*time.Millisecond {
		t.Fatalf("rate wait = %v, want at least 35ms", elapsed)
	}

	slowGate, err := NewConnectionGate(0.1, 1)
	if err != nil {
		t.Fatalf("NewConnectionGate() = %v", err)
	}
	release, err = slowGate.Acquire(context.Background(), "192.0.2.1")
	if err != nil {
		t.Fatalf("first slow Acquire() = %v", err)
	}
	release()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := slowGate.Acquire(ctx, "192.0.2.1"); err == nil {
		t.Fatal("rate-limited Acquire() ignored cancellation")
	}
}
