package scheduler

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunBoundsConcurrencyAndPreservesOrder(t *testing.T) {
	items := []int{5, 4, 3, 2, 1}
	var active atomic.Int32
	var maximum atomic.Int32
	results, err := Run(context.Background(), 2, items, func(_ context.Context, item int) int {
		current := active.Add(1)
		for {
			old := maximum.Load()
			if current <= old || maximum.CompareAndSwap(old, current) {
				break
			}
		}
		time.Sleep(time.Duration(item) * time.Millisecond)
		active.Add(-1)
		return item * 2
	})
	if err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if maximum.Load() > 2 {
		t.Fatalf("maximum concurrency = %d", maximum.Load())
	}
	for index, want := range []int{10, 8, 6, 4, 2} {
		if results[index] != want {
			t.Fatalf("result %d = %d, want %d", index, results[index], want)
		}
	}
}

func TestRunCancellationDoesNotLeakWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := Run(ctx, 2, []int{1, 2, 3}, func(ctx context.Context, _ int) int {
			select {
			case started <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return 0
		})
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run() = nil error after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not release workers")
	}
}
