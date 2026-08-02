// Package scheduler provides bounded, context-aware scan scheduling.
package scheduler

import (
	"context"
	"errors"
	"sync"
)

type indexedJob[T any] struct {
	index int
	value T
}

// Run applies work with at most concurrency active calls. Results retain input
// order regardless of completion order. Work must honor the supplied context.
func Run[T, R any](ctx context.Context, concurrency int, items []T, work func(context.Context, T) R) ([]R, error) {
	if concurrency < 1 {
		return nil, errors.New("worker concurrency must be at least 1")
	}
	if work == nil {
		return nil, errors.New("worker function is required")
	}
	results := make([]R, len(items))
	jobs := make(chan indexedJob[T])
	workerCount := min(concurrency, len(items))
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for job := range jobs {
				results[job.index] = work(ctx, job.value)
			}
		}()
	}

	dispatchErr := error(nil)
dispatch:
	for index, item := range items {
		select {
		case jobs <- indexedJob[T]{index: index, value: item}:
		case <-ctx.Done():
			dispatchErr = ctx.Err()
			break dispatch
		}
	}
	close(jobs)
	workers.Wait()
	if dispatchErr != nil {
		return results, dispatchErr
	}
	if err := ctx.Err(); err != nil {
		return results, err
	}
	return results, nil
}
