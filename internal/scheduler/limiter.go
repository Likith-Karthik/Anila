package scheduler

import (
	"context"
	"errors"
	"math"
	"sync"

	"golang.org/x/time/rate"
)

// ConnectionGate enforces a global start rate and active connection limit per
// resolved host. Callers must invoke the returned release function exactly once.
type ConnectionGate struct {
	limiter *rate.Limiter
	perHost int

	mu    sync.Mutex
	hosts map[string]chan struct{}
}

// NewConnectionGate creates a gate with a burst of one. A burst of one avoids
// startup spikes while still allowing the first connection immediately.
func NewConnectionGate(perSecond float64, perHost int) (*ConnectionGate, error) {
	if perSecond <= 0 || math.IsNaN(perSecond) || math.IsInf(perSecond, 0) {
		return nil, errors.New("connection rate must be a positive finite number")
	}
	if perHost < 1 {
		return nil, errors.New("per-host connection limit must be at least 1")
	}
	return &ConnectionGate{
		limiter: rate.NewLimiter(rate.Limit(perSecond), 1),
		perHost: perHost,
		hosts:   make(map[string]chan struct{}),
	}, nil
}

// Acquire waits for a per-host slot and a global rate token. Cancellation
// releases any partially acquired resource.
func (g *ConnectionGate) Acquire(ctx context.Context, host string) (func(), error) {
	if host == "" {
		return nil, errors.New("connection host key is required")
	}
	semaphore := g.hostSemaphore(host)
	select {
	case semaphore <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := g.limiter.Wait(ctx); err != nil {
		<-semaphore
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() { <-semaphore })
	}, nil
}

func (g *ConnectionGate) hostSemaphore(host string) chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	semaphore := g.hosts[host]
	if semaphore == nil {
		semaphore = make(chan struct{}, g.perHost)
		g.hosts[host] = semaphore
	}
	return semaphore
}
