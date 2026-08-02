package probe

import (
	"context"
	"errors"
	"net"
	"syscall"
)

// Dialer is implemented by net.Dialer and deterministic test doubles.
type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// ConnectionGate is the scheduler contract shared by network probes.
type ConnectionGate interface {
	Acquire(context.Context, string) (release func(), err error)
}

// ClassifyNetworkError removes platform-specific details from report messages
// while retaining the wrapped cause for diagnostics.
func ClassifyNetworkError(probeName string, err error) Error {
	classified := Error{Probe: probeName, Message: "network operation failed", Cause: err}
	switch {
	case errors.Is(err, context.Canceled):
		classified.Kind = ErrorCancelled
		classified.Message = "network operation cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		classified.Kind = ErrorConnectionTimeout
		classified.Message = "network operation timed out"
		classified.Retryable = true
	case errors.Is(err, syscall.ECONNREFUSED):
		classified.Kind = ErrorConnectionRefused
		classified.Message = "connection refused"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		classified.Kind = ErrorNetworkUnreachable
		classified.Message = "network unreachable"
		classified.Retryable = true
	default:
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			classified.Kind = ErrorConnectionTimeout
			classified.Message = "network operation timed out"
			classified.Retryable = true
		} else {
			classified.Kind = ErrorNetwork
		}
	}
	return classified
}
