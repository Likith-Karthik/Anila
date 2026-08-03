package probe

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestClassifyNetworkError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorKind
	}{
		{"cancelled", context.Canceled, ErrorCancelled},
		{"timeout", context.DeadlineExceeded, ErrorConnectionTimeout},
		{"refused", syscall.ECONNREFUSED, ErrorConnectionRefused},
		{"network unreachable", syscall.ENETUNREACH, ErrorNetworkUnreachable},
		{"other", syscall.EIO, ErrorNetwork},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyNetworkError("test", tt.err); got.Kind != tt.want {
				t.Fatalf("ClassifyNetworkError() = %+v, want %s", got, tt.want)
			}
		})
	}
}

func TestBindConnectionToContextInterruptsBlockedIO(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	stop, err := BindConnectionToContext(ctx, client)
	if err != nil {
		t.Fatalf("BindConnectionToContext() = %v", err)
	}
	defer stop()
	readDone := make(chan error, 1)
	go func() {
		var buffer [1]byte
		_, readErr := client.Read(buffer[:])
		readDone <- readErr
	}()
	cancel()
	select {
	case readErr := <-readDone:
		if readErr == nil {
			t.Fatal("blocked read completed without an error")
		}
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not interrupt blocked connection I/O")
	}
	stop()
	stop()
}

func TestBindConnectionToContextValidatesInputs(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name       string
		ctx        context.Context
		connection net.Conn
		want       error
	}{
		{name: "nil context", connection: client},
		{name: "nil connection", ctx: context.Background()},
		{name: "cancelled", ctx: cancelled, connection: client, want: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BindConnectionToContext(tt.ctx, tt.connection)
			if err == nil || tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("BindConnectionToContext() error = %v", err)
			}
		})
	}
}
