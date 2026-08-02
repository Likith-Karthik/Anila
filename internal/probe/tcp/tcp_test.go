package tcp

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/sshscope/sshscope/internal/probe"
	"github.com/sshscope/sshscope/internal/target"
)

type allowGate struct{}

func (allowGate) Acquire(context.Context, string) (func(), error) { return func() {}, nil }

type errorDialer struct{ err error }

func (d errorDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, d.err
}

type blockingDialer struct{}

func (blockingDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestProbeReachable(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() = %v", err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			_ = connection.Close()
		}
		close(accepted)
	}()
	addressPort := listener.Addr().(*net.TCPAddr).AddrPort()
	item := target.Target{
		Original:   addressPort.Addr().String(),
		Hostname:   addressPort.Addr().String(),
		ResolvedIP: addressPort.Addr(),
		Port:       addressPort.Port(),
		IPVersion:  target.Version4,
	}
	scanner, err := New(time.Second, &net.Dialer{}, allowGate{})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	result := scanner.Run(context.Background(), item)
	<-accepted
	if result.Status != probe.StatusComplete || len(result.Observations) != 2 || len(result.Errors) != 0 {
		t.Fatalf("Run() = %+v", result)
	}
	if reachable := result.Observations[0].Value.Boolean; reachable == nil || !*reachable {
		t.Fatalf("reachable observation = %+v", result.Observations[0])
	}
}

func TestProbeClassifiesRefusal(t *testing.T) {
	item := target.Target{
		Original:   "192.0.2.1",
		Hostname:   "192.0.2.1",
		ResolvedIP: netip.MustParseAddr("192.0.2.1"),
		Port:       22,
		IPVersion:  target.Version4,
	}
	scanner, err := New(time.Second, errorDialer{err: syscall.ECONNREFUSED}, allowGate{})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	result := scanner.Run(context.Background(), item)
	if result.Status != probe.StatusFailed || len(result.Errors) != 1 || result.Errors[0].Kind != probe.ErrorConnectionRefused {
		t.Fatalf("Run() = %+v", result)
	}
}

func TestProbeEnforcesConnectionTimeout(t *testing.T) {
	item := target.Target{
		Original:   "192.0.2.1",
		Hostname:   "192.0.2.1",
		ResolvedIP: netip.MustParseAddr("192.0.2.1"),
		Port:       22,
		IPVersion:  target.Version4,
	}
	scanner, err := New(10*time.Millisecond, blockingDialer{}, allowGate{})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	result := scanner.Run(context.Background(), item)
	if len(result.Errors) != 1 || result.Errors[0].Kind != probe.ErrorConnectionTimeout {
		t.Fatalf("Run() = %+v", result)
	}
}
