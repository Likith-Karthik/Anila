package banner

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/probe"
	"github.com/sshscope/sshscope/internal/target"
)

type allowGate struct{}

func (allowGate) Acquire(context.Context, string) (func(), error) { return func() {}, nil }

type pipeDialer struct{ payload string }

func (d pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		_, _ = server.Write([]byte(d.payload))
		_ = server.Close()
	}()
	return client, nil
}

type idlePipeDialer struct{}

func (idlePipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		var buffer [1]byte
		_, _ = server.Read(buffer[:])
		_ = server.Close()
	}()
	return client, nil
}

func TestProbeCollectsIdentification(t *testing.T) {
	item := target.Target{Original: "192.0.2.1", Hostname: "192.0.2.1", ResolvedIP: netip.MustParseAddr("192.0.2.1"), Port: 22, IPVersion: target.Version4}
	scanner, err := New(time.Second, pipeDialer{payload: "notice\r\nSSH-2.0-test_1 comment\r\n"}, allowGate{}, DefaultLimits())
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	result := scanner.Run(context.Background(), item)
	if result.Status != probe.StatusComplete || len(result.Errors) != 0 {
		t.Fatalf("Run() = %+v", result)
	}
	values := make(map[string]evidence.Value)
	for _, observation := range result.Observations {
		values[observation.ID] = observation.Value
	}
	if values[evidence.ObservationProtocolVersion].String == nil || *values[evidence.ObservationProtocolVersion].String != "2.0" {
		t.Fatalf("protocol observation = %+v", values[evidence.ObservationProtocolVersion])
	}
	if len(values[evidence.ObservationBannerPreLines].Strings) != 1 {
		t.Fatalf("pre-banner observation = %+v", values[evidence.ObservationBannerPreLines])
	}
}

func TestProbeRejectsOversizedIdentification(t *testing.T) {
	item := target.Target{Original: "192.0.2.1", Hostname: "192.0.2.1", ResolvedIP: netip.MustParseAddr("192.0.2.1"), Port: 22, IPVersion: target.Version4}
	scanner, err := New(time.Second, pipeDialer{payload: "SSH-2.0-" + string(make([]byte, 300)) + "\r\n"}, allowGate{}, DefaultLimits())
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	result := scanner.Run(context.Background(), item)
	if len(result.Errors) != 1 || result.Errors[0].Kind != probe.ErrorInvalidBanner {
		t.Fatalf("Run() = %+v", result)
	}
}

func TestProbeEnforcesReadDeadline(t *testing.T) {
	item := target.Target{Original: "192.0.2.1", Hostname: "192.0.2.1", ResolvedIP: netip.MustParseAddr("192.0.2.1"), Port: 22, IPVersion: target.Version4}
	scanner, err := New(10*time.Millisecond, idlePipeDialer{}, allowGate{}, DefaultLimits())
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	result := scanner.Run(context.Background(), item)
	if len(result.Errors) != 1 || result.Errors[0].Kind != probe.ErrorConnectionTimeout {
		t.Fatalf("Run() = %+v", result)
	}
}
