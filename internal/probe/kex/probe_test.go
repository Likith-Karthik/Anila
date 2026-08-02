package kex

import (
	"bufio"
	"bytes"
	"context"
	"io"
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

type kexPipeDialer struct {
	payload []byte
	invalid bool
}

func (d kexPipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buffered := bufio.NewReader(server)
		_, _ = buffered.ReadString('\n')
		_, _ = io.WriteString(server, "SSH-2.0-fixture\r\n")
		_, _ = ReadPacket(buffered, DefaultMaxPacketLength)
		if d.invalid {
			_, _ = server.Write([]byte{0, 0, 0, 1, 0})
			return
		}
		packet, err := MarshalPacket(d.payload, bytes.NewReader(make([]byte, 256)))
		if err == nil {
			_, _ = server.Write(packet)
		}
	}()
	return client, nil
}

func TestProbeCollectsCompleteProposal(t *testing.T) {
	payload, err := MarshalKEXINIT(fixtureProposal(), [16]byte{})
	if err != nil {
		t.Fatalf("MarshalKEXINIT() = %v", err)
	}
	scanner, err := New(time.Second, kexPipeDialer{payload: payload}, allowGate{})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	scanner.randomness = bytes.NewReader(make([]byte, 512))
	result := scanner.Run(context.Background(), kexTarget())
	if result.Status != probe.StatusComplete || len(result.Errors) != 0 || len(result.Observations) != 13 {
		t.Fatalf("Run() = %+v", result)
	}
	var algorithms []string
	for _, observation := range result.Observations {
		if observation.ID == evidence.ObservationKEXAlgorithms {
			algorithms = observation.Value.Strings
		}
	}
	want := fixtureProposal().KeyExchanges
	if len(algorithms) != len(want) || algorithms[0] != want[0] || algorithms[1] != want[1] {
		t.Fatalf("KEX algorithms = %v, want %v", algorithms, want)
	}
}

func TestProbeClassifiesInvalidFrame(t *testing.T) {
	scanner, err := New(time.Second, kexPipeDialer{invalid: true}, allowGate{})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	scanner.randomness = bytes.NewReader(make([]byte, 512))
	result := scanner.Run(context.Background(), kexTarget())
	if len(result.Errors) != 1 || result.Errors[0].Kind != probe.ErrorInvalidPacket {
		t.Fatalf("Run() = %+v", result)
	}
}

func kexTarget() target.Target {
	return target.Target{Original: "192.0.2.1", Hostname: "192.0.2.1", ResolvedIP: netip.MustParseAddr("192.0.2.1"), Port: 22, IPVersion: target.Version4}
}
