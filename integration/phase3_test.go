package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sshscope/sshscope/internal/cli"
	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/probe"
	"github.com/sshscope/sshscope/internal/probe/kex"
	"github.com/sshscope/sshscope/internal/report"
)

func TestPhase3LoopbackScan(t *testing.T) {
	serverProposal := evidence.KEXProposal{
		KeyExchanges:              []string{"curve25519-sha256", "diffie-hellman-group14-sha256", "ext-info-s", "kex-strict-s-v00@openssh.com"},
		ServerHostKeys:            []string{"ssh-ed25519", "rsa-sha2-512"},
		CiphersClientToServer:     []string{"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com"},
		CiphersServerToClient:     []string{"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com"},
		MACsClientToServer:        []string{"hmac-sha2-256-etm@openssh.com"},
		MACsServerToClient:        []string{"hmac-sha2-256-etm@openssh.com"},
		CompressionClientToServer: []string{"none"},
		CompressionServerToClient: []string{"none"},
		LanguagesClientToServer:   []string{},
		LanguagesServerToClient:   []string{},
	}
	serverPayload, err := kex.MarshalKEXINIT(serverProposal, [16]byte{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("MarshalKEXINIT() = %v", err)
	}
	serverPacket, err := kex.MarshalPacket(serverPayload, bytes.NewReader(make([]byte, 32)))
	if err != nil {
		t.Fatalf("MarshalPacket() = %v", err)
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() = %v", err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		first, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		_ = first.Close()
		second, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		_, err = io.WriteString(second, "test fixture notice\r\nSSH-2.0-OpenSSH_fixture phase2\r\n")
		_ = second.Close()
		if err != nil {
			serverDone <- err
			return
		}
		third, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer third.Close()
		buffered := bufio.NewReader(third)
		if _, err := buffered.ReadString('\n'); err != nil {
			serverDone <- err
			return
		}
		if _, err := io.WriteString(third, "SSH-2.0-OpenSSH_fixture phase3\r\n"); err != nil {
			serverDone <- err
			return
		}
		if _, err := kex.ReadPacket(buffered, kex.DefaultMaxPacketLength); err != nil {
			serverDone <- err
			return
		}
		_, err = third.Write(serverPacket)
		serverDone <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := cli.NewRootCommand("phase3-test")
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs([]string{
		"scan", listener.Addr().String(),
		"--format", "json",
		"--rate", "1000",
		"--timeout", "2s",
		"--connect-timeout", "1s",
		"--no-auth-probe",
	})
	if err := command.ExecuteContext(ctx); err != nil {
		t.Fatalf("scan = %v, stderr=%q, stdout=%q", err, stderr.String(), stdout.String())
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("fixture server = %v", err)
	}
	var scanReport report.Report
	if err := json.Unmarshal(stdout.Bytes(), &scanReport); err != nil {
		t.Fatalf("Unmarshal() = %v; output=%q", err, stdout.String())
	}
	if err := scanReport.Validate(); err != nil {
		t.Fatalf("report Validate() = %v", err)
	}
	if scanReport.Status != probe.StatusComplete || len(scanReport.Targets) != 1 {
		t.Fatalf("report status = %s; targets=%d", scanReport.Status, len(scanReport.Targets))
	}
	observedBanner := false
	observedKEX := false
	for _, observation := range scanReport.Targets[0].Observations {
		if observation.ID == evidence.ObservationBannerRaw && observation.Value.String != nil &&
			*observation.Value.String == "SSH-2.0-OpenSSH_fixture phase2" {
			observedBanner = true
		}
		if observation.ID == evidence.ObservationKEXAlgorithms && len(observation.Value.Strings) == 4 &&
			observation.Value.Strings[0] == "curve25519-sha256" && observation.Value.Strings[3] == "kex-strict-s-v00@openssh.com" {
			observedKEX = true
		}
	}
	if !observedBanner {
		t.Fatalf("banner not found in observations: %+v", scanReport.Targets[0].Observations)
	}
	if !observedKEX {
		t.Fatalf("ordered KEX proposal not found in observations: %+v", scanReport.Targets[0].Observations)
	}
}
