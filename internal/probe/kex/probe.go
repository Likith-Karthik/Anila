package kex

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"time"

	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/probe"
	"github.com/sshscope/sshscope/internal/probe/banner"
	"github.com/sshscope/sshscope/internal/target"
)

const (
	name                 = "kex"
	clientIdentification = "SSH-2.0-sshscope\r\n"
)

// Probe exchanges identification and initial KEXINIT packets, then closes the
// connection before negotiation or cryptographic key exchange begins.
type Probe struct {
	operationTimeout time.Duration
	dialer           probe.Dialer
	gate             probe.ConnectionGate
	randomness       io.Reader
	bannerLimits     banner.Limits
}

func New(operationTimeout time.Duration, dialer probe.Dialer, gate probe.ConnectionGate) (*Probe, error) {
	if operationTimeout <= 0 {
		return nil, errors.New("KEX operation timeout must be positive")
	}
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	if gate == nil {
		return nil, errors.New("KEX connection gate is required")
	}
	return &Probe{
		operationTimeout: operationTimeout,
		dialer:           dialer,
		gate:             gate,
		randomness:       rand.Reader,
		bannerLimits:     banner.DefaultLimits(),
	}, nil
}

func (*Probe) Name() string { return name }

func (p *Probe) Run(ctx context.Context, item target.Target) probe.Result {
	started := time.Now()
	release, err := p.gate.Acquire(ctx, item.ResolvedIP.String())
	if err != nil {
		return failedResult(started, gateError(err))
	}
	defer release()

	operationCtx, cancel := context.WithTimeout(ctx, p.operationTimeout)
	defer cancel()
	connection, err := p.dialer.DialContext(operationCtx, "tcp", item.Endpoint())
	if err != nil {
		return failedResult(started, probe.ClassifyNetworkError(name, err))
	}
	defer connection.Close()
	stopConnectionContext, err := probe.BindConnectionToContext(operationCtx, connection)
	if err != nil {
		return failedResult(started, probe.ClassifyNetworkError(name, err))
	}
	defer stopConnectionContext()
	if err := writeAll(connection, []byte(clientIdentification)); err != nil {
		return failedResult(started, classifyKEXError(err))
	}

	buffered := bufio.NewReaderSize(connection, p.bannerLimits.MaxLineBytes+1)
	if _, err := banner.ParseIdentificationBuffered(buffered, p.bannerLimits); err != nil {
		if isNetworkError(err) {
			return failedResult(started, probe.ClassifyNetworkError(name, err))
		}
		return failedResult(started, probe.Error{Kind: probe.ErrorInvalidBanner, Probe: name, Message: "server identification is invalid", Cause: err})
	}

	cookie, err := randomCookie(p.randomness)
	if err != nil {
		return failedResult(started, probe.Error{Kind: probe.ErrorProtocol, Probe: name, Message: "could not generate KEXINIT cookie", Cause: err})
	}
	clientPayload, err := MarshalKEXINIT(clientProposal(), cookie)
	if err != nil {
		return failedResult(started, probe.Error{Kind: probe.ErrorProtocol, Probe: name, Message: "could not construct bounded client KEXINIT", Cause: err})
	}
	clientPacket, err := MarshalPacket(clientPayload, p.randomness)
	if err != nil {
		return failedResult(started, probe.Error{Kind: probe.ErrorProtocol, Probe: name, Message: "could not frame bounded client KEXINIT", Cause: err})
	}
	if err := writeAll(connection, clientPacket); err != nil {
		return failedResult(started, classifyKEXError(err))
	}

	payload, err := readInitialKEXINIT(buffered)
	if err != nil {
		return failedResult(started, classifyKEXError(err))
	}
	proposal, err := ParseKEXINIT(payload)
	if err != nil {
		return failedResult(started, classifyKEXError(err))
	}
	observedAt := time.Now().UTC()
	observations := proposalObservations(proposal, observedAt)
	return probe.Result{
		Observations: observations,
		Errors:       []probe.Error{},
		Duration:     probe.Duration(time.Since(started)),
		Status:       probe.StatusComplete,
	}
}

func clientProposal() evidence.KEXProposal {
	return evidence.KEXProposal{
		KeyExchanges:              []string{"curve25519-sha256", "ext-info-c", "kex-strict-c-v00@openssh.com"},
		ServerHostKeys:            []string{"ssh-ed25519"},
		CiphersClientToServer:     []string{"aes128-ctr"},
		CiphersServerToClient:     []string{"aes128-ctr"},
		MACsClientToServer:        []string{"hmac-sha2-256"},
		MACsServerToClient:        []string{"hmac-sha2-256"},
		CompressionClientToServer: []string{"none"},
		CompressionServerToClient: []string{"none"},
		LanguagesClientToServer:   []string{},
		LanguagesServerToClient:   []string{},
	}
}

func proposalObservations(proposal evidence.KEXProposal, observedAt time.Time) []evidence.Observation {
	stringList := func(id string, values []string) evidence.Observation {
		return evidence.Observation{ID: id, Value: evidence.StringsValue(values), Probe: name, ObservedAt: observedAt, Confidence: evidence.ConfidenceHigh}
	}
	return []evidence.Observation{
		stringList(evidence.ObservationKEXAlgorithms, proposal.KeyExchanges),
		stringList(evidence.ObservationHostKeyAlgorithms, proposal.ServerHostKeys),
		stringList(evidence.ObservationCiphersClientToServer, proposal.CiphersClientToServer),
		stringList(evidence.ObservationCiphersServerToClient, proposal.CiphersServerToClient),
		stringList(evidence.ObservationMACsClientToServer, proposal.MACsClientToServer),
		stringList(evidence.ObservationMACsServerToClient, proposal.MACsServerToClient),
		stringList(evidence.ObservationCompressionClientToServer, proposal.CompressionClientToServer),
		stringList(evidence.ObservationCompressionServerToClient, proposal.CompressionServerToClient),
		stringList(evidence.ObservationLanguagesClientToServer, proposal.LanguagesClientToServer),
		stringList(evidence.ObservationLanguagesServerToClient, proposal.LanguagesServerToClient),
		stringList(evidence.ObservationProtocolExtensions, proposal.Extensions),
		{ID: evidence.ObservationFirstKEXPacketFollows, Value: evidence.BooleanValue(proposal.FirstKEXPacketFollows), Probe: name, ObservedAt: observedAt, Confidence: evidence.ConfidenceHigh},
		{ID: evidence.ObservationKEXReserved, Value: evidence.NumberValue(float64(proposal.Reserved)), Probe: name, ObservedAt: observedAt, Confidence: evidence.ConfidenceHigh},
	}
}

func randomCookie(reader io.Reader) ([16]byte, error) {
	var cookie [16]byte
	if reader == nil {
		return cookie, errors.New("randomness source is required")
	}
	if _, err := io.ReadFull(reader, cookie[:]); err != nil {
		return cookie, err
	}
	return cookie, nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(data) {
			return io.ErrNoProgress
		}
		data = data[written:]
	}
	return nil
}

func classifyKEXError(err error) probe.Error {
	if isNetworkError(err) {
		return probe.ClassifyNetworkError(name, err)
	}
	if errors.Is(err, ErrUnexpectedMessage) {
		return probe.Error{Kind: probe.ErrorUnexpectedMessage, Probe: name, Message: "server sent an unexpected initial SSH message", Cause: err}
	}
	return probe.Error{Kind: probe.ErrorInvalidPacket, Probe: name, Message: "server sent an invalid SSH KEXINIT packet", Cause: err}
}

func isNetworkError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError)
}

func gateError(err error) probe.Error {
	if isNetworkError(err) {
		return probe.ClassifyNetworkError(name, err)
	}
	return probe.Error{Kind: probe.ErrorRateLimited, Probe: name, Message: "connection start was rate limited", Retryable: true, Cause: err}
}

func failedResult(started time.Time, probeErr probe.Error) probe.Result {
	return probe.Result{
		Observations: []evidence.Observation{},
		Errors:       []probe.Error{probeErr},
		Duration:     probe.Duration(time.Since(started)),
		Status:       probe.StatusFailed,
	}
}
