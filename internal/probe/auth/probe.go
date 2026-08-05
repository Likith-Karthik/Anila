// Package auth observes the initial SSH authentication method surface without
// submitting credentials.
package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/probe"
	"github.com/sshscope/sshscope/internal/target"
)

const (
	name                  = "auth"
	maximumAllowedMethods = 64
)

var errAuthObserved = errors.New("authentication methods observed")

type Probe struct {
	timeout   time.Duration
	dialer    probe.Dialer
	gate      probe.ConnectionGate
	auditUser string
}

func New(timeout time.Duration, dialer probe.Dialer, gate probe.ConnectionGate, auditUser string) (*Probe, error) {
	if timeout <= 0 {
		return nil, errors.New("auth timeout must be positive")
	}
	if dialer == nil {
		return nil, errors.New("auth dialer is required")
	}
	if gate == nil {
		return nil, errors.New("auth connection gate is required")
	}
	if auditUser == "" {
		return nil, errors.New("auth audit user is required")
	}
	return &Probe{timeout: timeout, dialer: dialer, gate: gate, auditUser: auditUser}, nil
}

func (p *Probe) Name() string { return name }

func (p *Probe) Run(ctx context.Context, item target.Target) probe.Result {
	return p.RunWithEvidence(ctx, item, nil)
}

func (p *Probe) RunWithEvidence(ctx context.Context, item target.Target, prior []evidence.Observation) probe.Result {
	started := time.Now()
	fingerprint := firstHostKeyFingerprint(prior)
	if fingerprint == "" {
		err := probe.Error{Kind: probe.ErrorUnsupported, Probe: name, Message: "host-key evidence is required before authentication observation"}
		return probe.Result{Errors: []probe.Error{err}, Duration: probe.Duration(time.Since(started)), Status: probe.StatusFailed}
	}
	methods, noneAccepted, err := p.observe(ctx, item, fingerprint)
	observations := []evidence.Observation{}
	if err == nil || errors.Is(err, errAuthObserved) {
		observations = append(observations,
			evidence.Observation{
				ID:         evidence.ObservationAuthMethods,
				Value:      evidence.StringsValue(methods),
				Probe:      name,
				ObservedAt: time.Now().UTC(),
				Confidence: evidence.ConfidenceHigh,
			},
			evidence.Observation{
				ID:         evidence.ObservationAuthNoneAccepted,
				Value:      evidence.BooleanValue(noneAccepted),
				Probe:      name,
				ObservedAt: time.Now().UTC(),
				Confidence: evidence.ConfidenceHigh,
			},
		)
		return probe.Result{Observations: observations, Duration: probe.Duration(time.Since(started)), Status: probe.StatusComplete}
	}
	probeErr := probe.ClassifyNetworkError(name, err)
	if len(methods) > 0 {
		observations = append(observations, evidence.Observation{
			ID:         evidence.ObservationAuthMethods,
			Value:      evidence.StringsValue(methods),
			Probe:      name,
			ObservedAt: time.Now().UTC(),
			Confidence: evidence.ConfidenceMedium,
		})
		return probe.Result{
			Observations: observations,
			Errors:       []probe.Error{probeErr},
			Duration:     probe.Duration(time.Since(started)),
			Status:       probe.StatusPartial,
		}
	}
	return probe.Result{Errors: []probe.Error{probeErr}, Duration: probe.Duration(time.Since(started)), Status: probe.StatusFailed}
}

func (p *Probe) observe(ctx context.Context, item target.Target, fingerprint string) ([]string, bool, error) {
	release, err := p.gate.Acquire(ctx, item.ResolvedIP.String())
	if err != nil {
		return nil, false, err
	}
	defer release()
	operationCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	connection, err := p.dialer.DialContext(operationCtx, "tcp", item.Endpoint())
	if err != nil {
		return nil, false, err
	}
	stop, err := probe.BindConnectionToContext(operationCtx, connection)
	if err != nil {
		_ = connection.Close()
		return nil, false, err
	}
	defer stop()
	var methods []string
	config := &ssh.ClientConfig{
		User:    p.auditUser,
		Auth:    []ssh.AuthMethod{},
		Timeout: p.timeout,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != fingerprint {
				return fmt.Errorf("host key fingerprint changed before auth probe")
			}
			return nil
		},
		AuthCallback: func(authCtx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
			if authCtx == nil {
				return nil, errAuthObserved
			}
			methods = boundedUnique(authCtx.AllowedMethods)
			return nil, errAuthObserved
		},
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(connection, item.Endpoint(), config)
	if err == nil {
		go ssh.DiscardRequests(reqs)
		for newChannel := range chans {
			_ = newChannel.Reject(ssh.Prohibited, "sshscope does not open channels")
		}
		_ = clientConn.Close()
		return []string{}, true, nil
	}
	if errors.Is(err, errAuthObserved) {
		return methods, false, errAuthObserved
	}
	return methods, false, err
}

func firstHostKeyFingerprint(observations []evidence.Observation) string {
	for _, observation := range observations {
		if observation.ID != evidence.ObservationHostKeys || len(observation.Value.HostKeys) == 0 {
			continue
		}
		return observation.Value.HostKeys[0].FingerprintSHA256
	}
	return ""
}

func boundedUnique(input []string) []string {
	if len(input) > maximumAllowedMethods {
		input = input[:maximumAllowedMethods]
	}
	output := make([]string, 0, len(input))
	for _, item := range input {
		if slices.Contains(output, item) {
			continue
		}
		output = append(output, item)
	}
	return output
}
