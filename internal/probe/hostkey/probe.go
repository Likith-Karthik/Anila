// Package hostkey collects signature-verified SSH host keys without
// proceeding to user authentication.
package hostkey

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/probe"
	"github.com/sshscope/sshscope/internal/target"
)

const (
	name                      = "hostkey"
	maximumHostKeyAlgorithms  = 8
	maximumKnownHostsFileSize = 16 * 1024 * 1024
)

var errHostKeyCollected = errors.New("host key collected")

// Checker compares a collected host key with operator-supplied trust material.
type Checker interface {
	Check(hostname string, remote net.Addr, key ssh.PublicKey) evidence.KnownHostsStatus
}

type knownHostsChecker struct {
	callback ssh.HostKeyCallback
}

// NewKnownHostsChecker loads an OpenSSH known_hosts file.
func NewKnownHostsChecker(path string) (Checker, error) {
	if path == "" {
		return nil, errors.New("known_hosts path is required")
	}
	callback, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}
	return knownHostsChecker{callback: callback}, nil
}

func (c knownHostsChecker) Check(hostname string, remote net.Addr, key ssh.PublicKey) evidence.KnownHostsStatus {
	err := c.callback(hostname, remote, key)
	if err == nil {
		return evidence.KnownHostsMatch
	}
	var revoked *knownhosts.RevokedError
	if errors.As(err, &revoked) {
		return evidence.KnownHostsRevoked
	}
	var keyError *knownhosts.KeyError
	if errors.As(err, &keyError) {
		if len(keyError.Want) == 0 {
			return evidence.KnownHostsNew
		}
		return evidence.KnownHostsMismatch
	}
	return evidence.KnownHostsMismatch
}

// Probe performs bounded host-key collection.
type Probe struct {
	timeout time.Duration
	dialer  probe.Dialer
	gate    probe.ConnectionGate
	checker Checker
}

func New(timeout time.Duration, dialer probe.Dialer, gate probe.ConnectionGate, checker Checker) (*Probe, error) {
	if timeout <= 0 {
		return nil, errors.New("host-key timeout must be positive")
	}
	if dialer == nil {
		return nil, errors.New("host-key dialer is required")
	}
	if gate == nil {
		return nil, errors.New("host-key connection gate is required")
	}
	return &Probe{timeout: timeout, dialer: dialer, gate: gate, checker: checker}, nil
}

func (p *Probe) Name() string { return name }

func (p *Probe) Run(ctx context.Context, item target.Target) probe.Result {
	return p.RunWithEvidence(ctx, item, nil)
}

func (p *Probe) RunWithEvidence(ctx context.Context, item target.Target, prior []evidence.Observation) probe.Result {
	started := time.Now()
	algorithms := advertisedHostKeyAlgorithms(prior)
	if len(algorithms) == 0 {
		algorithms = []string{"ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"}
	}
	if len(algorithms) > maximumHostKeyAlgorithms {
		algorithms = algorithms[:maximumHostKeyAlgorithms]
	}
	collected := make([]evidence.HostKey, 0, len(algorithms))
	errs := make([]probe.Error, 0)
	seen := make(map[string]struct{}, len(algorithms))
	for _, algorithm := range algorithms {
		if err := ctx.Err(); err != nil {
			errs = append(errs, probe.ClassifyNetworkError(name, err))
			break
		}
		key, remote, err := p.collectOne(ctx, item, algorithm)
		if err != nil {
			errs = append(errs, probe.ClassifyNetworkError(name, err))
			continue
		}
		fingerprint := ssh.FingerprintSHA256(key)
		if _, exists := seen[fingerprint]; exists {
			continue
		}
		seen[fingerprint] = struct{}{}
		collected = append(collected, describeKey(key, p.knownHostsStatus(item, remote, key)))
	}
	observations := []evidence.Observation{}
	status := probe.StatusFailed
	if len(collected) > 0 {
		observations = append(observations, evidence.Observation{
			ID:         evidence.ObservationHostKeys,
			Value:      evidence.HostKeysValue(collected),
			Probe:      name,
			ObservedAt: time.Now().UTC(),
			Confidence: evidence.ConfidenceHigh,
		})
		status = probe.StatusComplete
		if len(errs) > 0 {
			status = probe.StatusPartial
		}
	}
	return probe.Result{Observations: observations, Errors: errs, Duration: probe.Duration(time.Since(started)), Status: status}
}

func (p *Probe) collectOne(ctx context.Context, item target.Target, algorithm string) (ssh.PublicKey, net.Addr, error) {
	release, err := p.gate.Acquire(ctx, item.ResolvedIP.String())
	if err != nil {
		return nil, nil, err
	}
	defer release()
	operationCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	connection, err := p.dialer.DialContext(operationCtx, "tcp", item.Endpoint())
	if err != nil {
		return nil, nil, err
	}
	stop, err := probe.BindConnectionToContext(operationCtx, connection)
	if err != nil {
		_ = connection.Close()
		return nil, nil, err
	}
	defer stop()
	var collected ssh.PublicKey
	var remote net.Addr
	var once sync.Once
	config := &ssh.ClientConfig{
		User:              "sshscope-hostkey",
		Auth:              []ssh.AuthMethod{},
		HostKeyAlgorithms: []string{algorithm},
		Timeout:           p.timeout,
		HostKeyCallback: func(_ string, address net.Addr, key ssh.PublicKey) error {
			once.Do(func() {
				collected = key
				remote = address
			})
			return errHostKeyCollected
		},
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(connection, item.Endpoint(), config)
	if err == nil {
		clientConn.Close()
		go ssh.DiscardRequests(reqs)
		for newChannel := range chans {
			_ = newChannel.Reject(ssh.Prohibited, "sshscope does not open channels")
		}
	}
	if !errors.Is(err, errHostKeyCollected) || collected == nil {
		return nil, nil, err
	}
	return collected, remote, nil
}

func (p *Probe) knownHostsStatus(item target.Target, remote net.Addr, key ssh.PublicKey) evidence.KnownHostsStatus {
	if p.checker == nil {
		return evidence.KnownHostsNotChecked
	}
	host := item.Hostname
	if host == "" {
		host = item.ResolvedIP.String()
	}
	return p.checker.Check(net.JoinHostPort(host, strconv.Itoa(int(item.Port))), remote, key)
}

func advertisedHostKeyAlgorithms(observations []evidence.Observation) []string {
	for _, observation := range observations {
		if observation.ID == evidence.ObservationHostKeyAlgorithms && observation.Value.Strings != nil {
			result := make([]string, 0, len(observation.Value.Strings))
			seen := make(map[string]struct{}, len(observation.Value.Strings))
			for _, algorithm := range observation.Value.Strings {
				if _, exists := seen[algorithm]; exists {
					continue
				}
				seen[algorithm] = struct{}{}
				result = append(result, algorithm)
			}
			return result
		}
	}
	return nil
}

func describeKey(key ssh.PublicKey, status evidence.KnownHostsStatus) evidence.HostKey {
	certificate, ok := key.(*ssh.Certificate)
	if ok {
		return evidence.HostKey{
			Algorithm:           key.Type(),
			FingerprintSHA256:   ssh.FingerprintSHA256(key),
			PublicKeyType:       certificate.Key.Type(),
			Bits:                keyBits(certificate.Key),
			Certificate:         true,
			CAFingerprintSHA256: ssh.FingerprintSHA256(certificate.SignatureKey),
			KnownHostsStatus:    status,
		}
	}
	return evidence.HostKey{
		Algorithm:         key.Type(),
		FingerprintSHA256: ssh.FingerprintSHA256(key),
		PublicKeyType:     key.Type(),
		Bits:              keyBits(key),
		KnownHostsStatus:  status,
	}
}

func keyBits(key ssh.PublicKey) int {
	switch key.Type() {
	case "ssh-ed25519", "sk-ssh-ed25519@openssh.com":
		return 256
	case "ecdsa-sha2-nistp256", "sk-ecdsa-sha2-nistp256@openssh.com":
		return 256
	case "ecdsa-sha2-nistp384":
		return 384
	case "ecdsa-sha2-nistp521":
		return 521
	default:
		return 0
	}
}
