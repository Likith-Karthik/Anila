// Package web exposes sshscope through a conservative local HTTP interface.
package web

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sshscope/sshscope/internal/app"
	"github.com/sshscope/sshscope/internal/config"
	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/policy"
	"github.com/sshscope/sshscope/internal/probe"
	"github.com/sshscope/sshscope/internal/probe/auth"
	"github.com/sshscope/sshscope/internal/probe/banner"
	"github.com/sshscope/sshscope/internal/probe/hostkey"
	"github.com/sshscope/sshscope/internal/probe/kex"
	"github.com/sshscope/sshscope/internal/probe/tcp"
	"github.com/sshscope/sshscope/internal/report"
	"github.com/sshscope/sshscope/internal/scheduler"
	"github.com/sshscope/sshscope/internal/target"
)

const (
	MaximumScanRequestBytes = 1 << 20
	maximumInlineTargets    = 4096
	maximumScopeReference   = 4096
)

type Defaults struct {
	Config config.Config `json:"config"`
}

type ScanInput struct {
	Targets           string  `json:"targets"`
	Port              uint16  `json:"port"`
	IPPreference      string  `json:"ip_preference"`
	TargetTimeout     string  `json:"target_timeout"`
	ConnectionTimeout string  `json:"connection_timeout"`
	Concurrency       int     `json:"concurrency"`
	PerHost           int     `json:"per_host_connections"`
	RateLimit         float64 `json:"rate_limit"`
	MaximumTargets    int     `json:"maximum_targets"`
	AuditUser         string  `json:"audit_user"`
	AuthProbeEnabled  bool    `json:"auth_probe_enabled"`
	KnownHostsPath    string  `json:"known_hosts_path"`
	PolicyPath        string  `json:"policy_path"`
	FailureThreshold  string  `json:"failure_threshold"`
	ScopeReference    string  `json:"scope_reference"`
	OperatorConfirmed bool    `json:"operator_confirmed"`
}

type ScanOutput struct {
	Report report.Report `json:"report"`
}

type Service struct {
	version string
	mu      sync.Mutex
	cancel  context.CancelFunc
	running bool
}

func NewService(version string) *Service {
	if version == "" {
		version = "dev"
	}
	return &Service{version: version}
}

func (s *Service) Defaults() Defaults {
	return Defaults{Config: config.Default()}
}

func (s *Service) Cancel() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel == nil {
		return false
	}
	s.cancel()
	return true
}

func (s *Service) Scan(ctx context.Context, input ScanInput) (ScanOutput, error) {
	if !input.OperatorConfirmed {
		return ScanOutput{}, errors.New("operator authorization confirmation is required")
	}
	if len(input.ScopeReference) > maximumScopeReference {
		return ScanOutput{}, fmt.Errorf("scope reference exceeds %d bytes", maximumScopeReference)
	}
	targets := targetLines(input.Targets)
	if len(targets) == 0 {
		return ScanOutput{}, errors.New("provide at least one target")
	}
	if len(targets) > maximumInlineTargets {
		return ScanOutput{}, fmt.Errorf("target input exceeds %d entries", maximumInlineTargets)
	}
	cfg, err := configFromInput(input)
	if err != nil {
		return ScanOutput{}, err
	}
	scanCtx, cancel := context.WithCancel(ctx)
	if !s.begin(cancel) {
		cancel()
		return ScanOutput{}, errors.New("a scan is already running")
	}
	defer s.finish()
	defer cancel()

	resolved, err := resolveTargets(scanCtx, targets, cfg)
	if err != nil {
		return ScanOutput{}, err
	}
	scanner, err := s.newScanner(cfg)
	if err != nil {
		return ScanOutput{}, err
	}
	output, err := scanner.Scan(scanCtx, app.ScanRequest{
		Targets:           resolved.Targets,
		PreparationErrors: resolved.Errors,
		Configuration:     cfg,
		Authorization: config.Authorization{
			ScopeReference:    input.ScopeReference,
			OperatorConfirmed: input.OperatorConfirmed,
		},
	})
	if err != nil {
		return ScanOutput{}, err
	}
	var buffer bytes.Buffer
	if err := (report.JSONRenderer{}).Render(scanCtx, &buffer, output); err != nil {
		return ScanOutput{}, fmt.Errorf("canonicalize report: %w", err)
	}
	decoded, err := (report.JSONDecoder{}).Decode(scanCtx, bytes.NewReader(buffer.Bytes()))
	if err != nil {
		return ScanOutput{}, fmt.Errorf("validate canonical report: %w", err)
	}
	return ScanOutput{Report: decoded}, nil
}

func (s *Service) begin(cancel context.CancelFunc) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return false
	}
	s.running = true
	s.cancel = cancel
	return true
}

func (s *Service) finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
	s.cancel = nil
}

func configFromInput(input ScanInput) (config.Config, error) {
	cfg := config.Default()
	if input.Port != 0 {
		cfg.Port = input.Port
	}
	if input.TargetTimeout != "" {
		duration, err := time.ParseDuration(input.TargetTimeout)
		if err != nil {
			return config.Config{}, fmt.Errorf("parse target timeout: %w", err)
		}
		cfg.TargetTimeout = duration
	}
	if input.ConnectionTimeout != "" {
		duration, err := time.ParseDuration(input.ConnectionTimeout)
		if err != nil {
			return config.Config{}, fmt.Errorf("parse connection timeout: %w", err)
		}
		cfg.ConnectionTimeout = duration
	}
	if input.Concurrency != 0 {
		cfg.Concurrency = input.Concurrency
	}
	if input.PerHost != 0 {
		cfg.PerHostConnections = input.PerHost
	}
	if input.RateLimit != 0 {
		cfg.RateLimit = input.RateLimit
	}
	if input.MaximumTargets != 0 {
		cfg.MaximumTargets = input.MaximumTargets
	}
	if input.IPPreference != "" {
		cfg.IPPreference = config.IPPreference(input.IPPreference)
	}
	if input.AuditUser != "" {
		cfg.AuditUser = input.AuditUser
	}
	cfg.AuthProbeEnabled = input.AuthProbeEnabled
	cfg.KnownHostsPath = input.KnownHostsPath
	cfg.PolicyPath = input.PolicyPath
	cfg.OutputFormat = config.OutputJSON
	if input.FailureThreshold != "" {
		cfg.FailureThreshold = config.FailureThreshold(input.FailureThreshold)
	}
	if err := cfg.Validate(); err != nil {
		return config.Config{}, fmt.Errorf("invalid scan configuration: %w", err)
	}
	return cfg, nil
}

func resolveTargets(ctx context.Context, inputs []string, cfg config.Config) (target.Resolution, error) {
	specs, err := (target.InputParser{}).Parse(ctx, inputs, cfg.Port)
	if err != nil {
		return target.Resolution{}, err
	}
	scoped, err := (target.Scope{}).Validate(ctx, specs, cfg.MaximumTargets)
	if err != nil {
		return target.Resolution{}, err
	}
	return target.NewDNSResolver(nil).Resolve(ctx, scoped, target.ResolveOptions{
		IPPreference:   cfg.IPPreference,
		MaximumTargets: cfg.MaximumTargets,
	})
}

func (s *Service) newScanner(cfg config.Config) (*app.ScanService, error) {
	policyDocument, err := loadPolicy(context.Background(), cfg.PolicyPath)
	if err != nil {
		return nil, err
	}
	engine, err := policy.NewEngine(policyDocument)
	if err != nil {
		return nil, fmt.Errorf("initialize policy: %w", err)
	}
	var checker hostkey.Checker
	if cfg.KnownHostsPath != "" {
		checker, err = hostkey.NewKnownHostsChecker(cfg.KnownHostsPath)
		if err != nil {
			return nil, err
		}
	}
	gate, err := scheduler.NewConnectionGate(cfg.RateLimit, cfg.PerHostConnections)
	if err != nil {
		return nil, err
	}
	tcpProbe, err := tcp.New(cfg.ConnectionTimeout, &net.Dialer{}, gate)
	if err != nil {
		return nil, err
	}
	bannerProbe, err := banner.New(cfg.ConnectionTimeout, &net.Dialer{}, gate, banner.DefaultLimits())
	if err != nil {
		return nil, err
	}
	kexProbe, err := kex.New(cfg.ConnectionTimeout, &net.Dialer{}, gate)
	if err != nil {
		return nil, err
	}
	hostKeyProbe, err := hostkey.New(cfg.ConnectionTimeout, &net.Dialer{}, gate, checker)
	if err != nil {
		return nil, err
	}
	pipeline := []probe.Probe{tcpProbe, bannerProbe, kexProbe, hostKeyProbe}
	if cfg.AuthProbeEnabled {
		authProbe, err := auth.New(cfg.ConnectionTimeout, &net.Dialer{}, gate, cfg.AuditUser)
		if err != nil {
			return nil, err
		}
		pipeline = append(pipeline, authProbe)
	}
	return app.NewScanner(s.version, pipeline, evidence.StableNormalizer{}, engine)
}

func loadPolicy(ctx context.Context, path string) (policy.Document, error) {
	if path == "" {
		return policy.LoadDefault(ctx)
	}
	return policy.Document{}, errors.New("custom policy files are available in the CLI; web policy upload is not enabled")
}

func targetLines(input string) []string {
	lines := strings.Split(input, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		result = append(result, line)
	}
	return result
}
