// Package config defines validated, presentation-independent scan settings.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

type jsonConfig struct {
	Port               uint16           `json:"port"`
	TargetTimeout      string           `json:"target_timeout"`
	ConnectionTimeout  string           `json:"connection_timeout"`
	Concurrency        int              `json:"concurrency"`
	PerHostConnections int              `json:"per_host_connections"`
	RateLimit          float64          `json:"rate_limit"`
	MaximumTargets     int              `json:"maximum_targets"`
	Retries            int              `json:"retries"`
	IPPreference       IPPreference     `json:"ip_preference"`
	AuthProbeEnabled   bool             `json:"auth_probe_enabled"`
	AuditUser          string           `json:"audit_user"`
	KnownHostsPath     string           `json:"known_hosts_path,omitempty"`
	PolicyPath         string           `json:"policy_path,omitempty"`
	OutputFormat       OutputFormat     `json:"output_format"`
	OutputPath         string           `json:"output_path,omitempty"`
	FailureThreshold   FailureThreshold `json:"failure_threshold"`
	Verbose            bool             `json:"verbose"`
}

const (
	DefaultPort               = 22
	DefaultConcurrency        = 10
	DefaultPerHostConnections = 3
	DefaultTargetTimeout      = 10 * time.Second
	DefaultConnectionTimeout  = 4 * time.Second
	DefaultRetries            = 0
	DefaultMaximumTargets     = 256
	DefaultRateLimit          = 5.0
	DefaultAuditUser          = "sshscope-audit"
	MaximumConcurrency        = 64
	MaximumPerHostConnections = 16
	AbsoluteMaximumTargets    = 4096
	MaximumRateLimit          = 1000.0
	MaximumTargetTimeout      = 5 * time.Minute
	MaximumConnectionTimeout  = time.Minute
	MaximumAuditUserBytes     = 255
)

// OutputFormat selects a report renderer.
type OutputFormat string

const (
	OutputTerminal OutputFormat = "terminal"
	OutputJSON     OutputFormat = "json"
)

// IPPreference controls address-family resolution.
type IPPreference string

const (
	IPAny IPPreference = "any"
	IPv4  IPPreference = "ipv4"
	IPv6  IPPreference = "ipv6"
)

// FailureThreshold controls finding-related process failure. The initial CLI
// intentionally excludes low and informational findings from failure choices.
type FailureThreshold string

const (
	FailOnCritical FailureThreshold = "critical"
	FailOnHigh     FailureThreshold = "high"
	FailOnMedium   FailureThreshold = "medium"
	FailOnNever    FailureThreshold = "never"
)

// Authorization records operator-provided audit authorization metadata. These
// values document intent and never relax safety controls.
type Authorization struct {
	ScopeReference    string `json:"scope_reference"`
	OperatorConfirmed bool   `json:"operator_confirmed"`
}

// Config contains safety limits and scan behavior. It intentionally contains
// no credentials or private-key material.
type Config struct {
	Port               uint16           `json:"port"`
	TargetTimeout      time.Duration    `json:"target_timeout"`
	ConnectionTimeout  time.Duration    `json:"connection_timeout"`
	Concurrency        int              `json:"concurrency"`
	PerHostConnections int              `json:"per_host_connections"`
	RateLimit          float64          `json:"rate_limit"`
	MaximumTargets     int              `json:"maximum_targets"`
	Retries            int              `json:"retries"`
	IPPreference       IPPreference     `json:"ip_preference"`
	AuthProbeEnabled   bool             `json:"auth_probe_enabled"`
	AuditUser          string           `json:"audit_user"`
	KnownHostsPath     string           `json:"known_hosts_path,omitempty"`
	PolicyPath         string           `json:"policy_path,omitempty"`
	OutputFormat       OutputFormat     `json:"output_format"`
	OutputPath         string           `json:"output_path,omitempty"`
	FailureThreshold   FailureThreshold `json:"failure_threshold"`
	Verbose            bool             `json:"verbose"`
}

// Default returns conservative scan settings.
func Default() Config {
	return Config{
		Port:               DefaultPort,
		TargetTimeout:      DefaultTargetTimeout,
		ConnectionTimeout:  DefaultConnectionTimeout,
		Concurrency:        DefaultConcurrency,
		PerHostConnections: DefaultPerHostConnections,
		RateLimit:          DefaultRateLimit,
		MaximumTargets:     DefaultMaximumTargets,
		Retries:            DefaultRetries,
		IPPreference:       IPAny,
		AuthProbeEnabled:   true,
		AuditUser:          DefaultAuditUser,
		OutputFormat:       OutputTerminal,
		FailureThreshold:   FailOnHigh,
	}
}

// Validate rejects unsafe or internally inconsistent settings.
func (c Config) Validate() error {
	var errs []error
	if c.Port == 0 {
		errs = append(errs, errors.New("port must be between 1 and 65535"))
	}
	if c.TargetTimeout <= 0 {
		errs = append(errs, errors.New("target timeout must be positive"))
	} else if c.TargetTimeout > MaximumTargetTimeout {
		errs = append(errs, fmt.Errorf("target timeout must not exceed %s", MaximumTargetTimeout))
	}
	if c.ConnectionTimeout <= 0 {
		errs = append(errs, errors.New("connection timeout must be positive"))
	} else if c.ConnectionTimeout > MaximumConnectionTimeout {
		errs = append(errs, fmt.Errorf("connection timeout must not exceed %s", MaximumConnectionTimeout))
	}
	if c.ConnectionTimeout > c.TargetTimeout {
		errs = append(errs, errors.New("connection timeout must not exceed target timeout"))
	}
	if c.Concurrency < 1 {
		errs = append(errs, errors.New("concurrency must be at least 1"))
	} else if c.Concurrency > MaximumConcurrency {
		errs = append(errs, fmt.Errorf("concurrency must not exceed %d", MaximumConcurrency))
	}
	if c.PerHostConnections < 1 || c.PerHostConnections > c.Concurrency {
		errs = append(errs, errors.New("per-host connections must be between 1 and concurrency"))
	} else if c.PerHostConnections > MaximumPerHostConnections {
		errs = append(errs, fmt.Errorf("per-host connections must not exceed %d", MaximumPerHostConnections))
	}
	if c.RateLimit <= 0 || math.IsNaN(c.RateLimit) || math.IsInf(c.RateLimit, 0) {
		errs = append(errs, errors.New("rate limit must be a positive finite number"))
	} else if c.RateLimit > MaximumRateLimit {
		errs = append(errs, fmt.Errorf("rate limit must not exceed %.0f", MaximumRateLimit))
	}
	if c.MaximumTargets < 1 {
		errs = append(errs, errors.New("maximum targets must be at least 1"))
	} else if c.MaximumTargets > AbsoluteMaximumTargets {
		errs = append(errs, fmt.Errorf("maximum targets must not exceed hard limit %d", AbsoluteMaximumTargets))
	}
	if c.Retries != 0 {
		errs = append(errs, errors.New("retries are not supported; use 0"))
	}
	if c.IPPreference != IPAny && c.IPPreference != IPv4 && c.IPPreference != IPv6 {
		errs = append(errs, fmt.Errorf("unsupported IP preference %q", c.IPPreference))
	}
	if c.AuthProbeEnabled && c.AuditUser == "" {
		errs = append(errs, errors.New("audit user is required when the authentication probe is enabled"))
	}
	if len(c.AuditUser) > MaximumAuditUserBytes || strings.ContainsAny(c.AuditUser, "\x00\r\n") {
		errs = append(errs, errors.New("audit user is oversized or contains a prohibited control character"))
	}
	if c.OutputFormat != OutputTerminal && c.OutputFormat != OutputJSON {
		errs = append(errs, fmt.Errorf("unsupported output format %q", c.OutputFormat))
	}
	if c.FailureThreshold != FailOnCritical && c.FailureThreshold != FailOnHigh &&
		c.FailureThreshold != FailOnMedium && c.FailureThreshold != FailOnNever {
		errs = append(errs, fmt.Errorf("unsupported failure threshold %q", c.FailureThreshold))
	}
	return errors.Join(errs...)
}

// MarshalJSON renders durations as readable, portable strings.
func (c Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonConfig{
		Port:               c.Port,
		TargetTimeout:      c.TargetTimeout.String(),
		ConnectionTimeout:  c.ConnectionTimeout.String(),
		Concurrency:        c.Concurrency,
		PerHostConnections: c.PerHostConnections,
		RateLimit:          c.RateLimit,
		MaximumTargets:     c.MaximumTargets,
		Retries:            c.Retries,
		IPPreference:       c.IPPreference,
		AuthProbeEnabled:   c.AuthProbeEnabled,
		AuditUser:          c.AuditUser,
		KnownHostsPath:     c.KnownHostsPath,
		PolicyPath:         c.PolicyPath,
		OutputFormat:       c.OutputFormat,
		OutputPath:         c.OutputPath,
		FailureThreshold:   c.FailureThreshold,
		Verbose:            c.Verbose,
	})
}

// UnmarshalJSON parses the canonical report representation of configuration.
func (c *Config) UnmarshalJSON(data []byte) error {
	var encoded jsonConfig
	if err := json.Unmarshal(data, &encoded); err != nil {
		return fmt.Errorf("decode scan configuration: %w", err)
	}
	targetTimeout, err := time.ParseDuration(encoded.TargetTimeout)
	if err != nil {
		return fmt.Errorf("parse target timeout: %w", err)
	}
	connectionTimeout, err := time.ParseDuration(encoded.ConnectionTimeout)
	if err != nil {
		return fmt.Errorf("parse connection timeout: %w", err)
	}
	*c = Config{
		Port:               encoded.Port,
		TargetTimeout:      targetTimeout,
		ConnectionTimeout:  connectionTimeout,
		Concurrency:        encoded.Concurrency,
		PerHostConnections: encoded.PerHostConnections,
		RateLimit:          encoded.RateLimit,
		MaximumTargets:     encoded.MaximumTargets,
		Retries:            encoded.Retries,
		IPPreference:       encoded.IPPreference,
		AuthProbeEnabled:   encoded.AuthProbeEnabled,
		AuditUser:          encoded.AuditUser,
		KnownHostsPath:     encoded.KnownHostsPath,
		PolicyPath:         encoded.PolicyPath,
		OutputFormat:       encoded.OutputFormat,
		OutputPath:         encoded.OutputPath,
		FailureThreshold:   encoded.FailureThreshold,
		Verbose:            encoded.Verbose,
	}
	return nil
}
