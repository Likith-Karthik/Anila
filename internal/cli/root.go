// Package cli contains Cobra command construction and exit-code conventions.
package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sshscope/sshscope/internal/app"
	"github.com/sshscope/sshscope/internal/config"
	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/probe"
	"github.com/sshscope/sshscope/internal/probe/banner"
	"github.com/sshscope/sshscope/internal/probe/kex"
	"github.com/sshscope/sshscope/internal/probe/tcp"
	"github.com/sshscope/sshscope/internal/report"
	"github.com/sshscope/sshscope/internal/scheduler"
	"github.com/sshscope/sshscope/internal/target"
)

const (
	ExitSuccess      = 0
	ExitFindings     = 1
	ExitInvalidInput = 2
	ExitScanFailed   = 3
	ExitInterrupted  = 130
)

var errPhasePending = WithExitCode(
	ExitScanFailed,
	errors.New("command is not available until its implementation phase is complete"),
)

const (
	maximumTargetFileBytes = 1 << 20
	maximumTargetLineBytes = 4096
)

// ExitError carries a process exit code across Cobra without coupling domain
// packages to command-line behavior.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

// WithExitCode annotates an error with a documented process exit code.
func WithExitCode(code int, err error) error {
	if err == nil {
		return nil
	}
	return &ExitError{Code: code, Err: err}
}

// ExitCode maps command results to the documented process status contract.
func ExitCode(err error) int {
	if err == nil {
		return ExitSuccess
	}
	if errors.Is(err, context.Canceled) {
		return ExitInterrupted
	}
	var coded *ExitError
	if errors.As(err, &coded) {
		return coded.Code
	}
	return ExitInvalidInput
}

// NewRootCommand constructs an isolated command tree suitable for tests.
func NewRootCommand(version string) *cobra.Command {
	root := &cobra.Command{
		Use:           "sshscope",
		Short:         "Low-impact black-box SSH security auditing",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.AddCommand(newScanCommand(version), newReportCommand(), newCompareCommand(), newPolicyCommand(), newVersionCommand(version))
	return root
}

func newScanCommand(version string) *cobra.Command {
	cfg := config.Default()
	var authorization config.Authorization
	var targetsFile string
	var ipv4, ipv6, noAuth bool
	var failOn string
	cmd := &cobra.Command{
		Use:   "scan [TARGET]",
		Short: "Audit one target, a bounded CIDR, or a target file",
		Args:  cobra.MaximumNArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && targetsFile == "" {
				return errors.New("provide TARGET or --targets FILE")
			}
			if len(args) > 0 && targetsFile != "" {
				return errors.New("TARGET and --targets are mutually exclusive")
			}
			if ipv4 && ipv6 {
				return errors.New("--ipv4 and --ipv6 are mutually exclusive")
			}
			if ipv4 {
				cfg.IPPreference = config.IPv4
			} else if ipv6 {
				cfg.IPPreference = config.IPv6
			}
			cfg.AuthProbeEnabled = !noAuth
			switch config.FailureThreshold(failOn) {
			case config.FailOnCritical, config.FailOnHigh, config.FailOnMedium, config.FailOnNever:
				cfg.FailureThreshold = config.FailureThreshold(failOn)
			default:
				return fmt.Errorf("unsupported --fail-on value %q", failOn)
			}
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("invalid scan configuration: %w", err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			inputs := args
			if targetsFile != "" {
				file, err := os.Open(targetsFile)
				if err != nil {
					return fmt.Errorf("open targets file: %w", err)
				}
				inputs, err = readTargetLines(file, cfg.MaximumTargets)
				closeErr := file.Close()
				if err != nil {
					return err
				}
				if closeErr != nil {
					return fmt.Errorf("close targets file: %w", closeErr)
				}
			}

			parser := target.InputParser{}
			specs, err := parser.Parse(cmd.Context(), inputs, cfg.Port)
			if err != nil {
				return err
			}
			scoped, err := (target.Scope{}).Validate(cmd.Context(), specs, cfg.MaximumTargets)
			if err != nil {
				return err
			}
			resolution, err := target.NewDNSResolver(nil).Resolve(cmd.Context(), scoped, target.ResolveOptions{
				IPPreference:   cfg.IPPreference,
				MaximumTargets: cfg.MaximumTargets,
			})
			if err != nil {
				return err
			}
			if target.AnyPublic(resolution.Targets) {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Notice: public IP targets detected; the operator is responsible for having authorization.")
			}

			gate, err := scheduler.NewConnectionGate(cfg.RateLimit, cfg.PerHostConnections)
			if err != nil {
				return err
			}
			tcpProbe, err := tcp.New(cfg.ConnectionTimeout, &net.Dialer{}, gate)
			if err != nil {
				return err
			}
			bannerProbe, err := banner.New(cfg.ConnectionTimeout, &net.Dialer{}, gate, banner.DefaultLimits())
			if err != nil {
				return err
			}
			kexProbe, err := kex.New(cfg.ConnectionTimeout, &net.Dialer{}, gate)
			if err != nil {
				return err
			}
			scanner, err := app.NewScanner(version, []probe.Probe{tcpProbe, bannerProbe, kexProbe}, evidence.StableNormalizer{})
			if err != nil {
				return err
			}
			scanReport, err := scanner.Scan(cmd.Context(), app.ScanRequest{
				Targets:           resolution.Targets,
				PreparationErrors: resolution.Errors,
				Configuration:     cfg,
				Authorization:     authorization,
			})
			if err != nil {
				return err
			}
			var renderer report.Renderer = report.TerminalRenderer{}
			if cfg.OutputFormat == config.OutputJSON {
				renderer = report.JSONRenderer{}
			}
			if err := renderOutput(cmd.Context(), cmd.OutOrStdout(), cfg.OutputPath, renderer, scanReport); err != nil {
				return WithExitCode(ExitScanFailed, fmt.Errorf("write report: %w", err))
			}
			if scanReport.Status == probe.StatusFailed {
				return WithExitCode(ExitScanFailed, errors.New("scan could not be meaningfully completed"))
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&targetsFile, "targets", "", "read targets from file")
	f.Uint16Var(&cfg.Port, "port", cfg.Port, "default SSH port")
	f.DurationVar(&cfg.TargetTimeout, "timeout", cfg.TargetTimeout, "per-target timeout")
	f.DurationVar(&cfg.ConnectionTimeout, "connect-timeout", cfg.ConnectionTimeout, "connection timeout")
	f.IntVar(&cfg.Concurrency, "concurrency", cfg.Concurrency, "global worker limit")
	f.IntVar(&cfg.PerHostConnections, "per-host-connections", cfg.PerHostConnections, "per-host connection limit")
	f.Float64Var(&cfg.RateLimit, "rate", cfg.RateLimit, "maximum connection starts per second")
	f.IntVar(&cfg.MaximumTargets, "max-targets", cfg.MaximumTargets, "hard target-count limit")
	f.BoolVar(&ipv4, "ipv4", false, "resolve IPv4 addresses only")
	f.BoolVar(&ipv6, "ipv6", false, "resolve IPv6 addresses only")
	f.StringVar(&cfg.AuditUser, "audit-user", cfg.AuditUser, "audit username setting; authentication probe begins in Phase 5")
	f.BoolVar(&noAuth, "no-auth-probe", false, "record authentication-method probing as disabled")
	f.StringVar(&cfg.KnownHostsPath, "known-hosts", "", "known_hosts setting; host-key comparison begins in Phase 4")
	f.StringVar(&cfg.PolicyPath, "policy", cfg.PolicyPath, "policy setting; evaluation begins in Phase 6")
	f.Var(newOutputFormatValue(&cfg.OutputFormat), "format", "output format: terminal or json")
	f.StringVarP(&cfg.OutputPath, "output", "o", "", "write output to file")
	f.BoolVar(&authorization.OperatorConfirmed, "authorized", false, "record that the operator confirms authorization")
	f.StringVar(&authorization.ScopeReference, "scope-reference", "", "authorization or scope reference")
	f.BoolVarP(&cfg.Verbose, "verbose", "v", false, "show additional operational detail")
	f.StringVar(&failOn, "fail-on", string(cfg.FailureThreshold), "finding threshold setting; evaluation begins in Phase 6")
	return cmd
}

func readTargetLines(reader io.Reader, maximumTargets int) ([]string, error) {
	if reader == nil {
		return nil, errors.New("targets reader is required")
	}
	if maximumTargets < 1 {
		return nil, errors.New("maximum targets must be at least 1")
	}
	limited := &io.LimitedReader{R: reader, N: maximumTargetFileBytes + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 1024), maximumTargetLineBytes)
	lines := make([]string, 0, min(maximumTargets, 32))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(lines) >= maximumTargets {
			return nil, fmt.Errorf("targets file exceeds maximum of %d entries before CIDR expansion", maximumTargets)
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read targets file: %w", err)
	}
	if limited.N <= 0 {
		return nil, fmt.Errorf("targets file exceeds %d bytes", maximumTargetFileBytes)
	}
	if len(lines) == 0 {
		return nil, errors.New("targets file contains no targets")
	}
	return lines, nil
}

func renderOutput(ctx context.Context, stdout io.Writer, outputPath string, renderer report.Renderer, scanReport report.Report) error {
	if outputPath == "" {
		return renderer.Render(ctx, stdout, scanReport)
	}
	directory := filepath.Dir(outputPath)
	temporary, err := os.CreateTemp(directory, ".sshscope-report-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := renderer.Render(ctx, temporary, scanReport); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, outputPath); err != nil {
		return err
	}
	removeTemporary = false
	return nil
}

func newReportCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "report REPORT.json",
		Short: "Render a canonical JSON report",
		Args:  cobra.ExactArgs(1),
		RunE:  func(*cobra.Command, []string) error { return errPhasePending },
	}
}

func newCompareCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "compare OLD.json NEW.json",
		Short: "Compare two canonical reports",
		Args:  cobra.ExactArgs(2),
		RunE:  func(*cobra.Command, []string) error { return errPhasePending },
	}
}

func newPolicyCommand() *cobra.Command {
	policy := &cobra.Command{Use: "policy", Short: "Inspect and validate audit policies"}
	policy.AddCommand(&cobra.Command{
		Use:   "validate POLICY.yaml",
		Short: "Validate policy syntax and semantics",
		Args:  cobra.ExactArgs(1),
		RunE:  func(*cobra.Command, []string) error { return errPhasePending },
	})
	return policy
}

func newVersionCommand(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the sshscope version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), version)
			return err
		},
	}
}

type outputFormatValue struct{ value *config.OutputFormat }

func newOutputFormatValue(value *config.OutputFormat) *outputFormatValue {
	return &outputFormatValue{value: value}
}

func (v *outputFormatValue) String() string { return string(*v.value) }
func (v *outputFormatValue) Type() string   { return "format" }
func (v *outputFormatValue) Set(s string) error {
	switch config.OutputFormat(s) {
	case config.OutputTerminal, config.OutputJSON:
		*v.value = config.OutputFormat(s)
		return nil
	default:
		return fmt.Errorf("must be terminal or json")
	}
}

// ExecuteForTest runs a command with isolated IO and returns its output.
func ExecuteForTest(cmd *cobra.Command, args ...string) (string, error) {
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return output.String(), err
}
