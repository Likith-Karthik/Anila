package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sshscope/sshscope/internal/config"
	"github.com/sshscope/sshscope/internal/probe"
	"github.com/sshscope/sshscope/internal/report"
	"github.com/sshscope/sshscope/internal/scheduler"
	"github.com/sshscope/sshscope/internal/target"
)

func TestCommandTree(t *testing.T) {
	root := NewRootCommand("test-version")
	for _, path := range [][]string{{"scan"}, {"report"}, {"compare"}, {"policy", "validate"}, {"version"}} {
		if _, _, err := root.Find(path); err != nil {
			t.Fatalf("Find(%v) = %v", path, err)
		}
	}
}

func TestReadTargetLines(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		maximum int
		want    int
		wantErr string
	}{
		{"targets", "# comment\nexample.test\n\n192.0.2.1\n", 4, 2, ""},
		{"empty", "# only comments\n", 4, 0, "no targets"},
		{"count limit", "one.test\ntwo.test\n", 1, 0, "exceeds maximum"},
		{"line limit", strings.Repeat("a", maximumTargetLineBytes+1), 4, 0, "token too long"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readTargetLines(strings.NewReader(tt.input), tt.maximum)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("readTargetLines() error = %v", err)
				}
				return
			}
			if err != nil || len(got) != tt.want {
				t.Fatalf("readTargetLines() = %v, %v", got, err)
			}
		})
	}
}

func TestRenderOutputAtomicallyWritesPrivateFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "report.txt")
	renderer := staticRenderer("report data")
	if err := renderOutput(context.Background(), io.Discard, path, renderer, report.Report{}); err != nil {
		t.Fatalf("renderOutput() = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() = %v", err)
	}
	if string(data) != "report data" {
		t.Fatalf("output = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permissions = %o", info.Mode().Perm())
	}
}

type staticRenderer string

func (r staticRenderer) Render(_ context.Context, writer io.Writer, _ report.Report) error {
	_, err := io.WriteString(writer, string(r))
	return err
}

func TestExitCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"success", nil, ExitSuccess},
		{"invalid input", errors.New("bad flag"), ExitInvalidInput},
		{"scan failure", WithExitCode(ExitScanFailed, errors.New("failed")), ExitScanFailed},
		{"interrupted", fmt.Errorf("wrapped: %w", context.Canceled), ExitInterrupted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExitCode(tt.err); got != tt.want {
				t.Fatalf("ExitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	output, err := ExecuteForTest(NewRootCommand("1.2.3"), "version")
	if err != nil {
		t.Fatalf("version error = %v", err)
	}
	if output != "1.2.3\n" {
		t.Fatalf("version output = %q", output)
	}
}

func TestScanValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing target", []string{"scan"}, "provide TARGET"},
		{"two target sources", []string{"scan", "host", "--targets", "targets.txt"}, "mutually exclusive"},
		{"two IP families", []string{"scan", "host", "--ipv4", "--ipv6"}, "mutually exclusive"},
		{"unsafe concurrency", []string{"scan", "host", "--concurrency", "0"}, "concurrency"},
		{"bad threshold", []string{"scan", "host", "--fail-on", "low"}, "unsupported --fail-on"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExecuteForTest(NewRootCommand("test"), tt.args...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Execute() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestAppendAuthenticationProbeHonorsConfiguration(t *testing.T) {
	gate, err := scheduler.NewConnectionGate(1000, 1)
	if err != nil {
		t.Fatalf("NewConnectionGate() = %v", err)
	}
	base := []probe.Probe{fakeNamedProbe("hostkey")}
	tests := []struct {
		name     string
		enabled  bool
		wantSize int
		wantLast string
	}{
		{name: "enabled", enabled: true, wantSize: 2, wantLast: "auth"},
		{name: "disabled", enabled: false, wantSize: 1, wantLast: "hostkey"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.AuthProbeEnabled = tt.enabled
			got, err := appendAuthenticationProbe(base, cfg, gate)
			if err != nil {
				t.Fatalf("appendAuthenticationProbe() = %v", err)
			}
			if len(got) != tt.wantSize || got[len(got)-1].Name() != tt.wantLast {
				t.Fatalf("pipeline size=%d last=%q", len(got), got[len(got)-1].Name())
			}
		})
	}
}

type fakeNamedProbe string

func (p fakeNamedProbe) Name() string { return string(p) }
func (fakeNamedProbe) Run(context.Context, target.Target) probe.Result {
	return probe.Result{}
}
