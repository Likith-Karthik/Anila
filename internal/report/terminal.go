package report

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/finding"
	"github.com/sshscope/sshscope/internal/probe"
)

// TerminalRenderer writes a compact human-readable scan report.
type TerminalRenderer struct {
	Canonicalizer Canonicalizer
}

func (r TerminalRenderer) Render(ctx context.Context, writer io.Writer, input Report) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if writer == nil {
		return errors.New("terminal report writer is required")
	}
	canonicalizer := r.Canonicalizer
	if canonicalizer == nil {
		canonicalizer = StableCanonicalizer{}
	}
	canonical, err := canonicalizer.Canonicalize(input)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "sshscope %s — scan %s\n", canonical.ToolVersion, canonical.Status); err != nil {
		return err
	}
	for _, reportErr := range canonical.Errors {
		if _, err := fmt.Fprintf(writer, "Warning [%s/%s]: %s\n", reportErr.Probe, reportErr.Kind, reportErr.Message); err != nil {
			return err
		}
	}
	for _, result := range canonical.Targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(writer, "\nTarget: %s (%s)\n", result.Target.Original, result.Target.Endpoint()); err != nil {
			return err
		}
		reachable := observation(result.Observations, evidence.ObservationTCPReachable)
		if reachable != nil && reachable.Value.Boolean != nil {
			if _, err := fmt.Fprintf(writer, "  Reachable: %t\n", *reachable.Value.Boolean); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintln(writer, "  Reachable: unknown"); err != nil {
			return err
		}
		latency := observation(result.Observations, evidence.ObservationTCPLatency)
		if latency != nil && latency.Value.Number != nil {
			if _, err := fmt.Fprintf(writer, "  TCP latency: %.2f %s\n", *latency.Value.Number, latency.Value.Unit); err != nil {
				return err
			}
		}
		banner := observation(result.Observations, evidence.ObservationBannerRaw)
		if banner != nil && banner.Value.String != nil {
			if _, err := fmt.Fprintf(writer, "  Banner: %s\n", *banner.Value.String); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintln(writer, "  Banner: not observed"); err != nil {
			return err
		}
		preBanner := observation(result.Observations, evidence.ObservationBannerPreLines)
		if preBanner != nil && len(preBanner.Value.Strings) > 0 {
			if _, err := fmt.Fprintf(writer, "  Pre-banner lines: %d\n", len(preBanner.Value.Strings)); err != nil {
				return err
			}
			if canonical.Configuration.Verbose {
				for _, line := range preBanner.Value.Strings {
					if _, err := fmt.Fprintf(writer, "    %q\n", line); err != nil {
						return err
					}
				}
			}
		}
		kexAlgorithms := observation(result.Observations, evidence.ObservationKEXAlgorithms)
		hostKeyAlgorithms := observation(result.Observations, evidence.ObservationHostKeyAlgorithms)
		if kexAlgorithms != nil && hostKeyAlgorithms != nil {
			if _, err := fmt.Fprintf(writer, "  Algorithms: kex=%d host-key=%d\n", len(kexAlgorithms.Value.Strings), len(hostKeyAlgorithms.Value.Strings)); err != nil {
				return err
			}
			if canonical.Configuration.Verbose {
				if _, err := fmt.Fprintf(writer, "    KEX: %s\n", strings.Join(kexAlgorithms.Value.Strings, ", ")); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(writer, "    Host-key algorithms: %s\n", strings.Join(hostKeyAlgorithms.Value.Strings, ", ")); err != nil {
					return err
				}
			}
		} else if _, err := fmt.Fprintln(writer, "  Algorithms: not observed"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(writer, "  Host keys: not collected in Phase 3"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(writer, "  Authentication methods: not collected in Phase 3"); err != nil {
			return err
		}
		for _, probeErr := range result.Errors {
			if _, err := fmt.Fprintf(writer, "  Warning [%s/%s]: %s\n", probeErr.Probe, probeErr.Kind, probeErr.Message); err != nil {
				return err
			}
		}
		if result.Status != probe.StatusComplete {
			if _, err := fmt.Fprintf(writer, "  Probe status: %s (results may be incomplete)\n", result.Status); err != nil {
				return err
			}
		}
	}

	totals := map[finding.Severity]int{
		finding.SeverityCritical: 0,
		finding.SeverityHigh:     0,
		finding.SeverityMedium:   0,
		finding.SeverityLow:      0,
		finding.SeverityInfo:     0,
	}
	for _, result := range canonical.Targets {
		for _, item := range result.Findings {
			totals[item.Severity]++
		}
	}
	_, err = fmt.Fprintf(writer, "\nFindings: critical=%d high=%d medium=%d low=%d info=%d\n",
		totals[finding.SeverityCritical], totals[finding.SeverityHigh], totals[finding.SeverityMedium],
		totals[finding.SeverityLow], totals[finding.SeverityInfo])
	return err
}

func observation(observations []evidence.Observation, id string) *evidence.Observation {
	for index := range observations {
		if observations[index].ID == id {
			return &observations[index]
		}
	}
	return nil
}
