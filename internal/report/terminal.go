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
		cipherClient := observation(result.Observations, evidence.ObservationCiphersClientToServer)
		cipherServer := observation(result.Observations, evidence.ObservationCiphersServerToClient)
		macClient := observation(result.Observations, evidence.ObservationMACsClientToServer)
		macServer := observation(result.Observations, evidence.ObservationMACsServerToClient)
		if cipherClient != nil && cipherServer != nil && macClient != nil && macServer != nil {
			if _, err := fmt.Fprintf(writer, "  Transport algorithms: ciphers=%d/%d macs=%d/%d (client/server directions)\n",
				len(cipherClient.Value.Strings), len(cipherServer.Value.Strings), len(macClient.Value.Strings), len(macServer.Value.Strings)); err != nil {
				return err
			}
			if canonical.Configuration.Verbose {
				if _, err := fmt.Fprintf(writer, "    Ciphers client-to-server: %s\n", strings.Join(cipherClient.Value.Strings, ", ")); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(writer, "    Ciphers server-to-client: %s\n", strings.Join(cipherServer.Value.Strings, ", ")); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(writer, "    MACs client-to-server: %s\n", strings.Join(macClient.Value.Strings, ", ")); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(writer, "    MACs server-to-client: %s\n", strings.Join(macServer.Value.Strings, ", ")); err != nil {
					return err
				}
			}
		}
		hostKeys := observation(result.Observations, evidence.ObservationHostKeys)
		if hostKeys != nil {
			for _, key := range hostKeys.Value.HostKeys {
				details := fmt.Sprintf("algorithm=%s type=%s known_hosts=%s", key.Algorithm, key.PublicKeyType, key.KnownHostsStatus)
				if key.Bits > 0 {
					details += fmt.Sprintf(" bits=%d", key.Bits)
				}
				if key.Certificate {
					details += " certificate=true"
				}
				if _, err := fmt.Fprintf(writer, "  Host key: %s (%s)\n", key.FingerprintSHA256, details); err != nil {
					return err
				}
				if key.CAFingerprintSHA256 != "" {
					if _, err := fmt.Fprintf(writer, "    Certificate CA: %s\n", key.CAFingerprintSHA256); err != nil {
						return err
					}
				}
			}
		} else if _, err := fmt.Fprintln(writer, "  Host keys: not observed"); err != nil {
			return err
		}
		if !canonical.Configuration.AuthProbeEnabled {
			if _, err := fmt.Fprintln(writer, "  Authentication methods: disabled"); err != nil {
				return err
			}
		} else {
			authMethods := observation(result.Observations, evidence.ObservationAuthMethods)
			if authMethods != nil {
				methods := strings.Join(authMethods.Value.Strings, ", ")
				if methods == "" {
					methods = "none advertised"
				}
				if _, err := fmt.Fprintf(writer, "  Authentication methods (%s): %s\n", canonical.Configuration.AuditUser, methods); err != nil {
					return err
				}
			} else if _, err := fmt.Fprintln(writer, "  Authentication methods: not observed"); err != nil {
				return err
			}
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
	if _, err := fmt.Fprintln(writer, "\nFindings by severity:"); err != nil {
		return err
	}
	if totalFindings(totals) == 0 {
		if _, err := fmt.Fprintln(writer, "  None"); err != nil {
			return err
		}
	} else {
		for _, severity := range []finding.Severity{
			finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo,
		} {
			if totals[severity] == 0 {
				continue
			}
			if _, err := fmt.Fprintf(writer, "  %s (%d)\n", strings.ToUpper(string(severity)), totals[severity]); err != nil {
				return err
			}
			for _, result := range canonical.Targets {
				for _, item := range result.Findings {
					if item.Severity != severity {
						continue
					}
					if _, err := fmt.Fprintf(writer, "    [%s] %s — %s\n", item.RuleID, item.Title, result.Target.Endpoint()); err != nil {
						return err
					}
					if _, err := fmt.Fprintf(writer, "      %s\n      Recommendation: %s\n", item.Description, item.Recommendation); err != nil {
						return err
					}
					if len(item.AffectedValues) > 0 {
						if _, err := fmt.Fprintf(writer, "      Affected: %s\n", strings.Join(item.AffectedValues, ", ")); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	if _, err = fmt.Fprintf(writer, "Severity totals: critical=%d high=%d medium=%d low=%d info=%d\n",
		totals[finding.SeverityCritical], totals[finding.SeverityHigh], totals[finding.SeverityMedium],
		totals[finding.SeverityLow], totals[finding.SeverityInfo]); err != nil {
		return err
	}
	return renderExitExplanation(writer, canonical)
}

func totalFindings(totals map[finding.Severity]int) int {
	return totals[finding.SeverityCritical] + totals[finding.SeverityHigh] + totals[finding.SeverityMedium] +
		totals[finding.SeverityLow] + totals[finding.SeverityInfo]
}

func renderExitExplanation(writer io.Writer, input Report) error {
	if input.Status == probe.StatusFailed {
		_, err := fmt.Fprintln(writer, "Exit status: 3 — scan could not be meaningfully completed")
		return err
	}
	matched, err := FindingsMeetThreshold(input)
	if err != nil {
		return err
	}
	if matched {
		_, err = fmt.Fprintf(writer, "Exit status: 1 — findings met the %s failure threshold\n", input.Configuration.FailureThreshold)
		return err
	}
	if input.Configuration.FailureThreshold == "never" {
		_, err = fmt.Fprintln(writer, "Exit status: 0 — finding threshold disabled")
		return err
	}
	_, err = fmt.Fprintf(writer, "Exit status: 0 — no findings met the %s failure threshold\n", input.Configuration.FailureThreshold)
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
