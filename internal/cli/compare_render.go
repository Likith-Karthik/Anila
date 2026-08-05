package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/sshscope/sshscope/internal/app"
)

func renderComparison(ctx context.Context, writer io.Writer, comparison app.Comparison) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if writer == nil {
		return errors.New("comparison writer is required")
	}
	if err := comparison.Validate(); err != nil {
		return err
	}
	if !comparison.HasChanges() {
		_, err := fmt.Fprintln(writer, "No semantic changes.")
		return err
	}
	for _, item := range comparison.AddedTargets {
		if _, err := fmt.Fprintf(writer, "Added target: %s (%s)\n", safeComparisonText(item.Original), safeComparisonText(item.Endpoint)); err != nil {
			return err
		}
	}
	for _, item := range comparison.RemovedTargets {
		if _, err := fmt.Fprintf(writer, "Removed target: %s (%s)\n", safeComparisonText(item.Original), safeComparisonText(item.Endpoint)); err != nil {
			return err
		}
	}
	for _, item := range comparison.HostKeyChanges {
		if _, err := fmt.Fprintf(writer, "Host-key identity change: %s\n", safeComparisonText(item.Target.Endpoint)); err != nil {
			return err
		}
	}
	for _, item := range comparison.KnownHostsChanges {
		if _, err := fmt.Fprintf(writer, "known_hosts state change: %s %s %s -> %s\n",
			safeComparisonText(item.Target.Endpoint), safeComparisonText(item.FingerprintSHA256), item.Before, item.After); err != nil {
			return err
		}
	}
	for _, item := range comparison.AddedAlgorithms {
		if _, err := fmt.Fprintf(writer, "Added algorithms: %s %s: %s\n",
			safeComparisonText(item.Target.Endpoint), safeComparisonText(item.Field), safeComparisonList(item.Algorithms)); err != nil {
			return err
		}
	}
	for _, item := range comparison.RemovedAlgorithms {
		if _, err := fmt.Fprintf(writer, "Removed algorithms: %s %s: %s\n",
			safeComparisonText(item.Target.Endpoint), safeComparisonText(item.Field), safeComparisonList(item.Algorithms)); err != nil {
			return err
		}
	}
	for _, item := range comparison.NewFindings {
		if _, err := fmt.Fprintf(writer, "New finding: [%s] %s on %s (%s)\n",
			safeComparisonText(item.RuleID), safeComparisonText(item.Title), safeComparisonText(item.Target.Endpoint), item.Severity); err != nil {
			return err
		}
	}
	for _, item := range comparison.ResolvedFindings {
		if _, err := fmt.Fprintf(writer, "Resolved finding: [%s] %s on %s (%s)\n",
			safeComparisonText(item.RuleID), safeComparisonText(item.Title), safeComparisonText(item.Target.Endpoint), item.Severity); err != nil {
			return err
		}
	}
	for _, item := range comparison.SeverityChanges {
		if _, err := fmt.Fprintf(writer, "Finding severity change: [%s] %s %s -> %s\n",
			safeComparisonText(item.RuleID), safeComparisonText(item.Target.Endpoint), item.Before, item.After); err != nil {
			return err
		}
	}
	for _, item := range comparison.AuthMethodChanges {
		if _, err := fmt.Fprintf(writer, "Authentication methods change: %s %s -> %s\n",
			safeComparisonText(item.Target.Endpoint), safeComparisonList(item.Before), safeComparisonList(item.After)); err != nil {
			return err
		}
	}
	for _, item := range comparison.AuthNoneChanges {
		if _, err := fmt.Fprintf(writer, "none-authentication acceptance change: %s %t -> %t\n",
			safeComparisonText(item.Target.Endpoint), item.Before, item.After); err != nil {
			return err
		}
	}
	for _, item := range comparison.BannerChanges {
		if _, err := fmt.Fprintf(writer, "Banner change (self-reported, not a verified package change): %s %s -> %s\n",
			safeComparisonText(item.Target.Endpoint), safeComparisonText(item.Before), safeComparisonText(item.After)); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func safeComparisonText(value string) string {
	quoted := strconv.QuoteToGraphic(value)
	return quoted[1 : len(quoted)-1]
}

func safeComparisonList(values []string) string {
	escaped := make([]string, len(values))
	for index, value := range values {
		escaped[index] = safeComparisonText(value)
	}
	return strings.Join(escaped, ", ")
}
