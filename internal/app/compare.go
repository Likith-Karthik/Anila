package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/finding"
	"github.com/sshscope/sshscope/internal/report"
)

// TargetReference identifies the report target associated with a change.
type TargetReference struct {
	Original string `json:"original"`
	Endpoint string `json:"endpoint"`
}

// HostKeyChange reports observed sets without attributing malicious intent.
type HostKeyChange struct {
	Target TargetReference    `json:"target"`
	Before []evidence.HostKey `json:"before"`
	After  []evidence.HostKey `json:"after"`
}

// AlgorithmChange identifies one proposal field and the algorithms changed.
type AlgorithmChange struct {
	Target     TargetReference `json:"target"`
	Field      string          `json:"field"`
	Algorithms []string        `json:"algorithms"`
}

// FindingReference is the stable identity and display context of a finding.
type FindingReference struct {
	Target   TargetReference  `json:"target"`
	RuleID   string           `json:"rule_id"`
	Title    string           `json:"title"`
	Severity finding.Severity `json:"severity"`
}

// SeverityChange records policy impact drift for an otherwise stable finding.
type SeverityChange struct {
	Target TargetReference  `json:"target"`
	RuleID string           `json:"rule_id"`
	Before finding.Severity `json:"before"`
	After  finding.Severity `json:"after"`
}

// AuthenticationMethodChange records two observed, possibly incomplete sets.
type AuthenticationMethodChange struct {
	Target TargetReference `json:"target"`
	Before []string        `json:"before"`
	After  []string        `json:"after"`
}

// BannerChange records a banner difference without treating it as a verified
// package version or security event.
type BannerChange struct {
	Target TargetReference `json:"target"`
	Before string          `json:"before"`
	After  string          `json:"after"`
}

// Comparison is a stable semantic difference between two reports.
type Comparison struct {
	AddedTargets      []TargetReference            `json:"added_targets"`
	RemovedTargets    []TargetReference            `json:"removed_targets"`
	HostKeyChanges    []HostKeyChange              `json:"host_key_changes"`
	AddedAlgorithms   []AlgorithmChange            `json:"added_algorithms"`
	RemovedAlgorithms []AlgorithmChange            `json:"removed_algorithms"`
	NewFindings       []FindingReference           `json:"new_findings"`
	ResolvedFindings  []FindingReference           `json:"resolved_findings"`
	SeverityChanges   []SeverityChange             `json:"severity_changes"`
	AuthMethodChanges []AuthenticationMethodChange `json:"auth_method_changes"`
	BannerChanges     []BannerChange               `json:"banner_changes"`
}

// Comparer computes semantic differences without assigning malicious intent.
type Comparer interface {
	Compare(context.Context, report.Report, report.Report) (Comparison, error)
}

// SemanticComparer compares report facts as sets where server preference is
// not itself the subject of the comparison. It deliberately assigns no
// security meaning to banner or host-key changes.
type SemanticComparer struct {
	Canonicalizer report.Canonicalizer
}

var comparedAlgorithmFields = []string{
	evidence.ObservationKEXAlgorithms,
	evidence.ObservationHostKeyAlgorithms,
	evidence.ObservationCiphersClientToServer,
	evidence.ObservationCiphersServerToClient,
	evidence.ObservationMACsClientToServer,
	evidence.ObservationMACsServerToClient,
	evidence.ObservationCompressionClientToServer,
	evidence.ObservationCompressionServerToClient,
}

func (c SemanticComparer) Compare(ctx context.Context, before, after report.Report) (Comparison, error) {
	if err := ctx.Err(); err != nil {
		return Comparison{}, err
	}
	canonicalizer := c.Canonicalizer
	if canonicalizer == nil {
		canonicalizer = report.StableCanonicalizer{}
	}
	oldReport, err := canonicalizer.Canonicalize(before)
	if err != nil {
		return Comparison{}, fmt.Errorf("canonicalize old report: %w", err)
	}
	newReport, err := canonicalizer.Canonicalize(after)
	if err != nil {
		return Comparison{}, fmt.Errorf("canonicalize new report: %w", err)
	}
	comparison := emptyComparison()
	oldTargets := targetResultsByEndpoint(oldReport.Targets)
	newTargets := targetResultsByEndpoint(newReport.Targets)

	for _, oldResult := range oldReport.Targets {
		if err := ctx.Err(); err != nil {
			return Comparison{}, err
		}
		endpoint := oldResult.Target.Endpoint()
		newResult, exists := newTargets[endpoint]
		if !exists {
			comparison.RemovedTargets = append(comparison.RemovedTargets, targetReference(oldResult))
			continue
		}
		compareSharedTarget(&comparison, oldResult, newResult)
	}
	for _, newResult := range newReport.Targets {
		if _, exists := oldTargets[newResult.Target.Endpoint()]; !exists {
			comparison.AddedTargets = append(comparison.AddedTargets, targetReference(newResult))
		}
	}
	sortComparison(&comparison)
	return comparison, nil
}

func emptyComparison() Comparison {
	return Comparison{
		AddedTargets: []TargetReference{}, RemovedTargets: []TargetReference{}, HostKeyChanges: []HostKeyChange{},
		AddedAlgorithms: []AlgorithmChange{}, RemovedAlgorithms: []AlgorithmChange{}, NewFindings: []FindingReference{},
		ResolvedFindings: []FindingReference{}, SeverityChanges: []SeverityChange{},
		AuthMethodChanges: []AuthenticationMethodChange{}, BannerChanges: []BannerChange{},
	}
}

func targetResultsByEndpoint(results []report.TargetResult) map[string]report.TargetResult {
	indexed := make(map[string]report.TargetResult, len(results))
	for _, result := range results {
		indexed[result.Target.Endpoint()] = result
	}
	return indexed
}

func targetReference(result report.TargetResult) TargetReference {
	return TargetReference{Original: result.Target.Original, Endpoint: result.Target.Endpoint()}
}

func compareSharedTarget(comparison *Comparison, before, after report.TargetResult) {
	reference := targetReference(after)
	oldKeys, oldKeysObserved := hostKeys(before.Observations)
	newKeys, newKeysObserved := hostKeys(after.Observations)
	if oldKeysObserved && newKeysObserved && !slices.Equal(oldKeys, newKeys) {
		comparison.HostKeyChanges = append(comparison.HostKeyChanges, HostKeyChange{Target: reference, Before: oldKeys, After: newKeys})
	}

	for _, field := range comparedAlgorithmFields {
		oldValues, oldObserved := stringObservation(before.Observations, field)
		newValues, newObserved := stringObservation(after.Observations, field)
		if !oldObserved || !newObserved {
			continue
		}
		added, removed := setDifference(oldValues, newValues)
		if len(added) > 0 {
			comparison.AddedAlgorithms = append(comparison.AddedAlgorithms, AlgorithmChange{Target: reference, Field: field, Algorithms: added})
		}
		if len(removed) > 0 {
			comparison.RemovedAlgorithms = append(comparison.RemovedAlgorithms, AlgorithmChange{Target: reference, Field: field, Algorithms: removed})
		}
	}

	compareFindings(comparison, reference, before.Findings, after.Findings)
	oldMethods, oldMethodsObserved := stringObservation(before.Observations, evidence.ObservationAuthMethods)
	newMethods, newMethodsObserved := stringObservation(after.Observations, evidence.ObservationAuthMethods)
	if oldMethodsObserved && newMethodsObserved && !equalStringSets(oldMethods, newMethods) {
		comparison.AuthMethodChanges = append(comparison.AuthMethodChanges, AuthenticationMethodChange{
			Target: reference, Before: sortedUnique(oldMethods), After: sortedUnique(newMethods),
		})
	}
	oldBanner, oldBannerObserved := scalarStringObservation(before.Observations, evidence.ObservationBannerRaw)
	newBanner, newBannerObserved := scalarStringObservation(after.Observations, evidence.ObservationBannerRaw)
	if oldBannerObserved && newBannerObserved && oldBanner != newBanner {
		comparison.BannerChanges = append(comparison.BannerChanges, BannerChange{Target: reference, Before: oldBanner, After: newBanner})
	}
}

func compareFindings(comparison *Comparison, target TargetReference, before, after []finding.Finding) {
	oldFindings := make(map[string]finding.Finding, len(before))
	newFindings := make(map[string]finding.Finding, len(after))
	for _, item := range before {
		oldFindings[item.RuleID] = item
	}
	for _, item := range after {
		newFindings[item.RuleID] = item
	}
	for _, item := range after {
		old, exists := oldFindings[item.RuleID]
		if !exists {
			comparison.NewFindings = append(comparison.NewFindings, findingReference(target, item))
		} else if old.Severity != item.Severity {
			comparison.SeverityChanges = append(comparison.SeverityChanges, SeverityChange{
				Target: target, RuleID: item.RuleID, Before: old.Severity, After: item.Severity,
			})
		}
	}
	for _, item := range before {
		if _, exists := newFindings[item.RuleID]; !exists {
			comparison.ResolvedFindings = append(comparison.ResolvedFindings, findingReference(target, item))
		}
	}
}

func findingReference(target TargetReference, item finding.Finding) FindingReference {
	return FindingReference{Target: target, RuleID: item.RuleID, Title: item.Title, Severity: item.Severity}
}

func hostKeys(observations []evidence.Observation) ([]evidence.HostKey, bool) {
	for _, observation := range observations {
		if observation.ID == evidence.ObservationHostKeys {
			keys := slices.Clone(observation.Value.HostKeys)
			sort.SliceStable(keys, func(i, j int) bool {
				if keys[i].FingerprintSHA256 != keys[j].FingerprintSHA256 {
					return keys[i].FingerprintSHA256 < keys[j].FingerprintSHA256
				}
				if keys[i].Algorithm != keys[j].Algorithm {
					return keys[i].Algorithm < keys[j].Algorithm
				}
				return keys[i].KnownHostsStatus < keys[j].KnownHostsStatus
			})
			return keys, true
		}
	}
	return []evidence.HostKey{}, false
}

func stringObservation(observations []evidence.Observation, id string) ([]string, bool) {
	for _, observation := range observations {
		if observation.ID == id {
			return slices.Clone(observation.Value.Strings), true
		}
	}
	return []string{}, false
}

func scalarStringObservation(observations []evidence.Observation, id string) (string, bool) {
	for _, observation := range observations {
		if observation.ID == id && observation.Value.String != nil {
			return *observation.Value.String, true
		}
	}
	return "", false
}

func setDifference(before, after []string) (added, removed []string) {
	oldSet := make(map[string]struct{}, len(before))
	newSet := make(map[string]struct{}, len(after))
	for _, value := range before {
		oldSet[value] = struct{}{}
	}
	for _, value := range after {
		newSet[value] = struct{}{}
	}
	for value := range newSet {
		if _, exists := oldSet[value]; !exists {
			added = append(added, value)
		}
	}
	for value := range oldSet {
		if _, exists := newSet[value]; !exists {
			removed = append(removed, value)
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	return added, removed
}

func equalStringSets(left, right []string) bool {
	return slices.Equal(sortedUnique(left), sortedUnique(right))
}

func sortedUnique(values []string) []string {
	result := slices.Clone(values)
	slices.Sort(result)
	return slices.Compact(result)
}

func sortComparison(comparison *Comparison) {
	sort.SliceStable(comparison.NewFindings, func(i, j int) bool { return findingReferenceLess(comparison.NewFindings[i], comparison.NewFindings[j]) })
	sort.SliceStable(comparison.ResolvedFindings, func(i, j int) bool {
		return findingReferenceLess(comparison.ResolvedFindings[i], comparison.ResolvedFindings[j])
	})
	sort.SliceStable(comparison.SeverityChanges, func(i, j int) bool {
		return comparison.SeverityChanges[i].Target.Endpoint+"\x00"+comparison.SeverityChanges[i].RuleID <
			comparison.SeverityChanges[j].Target.Endpoint+"\x00"+comparison.SeverityChanges[j].RuleID
	})
}

func findingReferenceLess(left, right FindingReference) bool {
	return left.Target.Endpoint+"\x00"+left.RuleID < right.Target.Endpoint+"\x00"+right.RuleID
}

// HasChanges reports whether the comparison contains any semantic change.
func (c Comparison) HasChanges() bool {
	return len(c.AddedTargets)+len(c.RemovedTargets)+len(c.HostKeyChanges)+len(c.AddedAlgorithms)+
		len(c.RemovedAlgorithms)+len(c.NewFindings)+len(c.ResolvedFindings)+len(c.SeverityChanges)+
		len(c.AuthMethodChanges)+len(c.BannerChanges) > 0
}

// Validate ensures comparison slices are initialized for stable JSON output.
func (c Comparison) Validate() error {
	if c.AddedTargets == nil || c.RemovedTargets == nil || c.HostKeyChanges == nil || c.AddedAlgorithms == nil ||
		c.RemovedAlgorithms == nil || c.NewFindings == nil || c.ResolvedFindings == nil || c.SeverityChanges == nil ||
		c.AuthMethodChanges == nil || c.BannerChanges == nil {
		return errors.New("comparison collections must not be nil")
	}
	return nil
}
