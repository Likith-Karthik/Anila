package app

import (
	"context"

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
