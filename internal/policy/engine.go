package policy

import (
	"context"

	"github.com/sshscope/sshscope/internal/evidence"
	"github.com/sshscope/sshscope/internal/finding"
)

// Evaluator converts observations into findings according to a loaded policy.
type Evaluator interface {
	Evaluate(context.Context, []evidence.Observation) ([]finding.Finding, error)
}
