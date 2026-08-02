package report

import (
	"context"
	"encoding/json"
	"errors"
	"io"
)

// JSONRenderer writes the canonical report representation.
type JSONRenderer struct {
	Canonicalizer Canonicalizer
}

func (r JSONRenderer) Render(ctx context.Context, writer io.Writer, input Report) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if writer == nil {
		return errors.New("JSON report writer is required")
	}
	canonicalizer := r.Canonicalizer
	if canonicalizer == nil {
		canonicalizer = StableCanonicalizer{}
	}
	canonical, err := canonicalizer.Canonicalize(input)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(canonical); err != nil {
		return err
	}
	return ctx.Err()
}
