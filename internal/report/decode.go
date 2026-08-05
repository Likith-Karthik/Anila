package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const MaximumJSONBytes = 64 * 1024 * 1024

// JSONDecoder reads one bounded canonical JSON report and validates it.
type JSONDecoder struct{}

func (JSONDecoder) Decode(ctx context.Context, reader io.Reader) (Report, error) {
	if reader == nil {
		return Report{}, errors.New("JSON report reader is required")
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	limited := &io.LimitedReader{R: reader, N: MaximumJSONBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var output Report
	if err := decoder.Decode(&output); err != nil {
		return Report{}, fmt.Errorf("decode report JSON: %w", err)
	}
	if limited.N <= 0 {
		return Report{}, fmt.Errorf("report exceeds %d bytes", MaximumJSONBytes)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return Report{}, fmt.Errorf("decode trailing report JSON: %w", err)
		}
		return Report{}, errors.New("report must contain exactly one JSON value")
	}
	if err := output.Validate(); err != nil {
		return Report{}, fmt.Errorf("validate report: %w", err)
	}
	return output, ctx.Err()
}
