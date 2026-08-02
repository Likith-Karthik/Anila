package policy

import (
	"context"
	"io"
)

// Loader parses and validates a versioned policy document.
type Loader interface {
	Load(context.Context, io.Reader) (Document, error)
}
