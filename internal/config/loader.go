package config

import "context"

// Loader loads and validates scan configuration from a source chosen by the
// presentation layer.
type Loader interface {
	Load(context.Context) (Config, error)
}
