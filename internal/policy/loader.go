package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// Loader parses and validates a versioned policy document.
type Loader interface {
	Load(context.Context, io.Reader) (Document, error)
}

const (
	MaximumPolicyBytes = 1 << 20
	maximumYAMLDepth   = 32
	maximumYAMLNodes   = 8192
)

// YAMLLoader performs bounded, known-fields-only YAML decoding followed by
// complete schema and semantic validation.
type YAMLLoader struct{}

func (YAMLLoader) Load(ctx context.Context, reader io.Reader) (Document, error) {
	if reader == nil {
		return Document{}, errors.New("policy reader is required")
	}
	if err := ctx.Err(); err != nil {
		return Document{}, err
	}
	limited := &io.LimitedReader{R: reader, N: MaximumPolicyBytes + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		return Document{}, fmt.Errorf("read policy: %w", err)
	}
	if len(data) > MaximumPolicyBytes {
		return Document{}, fmt.Errorf("policy exceeds %d bytes", MaximumPolicyBytes)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return Document{}, errors.New("policy is empty")
	}
	if err := validateYAMLShape(data); err != nil {
		return Document{}, err
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var document Document
	if err := decoder.Decode(&document); err != nil {
		return Document{}, fmt.Errorf("decode policy YAML: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return Document{}, fmt.Errorf("decode trailing policy YAML: %w", err)
		}
		return Document{}, errors.New("policy must contain exactly one YAML document")
	}
	if err := document.Validate(); err != nil {
		return Document{}, fmt.Errorf("validate policy: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Document{}, err
	}
	return document, nil
}

func validateYAMLShape(data []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return fmt.Errorf("parse policy YAML: %w", err)
	}
	nodes := 0
	var walk func(*yaml.Node, int) error
	walk = func(node *yaml.Node, depth int) error {
		if node == nil {
			return nil
		}
		nodes++
		if nodes > maximumYAMLNodes {
			return fmt.Errorf("policy YAML exceeds %d nodes", maximumYAMLNodes)
		}
		if depth > maximumYAMLDepth {
			return fmt.Errorf("policy YAML exceeds maximum depth %d", maximumYAMLDepth)
		}
		if node.Kind == yaml.AliasNode {
			return errors.New("policy YAML aliases are not supported")
		}
		for _, child := range node.Content {
			if err := walk(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(&root, 0)
}
