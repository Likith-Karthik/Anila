package evidence

import (
	"errors"
	"fmt"
	"slices"
	"sort"
)

// Normalizer converts probe observations into stable policy inputs.
type Normalizer interface {
	Normalize([]Observation) ([]Observation, error)
}

// StableNormalizer validates, copies, and sorts observations without changing
// order inside evidence lists such as SSH algorithm proposals.
type StableNormalizer struct{}

func (StableNormalizer) Normalize(input []Observation) ([]Observation, error) {
	result := make([]Observation, len(input))
	seen := make(map[string]struct{}, len(input))
	var errs []error
	for index, observation := range input {
		if err := observation.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("observation %d: %w", index, err))
			continue
		}
		key := observation.ID + "\x00" + observation.Probe
		if _, exists := seen[key]; exists {
			errs = append(errs, fmt.Errorf("duplicate observation %q from probe %q", observation.ID, observation.Probe))
			continue
		}
		seen[key] = struct{}{}
		result[index] = cloneObservation(observation)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].ID != result[j].ID {
			return result[i].ID < result[j].ID
		}
		return result[i].Probe < result[j].Probe
	})
	return result, nil
}

// CloneObservation deep-copies slice-backed evidence while preserving its order.
func CloneObservation(observation Observation) Observation {
	return cloneObservation(observation)
}

func cloneObservation(observation Observation) Observation {
	result := observation
	if observation.Value.Boolean != nil {
		value := *observation.Value.Boolean
		result.Value.Boolean = &value
	}
	if observation.Value.String != nil {
		value := *observation.Value.String
		result.Value.String = &value
	}
	if observation.Value.Number != nil {
		value := *observation.Value.Number
		result.Value.Number = &value
	}
	result.Value.Strings = slices.Clone(observation.Value.Strings)
	result.Value.HostKeys = slices.Clone(observation.Value.HostKeys)
	if observation.Value.KEX != nil {
		proposal := *observation.Value.KEX
		proposal.KeyExchanges = slices.Clone(proposal.KeyExchanges)
		proposal.ServerHostKeys = slices.Clone(proposal.ServerHostKeys)
		proposal.CiphersClientToServer = slices.Clone(proposal.CiphersClientToServer)
		proposal.CiphersServerToClient = slices.Clone(proposal.CiphersServerToClient)
		proposal.MACsClientToServer = slices.Clone(proposal.MACsClientToServer)
		proposal.MACsServerToClient = slices.Clone(proposal.MACsServerToClient)
		proposal.CompressionClientToServer = slices.Clone(proposal.CompressionClientToServer)
		proposal.CompressionServerToClient = slices.Clone(proposal.CompressionServerToClient)
		proposal.LanguagesClientToServer = slices.Clone(proposal.LanguagesClientToServer)
		proposal.LanguagesServerToClient = slices.Clone(proposal.LanguagesServerToClient)
		proposal.Extensions = slices.Clone(proposal.Extensions)
		result.Value.KEX = &proposal
	}
	if observation.Error != nil {
		errorInfo := *observation.Error
		result.Error = &errorInfo
	}
	return result
}
