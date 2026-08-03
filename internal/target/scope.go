package target

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"strconv"
	"strings"

	"github.com/sshscope/sshscope/internal/config"
)

// ScopeValidator expands bounded CIDRs, removes duplicates, and applies hard
// target-count limits before resolution.
type ScopeValidator interface {
	Validate(context.Context, []Spec, int) ([]Spec, error)
}

// Scope enforces conservative target limits without network activity.
type Scope struct{}

// Validate expands CIDRs only after proving they fit within the remaining
// limit. It preserves first-seen order and metadata while removing duplicates.
func (Scope) Validate(ctx context.Context, specs []Spec, maximum int) ([]Spec, error) {
	if maximum < 1 {
		return nil, errors.New("maximum targets must be at least 1")
	}
	if maximum > config.AbsoluteMaximumTargets {
		return nil, fmt.Errorf("maximum targets exceeds hard limit %d", config.AbsoluteMaximumTargets)
	}
	if len(specs) > config.AbsoluteMaximumTargets {
		return nil, fmt.Errorf("target specifications exceed hard limit %d", config.AbsoluteMaximumTargets)
	}
	result := make([]Spec, 0, min(len(specs), maximum))
	seen := make(map[string]struct{}, min(len(specs), maximum))
	for _, spec := range specs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := validateSpec(spec); err != nil {
			return nil, fmt.Errorf("invalid target specification %q: %w", spec.Original, err)
		}
		switch spec.Kind {
		case SpecCIDR:
			count, fits := prefixCount(spec.Prefix, maximum-len(result))
			if !fits {
				return nil, fmt.Errorf("CIDR %s exceeds remaining target limit %d", spec.Prefix, maximum-len(result))
			}
			address := spec.Prefix.Masked().Addr()
			for index := 0; index < count; index++ {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				expanded := spec
				expanded.Kind = SpecAddress
				expanded.Address = normalizeAddress(address)
				expanded.Host = expanded.Address.String()
				expanded.Prefix = netip.Prefix{}
				expanded.Metadata = maps.Clone(spec.Metadata)
				appendUniqueSpec(&result, seen, expanded)
				address = address.Next()
			}
		case SpecAddress, SpecHostname:
			appendUniqueSpec(&result, seen, spec)
		default:
			return nil, fmt.Errorf("target %q has unsupported specification kind %q", spec.Original, spec.Kind)
		}
		if len(result) > maximum {
			return nil, fmt.Errorf("target count exceeds maximum %d", maximum)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("scope contains no targets")
	}
	return result, nil
}

func validateSpec(spec Spec) error {
	if spec.Original == "" || len(spec.Original) > maximumOriginalTargetBytes {
		return errors.New("original target is empty or oversized")
	}
	if spec.Port == 0 {
		return errors.New("target port must be between 1 and 65535")
	}
	if len(spec.Metadata) > maximumTargetMetadata {
		return fmt.Errorf("target metadata exceeds %d entries", maximumTargetMetadata)
	}
	for key, value := range spec.Metadata {
		if key == "" || len(key) > maximumTargetMetadataBytes || len(value) > maximumTargetMetadataBytes {
			return errors.New("target metadata contains an empty or oversized entry")
		}
	}
	switch spec.Kind {
	case SpecHostname:
		return validateHostname(spec.Host)
	case SpecAddress:
		if !spec.Address.IsValid() || spec.Address.Zone() != "" {
			return errors.New("target address is invalid or zoned")
		}
	case SpecCIDR:
		if !spec.Prefix.IsValid() || spec.Prefix.Addr().Zone() != "" || spec.Prefix != spec.Prefix.Masked() {
			return errors.New("target CIDR is invalid, zoned, or not masked")
		}
	default:
		return fmt.Errorf("unsupported specification kind %q", spec.Kind)
	}
	return nil
}

func prefixCount(prefix netip.Prefix, remaining int) (int, bool) {
	if !prefix.IsValid() || remaining < 0 {
		return 0, false
	}
	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	if hostBits >= 63 {
		return 0, false
	}
	count := uint64(1) << uint(hostBits)
	if count > uint64(remaining) {
		return 0, false
	}
	return int(count), true
}

func appendUniqueSpec(result *[]Spec, seen map[string]struct{}, spec Spec) {
	key := specKey(spec)
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	spec.Metadata = maps.Clone(spec.Metadata)
	*result = append(*result, spec)
}

func specKey(spec Spec) string {
	host := strings.ToLower(spec.Host)
	if spec.Kind == SpecAddress && spec.Address.IsValid() {
		host = normalizeAddress(spec.Address).String()
	}
	return string(spec.Kind) + "|" + host + "|" + strconv.Itoa(int(spec.Port))
}

// IsPublic reports whether an address appears globally routable. Special-use,
// documentation, benchmark, multicast, local, and private ranges are excluded.
func IsPublic(address netip.Addr) bool {
	address = normalizeAddress(address)
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() ||
		address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// AnyPublic reports whether a resolved scope contains a public endpoint.
func AnyPublic(targets []Target) bool {
	for _, item := range targets {
		if IsPublic(item.ResolvedIP) {
			return true
		}
	}
	return false
}

var nonPublicPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2001::/23"),
}
