package target

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"

	"github.com/sshscope/sshscope/internal/config"
)

// ResolveOptions bounds address-family selection and DNS expansion. The limit
// is applied incrementally so a hostname cannot create an oversized slice.
type ResolveOptions struct {
	IPPreference   config.IPPreference
	MaximumTargets int
}

// ResolutionErrorKind classifies target preparation failures.
type ResolutionErrorKind string

const (
	ResolutionDNS         ResolutionErrorKind = "dns_error"
	ResolutionNoAddresses ResolutionErrorKind = "no_matching_addresses"
)

// ResolutionError is safe-to-report target preparation evidence.
type ResolutionError struct {
	Kind      ResolutionErrorKind
	Original  string
	Host      string
	Message   string
	Retryable bool
	Cause     error
}

func (e ResolutionError) Error() string { return e.Message }
func (e ResolutionError) Unwrap() error { return e.Cause }

// Resolution preserves usable targets when individual DNS names fail.
type Resolution struct {
	Targets []Target
	Errors  []ResolutionError
}

// Resolver resolves and endpoint-deduplicates specifications without applying
// security policy. A non-nil error indicates cancellation or a hard limit.
type Resolver interface {
	Resolve(context.Context, []Spec, ResolveOptions) (Resolution, error)
}

// AddressLookup is the context-aware subset implemented by net.Resolver.
type AddressLookup interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// DNSResolver resolves names through an injected lookup implementation.
type DNSResolver struct {
	Lookup AddressLookup
}

// NewDNSResolver returns a resolver backed by the supplied resolver, or the
// process default when nil.
func NewDNSResolver(resolver *net.Resolver) DNSResolver {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return DNSResolver{Lookup: resolver}
}

func (r DNSResolver) Resolve(ctx context.Context, specs []Spec, options ResolveOptions) (Resolution, error) {
	if options.MaximumTargets < 1 {
		return Resolution{}, errors.New("maximum targets must be at least 1")
	}
	if options.MaximumTargets > config.AbsoluteMaximumTargets {
		return Resolution{}, fmt.Errorf("maximum targets exceeds hard limit %d", config.AbsoluteMaximumTargets)
	}
	if len(specs) > config.AbsoluteMaximumTargets {
		return Resolution{}, fmt.Errorf("target specifications exceed hard limit %d", config.AbsoluteMaximumTargets)
	}
	if options.IPPreference != config.IPAny && options.IPPreference != config.IPv4 && options.IPPreference != config.IPv6 {
		return Resolution{}, fmt.Errorf("unsupported IP preference %q", options.IPPreference)
	}
	if r.Lookup == nil {
		return Resolution{}, errors.New("DNS resolver is not configured")
	}

	resolution := Resolution{
		Targets: make([]Target, 0, min(len(specs), options.MaximumTargets)),
		Errors:  make([]ResolutionError, 0),
	}
	seen := make(map[string]struct{}, min(len(specs), options.MaximumTargets))
	for _, spec := range specs {
		if err := ctx.Err(); err != nil {
			return Resolution{}, err
		}
		var addresses []netip.Addr
		switch spec.Kind {
		case SpecAddress:
			addresses = []netip.Addr{spec.Address}
		case SpecHostname:
			resolved, err := r.Lookup.LookupNetIP(ctx, lookupNetwork(options.IPPreference), spec.Host)
			if err != nil {
				if ctx.Err() != nil {
					return Resolution{}, ctx.Err()
				}
				resolution.Errors = append(resolution.Errors, ResolutionError{
					Kind:      ResolutionDNS,
					Original:  spec.Original,
					Host:      spec.Host,
					Message:   fmt.Sprintf("DNS resolution failed for %q", spec.Host),
					Retryable: true,
					Cause:     err,
				})
				continue
			}
			addresses = resolved
		default:
			return Resolution{}, fmt.Errorf("target %q was not expanded before resolution", spec.Original)
		}

		filtered, fits, err := filterAddresses(ctx, addresses, options.IPPreference, options.MaximumTargets)
		if err != nil {
			return Resolution{}, err
		}
		if !fits {
			return Resolution{}, fmt.Errorf("resolved target count exceeds maximum %d", options.MaximumTargets)
		}
		if len(filtered) == 0 {
			resolution.Errors = append(resolution.Errors, ResolutionError{
				Kind:      ResolutionNoAddresses,
				Original:  spec.Original,
				Host:      spec.Host,
				Message:   fmt.Sprintf("no %s addresses resolved for %q", addressFamilyLabel(options.IPPreference), spec.Host),
				Retryable: false,
			})
			continue
		}
		slices.SortFunc(filtered, func(a, b netip.Addr) int { return a.Compare(b) })
		for _, address := range filtered {
			address = normalizeAddress(address)
			key := address.String() + "|" + strconv.Itoa(int(spec.Port))
			if _, exists := seen[key]; exists {
				continue
			}
			if len(resolution.Targets) >= options.MaximumTargets {
				return Resolution{}, fmt.Errorf("resolved target count exceeds maximum %d", options.MaximumTargets)
			}
			seen[key] = struct{}{}
			version := Version6
			if address.Is4() {
				version = Version4
			}
			resolution.Targets = append(resolution.Targets, Target{
				Original:   spec.Original,
				Hostname:   spec.Host,
				ResolvedIP: address,
				Port:       spec.Port,
				IPVersion:  version,
				Metadata:   maps.Clone(spec.Metadata),
			})
		}
	}
	return resolution, nil
}

func lookupNetwork(preference config.IPPreference) string {
	switch preference {
	case config.IPv4:
		return "ip4"
	case config.IPv6:
		return "ip6"
	default:
		return "ip"
	}
}

func filterAddresses(ctx context.Context, addresses []netip.Addr, preference config.IPPreference, maximum int) ([]netip.Addr, bool, error) {
	filtered := make([]netip.Addr, 0, min(len(addresses), maximum))
	seen := make(map[netip.Addr]struct{}, min(len(addresses), maximum))
	for _, address := range addresses {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		address = normalizeAddress(address)
		if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
			continue
		}
		if preference == config.IPv4 && !address.Is4() || preference == config.IPv6 && !address.Is6() {
			continue
		}
		if _, exists := seen[address]; exists {
			continue
		}
		if len(filtered) >= maximum {
			return nil, false, nil
		}
		seen[address] = struct{}{}
		filtered = append(filtered, address)
	}
	return filtered, true, nil
}

func addressFamilyLabel(preference config.IPPreference) string {
	switch preference {
	case config.IPv4:
		return "IPv4"
	case config.IPv6:
		return "IPv6"
	default:
		return "usable IP"
	}
}
