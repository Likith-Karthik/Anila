package target

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
)

// SpecKind distinguishes names, addresses, and bounded CIDR inputs.
type SpecKind string

const (
	SpecHostname SpecKind = "hostname"
	SpecAddress  SpecKind = "address"
	SpecCIDR     SpecKind = "cidr"
)

// Spec is a validated but potentially unresolved operator target.
type Spec struct {
	Original string
	Host     string
	Port     uint16
	Kind     SpecKind
	Address  netip.Addr
	Prefix   netip.Prefix
	Metadata map[string]string
}

// Parser turns operator input into unresolved target specifications.
type Parser interface {
	Parse(context.Context, []string, uint16) ([]Spec, error)
}

// InputParser strictly parses SSH endpoint and CIDR syntax without performing
// DNS resolution or network activity.
type InputParser struct{}

// Parse validates every non-empty input. Blank lines and lines whose first
// non-space byte is '#' are ignored to support simple target files.
func (InputParser) Parse(ctx context.Context, inputs []string, defaultPort uint16) ([]Spec, error) {
	if defaultPort == 0 {
		return nil, errors.New("default port must be between 1 and 65535")
	}
	specs := make([]Spec, 0, len(inputs))
	for index, input := range inputs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		trimmed := strings.TrimSpace(input)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		spec, err := parseOne(trimmed, defaultPort)
		if err != nil {
			return nil, fmt.Errorf("target %d (%q): %w", index+1, trimmed, err)
		}
		specs = append(specs, spec)
	}
	if len(specs) == 0 {
		return nil, errors.New("target input contains no targets")
	}
	return specs, nil
}

func parseOne(input string, defaultPort uint16) (Spec, error) {
	if strings.Contains(input, "/") {
		prefix, err := netip.ParsePrefix(input)
		if err != nil {
			return Spec{}, fmt.Errorf("invalid CIDR: %w", err)
		}
		if prefix.Addr().Zone() != "" {
			return Spec{}, errors.New("CIDR zones are not supported")
		}
		return Spec{
			Original: input,
			Host:     prefix.Masked().String(),
			Port:     defaultPort,
			Kind:     SpecCIDR,
			Prefix:   prefix.Masked(),
		}, nil
	}

	if address, err := netip.ParseAddr(input); err == nil {
		address = normalizeAddress(address)
		return Spec{Original: input, Host: address.String(), Port: defaultPort, Kind: SpecAddress, Address: address}, nil
	}

	host := input
	port := defaultPort
	if strings.HasPrefix(input, "[") || strings.Count(input, ":") == 1 {
		parsedHost, parsedPort, err := net.SplitHostPort(input)
		if err != nil {
			return Spec{}, fmt.Errorf("invalid host and port: %w", err)
		}
		host = parsedHost
		port64, err := strconv.ParseUint(parsedPort, 10, 16)
		if err != nil || port64 == 0 {
			return Spec{}, fmt.Errorf("invalid port %q", parsedPort)
		}
		port = uint16(port64)
		if address, err := netip.ParseAddr(host); err == nil {
			address = normalizeAddress(address)
			return Spec{Original: input, Host: address.String(), Port: port, Kind: SpecAddress, Address: address}, nil
		}
	}

	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if err := validateHostname(host); err != nil {
		return Spec{}, err
	}
	return Spec{Original: input, Host: host, Port: port, Kind: SpecHostname}, nil
}

func validateHostname(host string) error {
	if host == "" {
		return errors.New("hostname is empty")
	}
	if len(host) > 253 {
		return errors.New("hostname exceeds 253 bytes")
	}
	if strings.ContainsAny(host, "@/?#%") {
		return errors.New("hostname contains URL, user-info, or zone syntax")
	}
	for _, r := range host {
		if r > unicode.MaxASCII || unicode.IsSpace(r) || unicode.IsControl(r) {
			return errors.New("hostname must contain printable ASCII without spaces")
		}
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("hostname contains an empty or oversized label")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("hostname labels must not begin or end with a hyphen")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return fmt.Errorf("hostname contains invalid character %q", r)
			}
		}
	}
	return nil
}

func normalizeAddress(address netip.Addr) netip.Addr {
	if address.Is4In6() {
		return address.Unmap()
	}
	return address
}
