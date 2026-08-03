package target

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/sshscope/sshscope/internal/config"
)

type fakeLookup struct {
	addresses map[string][]netip.Addr
	errors    map[string]error
}

type cancellingLookup struct{ cancel context.CancelFunc }

func (l cancellingLookup) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	l.cancel()
	return []netip.Addr{{}, {}, {}}, nil
}

func (f fakeLookup) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	if err := f.errors[host]; err != nil {
		return nil, err
	}
	return f.addresses[host], nil
}

func TestDNSResolverSortsFiltersAndDeduplicates(t *testing.T) {
	resolver := DNSResolver{Lookup: fakeLookup{addresses: map[string][]netip.Addr{
		"example.test": {
			netip.MustParseAddr("2001:db8::2"),
			netip.MustParseAddr("192.0.2.2"),
			netip.MustParseAddr("192.0.2.1"),
			netip.MustParseAddr("192.0.2.1"),
		},
	}}}
	specs, err := (InputParser{}).Parse(context.Background(), []string{"example.test", "192.0.2.1"}, 22)
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	result, err := resolver.Resolve(context.Background(), specs, ResolveOptions{IPPreference: config.IPv4, MaximumTargets: 4})
	if err != nil {
		t.Fatalf("Resolve() = %v", err)
	}
	if len(result.Targets) != 2 {
		t.Fatalf("Resolve() returned %d targets: %+v", len(result.Targets), result.Targets)
	}
	if result.Targets[0].ResolvedIP.String() != "192.0.2.1" || result.Targets[1].ResolvedIP.String() != "192.0.2.2" {
		t.Fatalf("targets are not deterministic: %+v", result.Targets)
	}
}

func TestDNSResolverPreservesPerNameErrors(t *testing.T) {
	resolver := DNSResolver{Lookup: fakeLookup{
		addresses: map[string][]netip.Addr{"good.test": {netip.MustParseAddr("192.0.2.1")}},
		errors:    map[string]error{"bad.test": errors.New("not found")},
	}}
	specs, err := (InputParser{}).Parse(context.Background(), []string{"bad.test", "good.test"}, 22)
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	result, err := resolver.Resolve(context.Background(), specs, ResolveOptions{IPPreference: config.IPAny, MaximumTargets: 4})
	if err != nil {
		t.Fatalf("Resolve() = %v", err)
	}
	if len(result.Targets) != 1 || len(result.Errors) != 1 || result.Errors[0].Kind != ResolutionDNS {
		t.Fatalf("Resolve() = %+v", result)
	}
}

func TestDNSResolverEnforcesPostResolutionLimit(t *testing.T) {
	resolver := DNSResolver{Lookup: fakeLookup{addresses: map[string][]netip.Addr{
		"many.test": {netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")},
	}}}
	specs, err := (InputParser{}).Parse(context.Background(), []string{"many.test"}, 22)
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	_, err = resolver.Resolve(context.Background(), specs, ResolveOptions{IPPreference: config.IPAny, MaximumTargets: 1})
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("Resolve() error = %v", err)
	}
}

func TestDNSResolverHonorsCancellationWhileFilteringLookupResults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	resolver := DNSResolver{Lookup: cancellingLookup{cancel: cancel}}
	specs, err := (InputParser{}).Parse(context.Background(), []string{"example.test"}, 22)
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	if _, err := resolver.Resolve(ctx, specs, ResolveOptions{IPPreference: config.IPAny, MaximumTargets: 4}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Resolve() = %v, want context cancellation", err)
	}
}
