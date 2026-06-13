package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

var blockedPrefixes = mustBlockedPrefixes()

var blockedExact = map[netip.Addr]struct{}{
	netip.MustParseAddr("169.254.169.254"): {},
	netip.MustParseAddr("fd00:ec2::254"):   {},
}

func mustBlockedPrefixes() []netip.Prefix {
	inputs := []string{
		"127.0.0.0/8",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"fe80::/10",
		"fc00::/7",
		"0.0.0.0/8",
		"224.0.0.0/4",
		"ff00::/8",
		"100.64.0.0/10",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
	}

	prefixes := make([]netip.Prefix, 0, len(inputs))
	for _, s := range inputs {
		prefixes = append(prefixes, netip.MustParsePrefix(s))
	}
	return prefixes
}

func ResolvePublicIPs(ctx context.Context, host string, max int) ([]netip.Addr, []string, error) {
	if isDangerousHostname(host) {
		return nil, nil, errors.New("host is blocked by safety policy")
	}

	resolver := net.DefaultResolver
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, nil, fmt.Errorf("dns lookup failed: %w", err)
	}

	var (
		safe    []netip.Addr
		blocked int
		all     = make([]string, 0, len(ips))
	)

	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip.IP)
		if !ok {
			continue
		}
		all = append(all, addr.String())
		if isBlockedAddr(addr) {
			blocked++
			continue
		}
		safe = append(safe, addr)
		if max > 0 && len(safe) >= max {
			break
		}
	}

	var warnings []string
	if blocked > 0 {
		warnings = append(warnings, fmt.Sprintf("%d resolved address(es) were blocked by safety policy", blocked))
	}
	if len(all) == 0 {
		return nil, warnings, errors.New("dns lookup returned no usable addresses")
	}
	if len(safe) == 0 {
		return nil, warnings, errors.New("all resolved addresses were blocked")
	}

	return safe, warnings, nil
}

func isBlockedAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	if _, ok := blockedExact[addr.Unmap()]; ok {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func normalizeAddrString(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(strings.Trim(s, "[]"))
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}
