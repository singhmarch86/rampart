// Package ipfilter implements CIDR-based allow/deny checks: the network-layer
// core of Rampart's firewall.
package ipfilter

import (
	"fmt"
	"net"
)

type Filter struct {
	allow []*net.IPNet // empty means "allow all" unless denied
	deny  []*net.IPNet
}

// New builds a Filter from CIDR strings (e.g. "10.0.0.0/8", "203.0.113.5/32").
// A bare IP without a prefix is treated as a /32 (or /128 for IPv6).
func New(allow, deny []string) (*Filter, error) {
	a, err := parseCIDRs(allow)
	if err != nil {
		return nil, fmt.Errorf("allow list: %w", err)
	}
	d, err := parseCIDRs(deny)
	if err != nil {
		return nil, fmt.Errorf("deny list: %w", err)
	}
	return &Filter{allow: a, deny: d}, nil
}

func parseCIDRs(entries []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(entries))
	for _, e := range entries {
		if _, _, err := net.ParseCIDR(e); err != nil {
			ip := net.ParseIP(e)
			if ip == nil {
				return nil, fmt.Errorf("invalid CIDR or IP %q: %w", e, err)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			e = fmt.Sprintf("%s/%d", ip.String(), bits)
		}
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", e, err)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

// Allowed reports whether ip may pass, and a reason string when it is denied.
func (f *Filter) Allowed(ip net.IP) (bool, string) {
	for _, n := range f.deny {
		if n.Contains(ip) {
			return false, fmt.Sprintf("ip %s matches deny list entry %s", ip, n)
		}
	}
	if len(f.allow) == 0 {
		return true, ""
	}
	for _, n := range f.allow {
		if n.Contains(ip) {
			return true, ""
		}
	}
	return false, "ip not in allow list"
}
