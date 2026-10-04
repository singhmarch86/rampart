// Package realip resolves the true client IP when Rampart sits behind a
// load balancer, Ingress controller or CDN, by honoring X-Forwarded-For -
// but only when the connection comes from an operator-listed trusted proxy.
// Every other layer keys on r.RemoteAddr, so rewriting it once, outermost,
// fixes the IP filter, rate limiter, brute-force lockout, WAF, RBAC and the
// event log together. Trusting the header from an arbitrary peer would let
// any client spoof its IP to dodge lockouts, hence the allowlist.
package realip

import (
	"net"
	"net/http"
	"strings"

	"github.com/singhmarch86/rampart/internal/ipfilter"
)

type Resolver struct {
	trusted []*net.IPNet
}

// New builds a Resolver from CIDRs or bare IPs. An empty list yields a
// Resolver whose Middleware is a no-op, preserving direct-exposure behavior.
func New(trustedProxies []string) (*Resolver, error) {
	nets, err := ipfilter.ParseCIDRs(trustedProxies)
	if err != nil {
		return nil, err
	}
	return &Resolver{trusted: nets}, nil
}

func (rs *Resolver) isTrusted(ip net.IP) bool {
	for _, n := range rs.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Middleware rewrites r.RemoteAddr to the resolved client IP (keeping the
// peer's port) when the direct peer is a trusted proxy. The chain is walked
// right to left, skipping trusted hops; the first untrusted address is the
// client. If every hop is trusted the leftmost is used. An unparseable
// entry means the chain can't be trusted, so RemoteAddr is left alone.
func (rs *Resolver) Middleware(next http.Handler) http.Handler {
	if len(rs.trusted) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if client, port, ok := rs.resolve(r); ok {
			r.RemoteAddr = net.JoinHostPort(client.String(), port)
		}
		next.ServeHTTP(w, r)
	})
}

func (rs *Resolver) resolve(r *http.Request) (net.IP, string, bool) {
	peerHost, peerPort, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, "", false
	}
	peer := net.ParseIP(peerHost)
	if peer == nil || !rs.isTrusted(peer) {
		return nil, "", false
	}
	header := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	if header == "" {
		return nil, "", false
	}
	hops := strings.Split(header, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(hops[i]))
		if ip == nil {
			return nil, "", false
		}
		if !rs.isTrusted(ip) || i == 0 {
			return ip, peerPort, true
		}
	}
	return nil, "", false
}
