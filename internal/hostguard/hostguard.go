// Package hostguard rejects requests whose Host header (or a header an
// application may trust in its place) is not one the operator listed in
// allowed_hosts.
//
// This is the defense against Host-header poisoning, the attack behind
// forged password-reset links: an application that builds an absolute URL
// from the request's Host (or X-Forwarded-Host) lets an attacker make the
// reset email point at their own domain, which is a phishing link that
// arrives from the real service. A WAF rule can't catch it because
// "evil.example" is a perfectly ordinary hostname; only the operator knows
// which names are legitimate. See docs/DETECTION.md.
package hostguard

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/singhmarch86/rampart/internal/events"
	"github.com/singhmarch86/rampart/internal/ratelimit"
)

// forwardedHostHeaders are the non-standard headers frameworks commonly
// trust to learn the public hostname. They are checked as well as Host,
// because poisoning through them works even when Host itself is fine.
var forwardedHostHeaders = []string{"X-Forwarded-Host", "X-Host"}

type entry struct {
	host     string // lowercase, no port, no leading "*."
	port     string // empty: any port
	wildcard bool   // "*.host": subdomains of host, not host itself
}

// Guard holds a parsed allow-list.
type Guard struct {
	entries []entry
}

// New parses allowed. Each entry is a hostname ("example.com"), a hostname
// with a port ("example.com:8443", which then only matches that port), or a
// wildcard ("*.example.com", matching any subdomain but not example.com
// itself). Matching is case-insensitive and ignores a trailing dot. IPv6
// literals are written in brackets ("[::1]"). Internationalized names must
// be given in their ASCII (punycode) form, as they appear in the Host header.
func New(allowed []string) (*Guard, error) {
	g := &Guard{}
	for _, raw := range allowed {
		e, err := parseEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("allowed_hosts %q: %w", raw, err)
		}
		g.entries = append(g.entries, e)
	}
	return g, nil
}

func parseEntry(raw string) (entry, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return entry{}, fmt.Errorf("must not be empty")
	}
	if strings.ContainsAny(s, "/@ \t?#") {
		return entry{}, fmt.Errorf("must be a bare hostname (optionally with :port), not a URL")
	}
	var e entry
	if strings.HasPrefix(s, "*.") {
		e.wildcard = true
		s = s[2:]
	}
	host, port, err := splitHostPort(s)
	if err != nil {
		return entry{}, err
	}
	if host == "" || strings.Contains(host, "*") {
		return entry{}, fmt.Errorf("wildcards are only allowed as a leading \"*.\"")
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return entry{}, fmt.Errorf("invalid port %q", port)
		}
	}
	e.host, e.port = host, port
	return e, nil
}

// splitHostPort lowercases and splits "host", "host:port", "[v6]" and
// "[v6]:port", dropping a trailing dot on the host. Unlike net.SplitHostPort
// it accepts a missing port.
func splitHostPort(s string) (host, port string, err error) {
	s = strings.ToLower(s)
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", "", fmt.Errorf("unterminated IPv6 literal")
		}
		host = s[:end+1]
		rest := s[end+1:]
		if rest == "" {
			return host, "", nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", "", fmt.Errorf("unexpected text after IPv6 literal")
		}
		return host, rest[1:], nil
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		if strings.Contains(s[:i], ":") {
			return "", "", fmt.Errorf("IPv6 literals must be in brackets")
		}
		host, port = s[:i], s[i+1:]
		if port == "" {
			return "", "", fmt.Errorf("empty port")
		}
	} else {
		host = s
	}
	return strings.TrimSuffix(host, "."), port, nil
}

// Allowed reports whether a single host value ("example.com",
// "example.com:8080", "[::1]:80") matches the list.
func (g *Guard) Allowed(value string) bool {
	host, port, err := splitHostPort(strings.TrimSpace(value))
	if err != nil || host == "" || strings.ContainsAny(host, "/\\@ \t?#") || !digits(port) {
		// Malformed: never match, even when the entry ignores the port.
		// Otherwise "example.com:80 evil.example" would pass an entry for
		// example.com, and the application may parse that value differently.
		return false
	}
	for _, e := range g.entries {
		if e.port != "" && e.port != port {
			continue
		}
		if e.wildcard {
			if len(host) > len(e.host)+1 && strings.HasSuffix(host, "."+e.host) {
				return true
			}
			continue
		}
		if host == e.host {
			return true
		}
	}
	return false
}

// digits reports whether s is empty or all ASCII digits.
func digits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// forwardedValues returns every host name the request claims through the
// forwarding headers: each comma-separated element of X-Forwarded-Host and
// X-Host, and the host= parameter of each Forwarded (RFC 7239) element.
func forwardedValues(r *http.Request) []string {
	var out []string
	for _, h := range forwardedHostHeaders {
		for _, line := range r.Header.Values(h) {
			for _, v := range strings.Split(line, ",") {
				out = append(out, strings.TrimSpace(v))
			}
		}
	}
	for _, line := range r.Header.Values("Forwarded") {
		for _, elem := range strings.Split(line, ",") {
			for _, param := range strings.Split(elem, ";") {
				k, v, ok := strings.Cut(strings.TrimSpace(param), "=")
				if ok && strings.EqualFold(k, "host") {
					out = append(out, strings.Trim(strings.TrimSpace(v), `"`))
				}
			}
		}
	}
	return out
}

// Middleware rejects, with 403 and a logged event, any request whose Host is
// missing or not allowed, or that carries a forwarded-host header naming a
// host that is not allowed. The reasons are fixed strings, not the offending
// value: that value is attacker-chosen and would make every probe a distinct
// row on the dashboard.
func (g *Guard) Middleware(logger *events.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reason := ""
		if !g.Allowed(r.Host) {
			reason = "Host header is not in allowed_hosts"
		} else {
			for _, v := range forwardedValues(r) {
				if !g.Allowed(v) {
					reason = "Forwarded host header (X-Forwarded-Host, X-Host or Forwarded) is not in allowed_hosts"
					break
				}
			}
		}
		if reason != "" {
			logger.Log(events.Event{
				Action: events.ActionBlock, Layer: "hostguard", Reason: reason,
				ClientIP: ratelimit.ClientIP(r).String(), Method: r.Method, Path: r.URL.Path,
			})
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
