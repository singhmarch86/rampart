package ratelimit

import (
	"net"
	"net/http"

	"github.com/singhmarch86/rampart/internal/events"
)

// Middleware wraps next with rate limiting by client IP. layer names the
// caller in the event log (e.g. "ratelimit" for the main proxy,
// "dashboard-ratelimit" for the dashboard server) so blocks stay
// attributable to which listener they hit — useful since both feed the
// same event stream the dashboard itself displays.
func Middleware(limiter *Limiter, layer string, logger *events.Logger, next http.Handler) http.Handler {
	if limiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)

		if !limiter.Allow(ip) {
			logger.Log(events.Event{
				Action: events.ActionBlock, Layer: layer, Reason: "requests-per-second exceeded",
				ClientIP: ip.String(), Method: r.Method, Path: r.URL.Path,
			})
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}

		if !limiter.Begin(ip) {
			logger.Log(events.Event{
				Action: events.ActionBlock, Layer: layer, Reason: "max concurrent requests exceeded",
				ClientIP: ip.String(), Method: r.Method, Path: r.URL.Path,
			})
			http.Error(w, "too many concurrent requests", http.StatusTooManyRequests)
			return
		}
		defer limiter.End(ip)

		next.ServeHTTP(w, r)
	})
}

// ClientIP extracts the request's source IP, ignoring proxy headers (which
// are attacker-controlled) unless deployed behind a trusted proxy — see
// docs/DEPLOYMENT.md.
func ClientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return net.IPv4zero
	}
	return ip
}
