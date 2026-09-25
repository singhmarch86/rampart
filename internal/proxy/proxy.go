// Package proxy assembles the reverse proxy and its enforcement middleware
// chain: IP filter -> rate limit -> OIDC RBAC -> API-abuse guard -> schema
// validation -> WAF -> upstream. Ordering matters: OIDC RBAC runs before
// the deeper checks so an unauthorized request never reaches them; the
// API-abuse guard wraps everything downstream of it so it observes the
// real final response status (needed to detect auth failures); schema
// validation and the WAF each only need to see the request.
package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/gauravdeepsingh/rampart/internal/apiabuse"
	"github.com/gauravdeepsingh/rampart/internal/config"
	"github.com/gauravdeepsingh/rampart/internal/events"
	"github.com/gauravdeepsingh/rampart/internal/ipfilter"
	"github.com/gauravdeepsingh/rampart/internal/oidcauth"
	"github.com/gauravdeepsingh/rampart/internal/ratelimit"
	"github.com/gauravdeepsingh/rampart/internal/schema"
	"github.com/gauravdeepsingh/rampart/internal/waf"
)

type Proxy struct {
	handler    http.Handler
	limiter    *ratelimit.Limiter
	abuseGuard *apiabuse.Guard
}

func New(cfg config.Config, logger *events.Logger) (*Proxy, error) {
	upstreamURL, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, err
	}

	filter, err := ipfilter.New(cfg.Firewall.Allow, cfg.Firewall.Deny)
	if err != nil {
		return nil, err
	}

	var limiter *ratelimit.Limiter
	if cfg.RateLimit.Enabled {
		limiter = ratelimit.New(
			cfg.RateLimit.RequestsPerSecond,
			cfg.RateLimit.Burst,
			cfg.RateLimit.MaxConcurrentPerIP,
			cfg.RateLimit.IdleTimeout,
		)
	}

	reverseProxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	reverseProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy: upstream error for %s %s: %v", r.Method, r.URL.Path, err)
		w.WriteHeader(http.StatusBadGateway)
	}

	var handler http.Handler = reverseProxy
	if cfg.WAF.Enabled {
		wafEngine, err := waf.New(cfg.WAF, logger)
		if err != nil {
			return nil, fmt.Errorf("initializing WAF: %w", err)
		}
		handler = wafEngine.Middleware(handler)
	}
	if cfg.Schema.Enabled {
		validator, err := schema.New(cfg.Schema, logger)
		if err != nil {
			return nil, fmt.Errorf("initializing schema validation: %w", err)
		}
		handler = validator.Middleware(handler)
	}
	var abuseGuard *apiabuse.Guard
	if cfg.APIAbuse.Enabled {
		abuseGuard = apiabuse.New(cfg.APIAbuse, logger)
		handler = abuseGuard.Middleware(handler)
	}
	if cfg.OIDC.Enabled && cfg.OIDC.APIRBAC.Enabled {
		discoverCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		provider, err := oidcauth.NewProvider(discoverCtx, cfg.OIDC.IssuerURL)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("initializing OIDC RBAC: %w", err)
		}
		rbacGuard := oidcauth.NewRBACGuard(provider, cfg.OIDC.APIRBAC, cfg.OIDC.RolesClaim, logger)
		handler = rbacGuard.Middleware(handler)
	}
	handler = withRateLimit(handler, limiter, logger)
	handler = withIPFilter(handler, filter, logger)

	return &Proxy{handler: handler, limiter: limiter, abuseGuard: abuseGuard}, nil
}

func (p *Proxy) Handler() http.Handler {
	return p.handler
}

func (p *Proxy) Close() {
	if p.limiter != nil {
		p.limiter.Close()
	}
	if p.abuseGuard != nil {
		p.abuseGuard.Close()
	}
}

func withIPFilter(next http.Handler, filter *ipfilter.Filter, logger *events.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		allowed, reason := filter.Allowed(ip)
		if !allowed {
			logger.Log(events.Event{
				Action: events.ActionBlock, Layer: "ipfilter", Reason: reason,
				ClientIP: ip.String(), Method: r.Method, Path: r.URL.Path,
			})
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func withRateLimit(next http.Handler, limiter *ratelimit.Limiter, logger *events.Logger) http.Handler {
	if limiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)

		if !limiter.Allow(ip) {
			logger.Log(events.Event{
				Action: events.ActionBlock, Layer: "ratelimit", Reason: "requests-per-second exceeded",
				ClientIP: ip.String(), Method: r.Method, Path: r.URL.Path,
			})
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}

		if !limiter.Begin(ip) {
			logger.Log(events.Event{
				Action: events.ActionBlock, Layer: "ratelimit", Reason: "max concurrent requests exceeded",
				ClientIP: ip.String(), Method: r.Method, Path: r.URL.Path,
			})
			http.Error(w, "too many concurrent requests", http.StatusTooManyRequests)
			return
		}
		defer limiter.End(ip)

		next.ServeHTTP(w, r)
	})
}

// clientIP extracts the request's source IP, ignoring proxy headers (which
// are attacker-controlled) unless Rampart itself is deployed behind a
// trusted proxy — a case Phase 5 (cloud-native packaging) will address
// explicitly via a trusted-proxy allowlist.
func clientIP(r *http.Request) net.IP {
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
