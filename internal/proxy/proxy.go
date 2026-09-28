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
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/singhmarch86/rampart/internal/apiabuse"
	"github.com/singhmarch86/rampart/internal/config"
	"github.com/singhmarch86/rampart/internal/events"
	"github.com/singhmarch86/rampart/internal/ipfilter"
	"github.com/singhmarch86/rampart/internal/oidcauth"
	"github.com/singhmarch86/rampart/internal/ratelimit"
	"github.com/singhmarch86/rampart/internal/schema"
	"github.com/singhmarch86/rampart/internal/waf"
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
		// %q, not %s: r.Method and r.URL.Path are attacker-controlled and
		// r.URL.Path is already percent-decoded, so a path like
		// "/foo%0d%0aFAKE-LOG-LINE" arrives containing a real CR/LF —
		// logged with %s that forges a second log line; %q escapes it
		// (verified: %q renders an embedded \r\n as the literal two-byte
		// escape sequence, not a real line break).
		// #nosec G706 -- gosec's taint check doesn't account for %q
		// escaping; the CR/LF this rule warns about can't survive %q.
		log.Printf("proxy: upstream error for %q %q: %v", r.Method, r.URL.Path, err)
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
	handler = ratelimit.Middleware(limiter, "ratelimit", logger, handler)
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
		ip := ratelimit.ClientIP(r)
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
