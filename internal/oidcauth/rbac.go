package oidcauth

import (
	"net"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/singhmarch86/rampart/internal/config"
	"github.com/singhmarch86/rampart/internal/events"
)

type compiledRBACRule struct {
	methods       map[string]bool // nil means "all methods"
	pathPrefix    string
	verifier      *oidc.IDTokenVerifier
	requiredRoles []string
}

// RBACGuard validates OIDC access tokens on proxied requests and enforces
// per-route role requirements. It expects the access token to be a JWT
// signed by the configured issuer (true of Keycloak and most modern
// providers) — a provider issuing opaque access tokens would need a
// token-introspection integration instead, which isn't implemented here.
type RBACGuard struct {
	rules      []compiledRBACRule
	rolesClaim string
	logger     *events.Logger
}

func NewRBACGuard(provider *oidc.Provider, cfg config.APIRBACConfig, rolesClaim string, logger *events.Logger) *RBACGuard {
	g := &RBACGuard{rolesClaim: rolesClaim, logger: logger}
	for _, r := range cfg.Rules {
		verifierConfig := &oidc.Config{
			SkipClientIDCheck: r.Audience == "",
			ClientID:          r.Audience,
		}
		cr := compiledRBACRule{
			pathPrefix:    r.PathPrefix,
			verifier:      provider.Verifier(verifierConfig),
			requiredRoles: r.RequiredRoles,
		}
		if len(r.Methods) > 0 {
			cr.methods = make(map[string]bool, len(r.Methods))
			for _, m := range r.Methods {
				cr.methods[strings.ToUpper(m)] = true
			}
		}
		g.rules = append(g.rules, cr)
	}
	return g
}

func (g *RBACGuard) Middleware(next http.Handler) http.Handler {
	if len(g.rules) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rule := g.match(r)
		if rule == nil {
			next.ServeHTTP(w, r)
			return
		}

		token := bearerToken(r)
		if token == "" {
			g.deny(w, r, http.StatusUnauthorized, "missing bearer token")
			return
		}

		idToken, err := rule.verifier.Verify(r.Context(), token)
		if err != nil {
			g.deny(w, r, http.StatusUnauthorized, "token verification failed: "+err.Error())
			return
		}

		var claims map[string]any
		if err := idToken.Claims(&claims); err != nil {
			g.deny(w, r, http.StatusUnauthorized, "could not parse token claims")
			return
		}
		roles := extractRoles(claims, g.rolesClaim)
		if !hasAnyRole(roles, rule.requiredRoles) {
			g.deny(w, r, http.StatusForbidden, "token missing required role")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (g *RBACGuard) match(r *http.Request) *compiledRBACRule {
	for i, rule := range g.rules {
		if rule.methods != nil && !rule.methods[strings.ToUpper(r.Method)] {
			continue
		}
		// Case-insensitive: see the identical fix/comment in
		// internal/apiabuse/apiabuse.go's matches() and
		// internal/schema/schema.go's match() - same root cause
		// (Express's default case-insensitive routing vs. Go's
		// case-sensitive strings.HasPrefix), same bypass pattern, but
		// this instance (finding #11) is more severe: it's the actual
		// authorization layer, so a case-varied path skipped token
		// verification and the role check entirely, not just abuse
		// detection.
		if strings.HasPrefix(strings.ToLower(r.URL.Path), strings.ToLower(rule.pathPrefix)) {
			return &g.rules[i]
		}
	}
	return nil
}

func (g *RBACGuard) deny(w http.ResponseWriter, r *http.Request, status int, reason string) {
	g.logger.Log(events.Event{
		Action: events.ActionBlock, Layer: "oidc", Reason: reason,
		ClientIP: clientIP(r), Method: r.Method, Path: r.URL.Path,
	})
	w.Header().Set("WWW-Authenticate", `Bearer`)
	http.Error(w, http.StatusText(status), status)
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return ""
	}
	return auth[len(prefix):]
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
