// Package oidcauth makes Rampart an OIDC relying party / resource server
// against an existing identity provider (Keycloak, Auth0, Okta, ...). It
// does not implement an identity provider: no user store, no login UI, no
// token issuance. Two things live here:
//
//   - RBACGuard: validates OIDC access tokens on proxied requests and
//     enforces per-route role requirements (see rbac.go).
//   - DashboardAuth: requires OIDC login to view the analytics dashboard,
//     using the Authorization Code + PKCE flow (see dashboard.go).
//
// Both share role extraction (this file) and rely on go-oidc for the
// actual OIDC/JWT mechanics — that library, not this package, is what you'd
// audit for protocol-level correctness.
package oidcauth

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// NewProvider performs OIDC discovery against issuerURL.
func NewProvider(ctx context.Context, issuerURL string) (*oidc.Provider, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery against %s: %w", issuerURL, err)
	}
	return provider, nil
}

// extractRoles walks claims along a dot-separated path (e.g.
// "realm_access.roles") and returns the []string found there, or nil if
// the path doesn't resolve to a string array. Handles the common shapes:
// a plain top-level array ("roles"), and a nested object-then-array
// (Keycloak's "realm_access.roles").
func extractRoles(claims map[string]any, path string) []string {
	if path == "" {
		return nil
	}
	segments := strings.Split(path, ".")

	var cur any = claims
	for _, seg := range segments {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[seg]
		if !ok {
			return nil
		}
	}

	raw, ok := cur.([]any)
	if !ok {
		return nil
	}
	roles := make([]string, 0, len(raw))
	for _, r := range raw {
		if s, ok := r.(string); ok {
			roles = append(roles, s)
		}
	}
	return roles
}

// hasAnyRole reports whether userRoles contains at least one role in
// required. An empty required list means "no specific role needed."
func hasAnyRole(userRoles, required []string) bool {
	if len(required) == 0 {
		return true
	}
	have := make(map[string]bool, len(userRoles))
	for _, r := range userRoles {
		have[r] = true
	}
	for _, need := range required {
		if have[need] {
			return true
		}
	}
	return false
}
