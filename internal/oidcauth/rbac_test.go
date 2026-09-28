package oidcauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"github.com/singhmarch86/rampart/internal/config"
	"github.com/singhmarch86/rampart/internal/events"
)

func newTestGuard(t *testing.T, mock *mockOIDCProvider, rules ...config.APIRBACRule) *RBACGuard {
	t.Helper()
	provider, err := NewProvider(context.Background(), mock.Issuer)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	logger, err := events.NewLogger("")
	if err != nil {
		t.Fatal(err)
	}
	return NewRBACGuard(provider, config.APIRBACConfig{Enabled: true, Rules: rules}, "realm_access.roles", logger)
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func doRequest(h http.Handler, method, path, bearerToken string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRBACAllowsValidTokenWithRequiredRole(t *testing.T) {
	mock := newMockOIDCProvider(t)
	guard := newTestGuard(t, mock, config.APIRBACRule{
		PathPrefix: "/admin", RequiredRoles: []string{"admin"},
	})
	token := mock.signToken(t, map[string]any{
		"realm_access": map[string]any{"roles": []string{"admin", "viewer"}},
	})
	rec := doRequest(guard.Middleware(okHandler()), http.MethodGet, "/admin/dashboard", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRBACRejectsMissingToken(t *testing.T) {
	mock := newMockOIDCProvider(t)
	guard := newTestGuard(t, mock, config.APIRBACRule{PathPrefix: "/admin"})
	rec := doRequest(guard.Middleware(okHandler()), http.MethodGet, "/admin/dashboard", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got %d", rec.Code)
	}
}

func TestRBACRejectsTokenMissingRequiredRole(t *testing.T) {
	mock := newMockOIDCProvider(t)
	guard := newTestGuard(t, mock, config.APIRBACRule{
		PathPrefix: "/admin", RequiredRoles: []string{"admin"},
	})
	token := mock.signToken(t, map[string]any{
		"realm_access": map[string]any{"roles": []string{"viewer"}},
	})
	rec := doRequest(guard.Middleware(okHandler()), http.MethodGet, "/admin/dashboard", token)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for valid token missing required role, got %d", rec.Code)
	}
}

func TestRBACNoRequiredRolesMeansAnyValidTokenPasses(t *testing.T) {
	mock := newMockOIDCProvider(t)
	guard := newTestGuard(t, mock, config.APIRBACRule{PathPrefix: "/api"})
	token := mock.signToken(t, nil)
	rec := doRequest(guard.Middleware(okHandler()), http.MethodGet, "/api/things", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for any valid token when no roles required, got %d", rec.Code)
	}
}

func TestRBACRejectsExpiredToken(t *testing.T) {
	mock := newMockOIDCProvider(t)
	guard := newTestGuard(t, mock, config.APIRBACRule{PathPrefix: "/admin"})
	token := mock.signToken(t, map[string]any{
		"exp": josejwt.NewNumericDate(time.Now().Add(-time.Hour)),
	})
	rec := doRequest(guard.Middleware(okHandler()), http.MethodGet, "/admin/x", token)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired token, got %d", rec.Code)
	}
}

func TestRBACRejectsTokenSignedByDifferentIssuer(t *testing.T) {
	mock := newMockOIDCProvider(t)
	otherMock := newMockOIDCProvider(t) // different keypair AND different issuer URL
	guard := newTestGuard(t, mock, config.APIRBACRule{PathPrefix: "/admin"})

	// Signed by otherMock's key but claims iss=mock's issuer via override —
	// this specifically tests that signature verification catches a token
	// whose claims lie about which issuer it came from.
	token := otherMock.signToken(t, map[string]any{"iss": mock.Issuer})
	rec := doRequest(guard.Middleware(okHandler()), http.MethodGet, "/admin/x", token)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for token signed by an untrusted key, got %d", rec.Code)
	}
}

func TestRBACUnrelatedPathNotGuarded(t *testing.T) {
	mock := newMockOIDCProvider(t)
	guard := newTestGuard(t, mock, config.APIRBACRule{PathPrefix: "/admin"})
	rec := doRequest(guard.Middleware(okHandler()), http.MethodGet, "/public/page", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected unguarded path to pass through with no token, got %d", rec.Code)
	}
}

func TestRBACAudienceCheckedWhenConfigured(t *testing.T) {
	mock := newMockOIDCProvider(t)
	guard := newTestGuard(t, mock, config.APIRBACRule{PathPrefix: "/admin", Audience: "rampart-api"})

	wrongAud := mock.signToken(t, map[string]any{"aud": "some-other-client"})
	rec := doRequest(guard.Middleware(okHandler()), http.MethodGet, "/admin/x", wrongAud)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong audience, got %d", rec.Code)
	}

	rightAud := mock.signToken(t, map[string]any{"aud": "rampart-api"})
	rec = doRequest(guard.Middleware(okHandler()), http.MethodGet, "/admin/x", rightAud)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for correct audience, got %d", rec.Code)
	}
}
