package oidcauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/singhmarch86/rampart/internal/config"
	"github.com/singhmarch86/rampart/internal/events"
)

// mockOIDCProviderWithToken extends mockOIDCProvider with a real /token
// endpoint, so DashboardAuth's full Authorization Code exchange can be
// exercised end to end — this is what caught, live against real Keycloak,
// that realm roles live on the access token, not the ID token. This test
// guards against reintroducing that regression.
type mockOIDCProviderWithToken struct {
	*mockOIDCProvider
	// idTokenClaims/accessTokenClaims let each test control exactly what
	// ends up in each token, so the test can assert role extraction reads
	// the right one.
	idTokenClaims      map[string]any
	accessTokenClaims  map[string]any
	nextNonce          string
	endSessionEndpoint string // set before the server starts to advertise RP-Initiated Logout support
}

func newMockOIDCProviderWithToken(t *testing.T, endSessionEndpoint string) *mockOIDCProviderWithToken {
	t.Helper()
	base := newMockOIDCProviderNoServerYet(t)
	m := &mockOIDCProviderWithToken{mockOIDCProvider: base, endSessionEndpoint: endSessionEndpoint}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"issuer":                                m.Issuer,
			"authorization_endpoint":                m.Issuer + "/auth",
			"token_endpoint":                        m.Issuer + "/token",
			"jwks_uri":                              m.Issuer + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		if m.endSessionEndpoint != "" {
			doc["end_session_endpoint"] = m.endSessionEndpoint
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/keys", base.serveKeys)
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// The real token-exchange POST doesn't carry our test's nonce
		// through (oauth2.Config.Exchange only sends standard OAuth2
		// params), so the test sets m.nextNonce directly before firing
		// the callback request instead of threading it through HTTP.
		idClaims := map[string]any{"nonce": m.nextNonce}
		for k, v := range m.idTokenClaims {
			idClaims[k] = v
		}
		accessClaims := map[string]any{}
		for k, v := range m.accessTokenClaims {
			accessClaims[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": m.signToken(t, accessClaims),
			"id_token":     m.signToken(t, idClaims),
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	})

	m.Server = httptest.NewServer(mux)
	m.Issuer = m.Server.URL
	t.Cleanup(m.Server.Close)
	return m
}

func TestDashboardCallbackExtractsRolesFromAccessTokenNotIDToken(t *testing.T) {
	mock := newMockOIDCProviderWithToken(t, "")
	// This is exactly the shape Keycloak actually returns by default: the
	// ID token has no realm_access claim at all, only the access token does.
	mock.accessTokenClaims = map[string]any{
		"realm_access": map[string]any{"roles": []string{"rampart-dashboard-viewer"}},
	}
	// Deliberately no realm_access/roles claim on the ID token — this
	// mirrors Keycloak's actual default. "aud" must match ClientID for the
	// ID token's own verification to pass (that's the identity-proof half
	// of OIDC and is unrelated to the roles bug being tested here).
	mock.idTokenClaims = map[string]any{"aud": "test-client"}

	provider, err := NewProvider(context.Background(), mock.Issuer)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	logger, err := events.NewLogger("")
	if err != nil {
		t.Fatal(err)
	}
	dash := NewDashboardAuth(provider, config.DashboardAuthConfig{
		ClientID:        "test-client",
		RedirectURL:     "http://rampart.example/auth/callback",
		SessionSecret:   "test-secret-at-least-32-bytes-long!",
		SessionDuration: time.Hour,
		RequiredRoles:   []string{"rampart-dashboard-viewer"},
	}, "realm_access.roles", logger)

	// Drive handleLogin to get a real, valid auth-state cookie + nonce.
	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	dash.Handler().ServeHTTP(loginRec, loginReq)
	authStateCookie := findCookie(t, loginRec.Result().Cookies(), authStateCookieName)
	if authStateCookie == nil {
		t.Fatal("expected /auth/login to set an auth-state cookie")
	}

	// Extract the state and nonce the login step generated, since the
	// mock token endpoint needs the real nonce to embed in the ID token
	// for nonce validation to pass, and the callback needs the matching state.
	stateCheckReq := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	stateCheckReq.AddCookie(authStateCookie)
	st, err := dash.getAuthState(stateCheckReq)
	if err != nil {
		t.Fatalf("could not read back auth state: %v", err)
	}
	mock.nextNonce = st.Nonce

	callbackReq := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+st.State+"&code=test-code", nil)
	callbackReq.AddCookie(authStateCookie)
	callbackRec := httptest.NewRecorder()
	dash.Handler().ServeHTTP(callbackRec, callbackReq)

	if callbackRec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect to / on successful login, got %d: %s", callbackRec.Code, callbackRec.Body.String())
	}

	sessionCookie := findCookie(t, callbackRec.Result().Cookies(), sessionCookieName)
	if sessionCookie == nil {
		t.Fatal("expected a session cookie to be set after successful login")
	}
}

func TestDashboardCallbackRejectsWhenAccessTokenLacksRequiredRole(t *testing.T) {
	mock := newMockOIDCProviderWithToken(t, "")
	mock.accessTokenClaims = map[string]any{
		"realm_access": map[string]any{"roles": []string{"some-other-role"}},
	}
	mock.idTokenClaims = map[string]any{"aud": "test-client"}

	provider, err := NewProvider(context.Background(), mock.Issuer)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	logger, err := events.NewLogger("")
	if err != nil {
		t.Fatal(err)
	}
	dash := NewDashboardAuth(provider, config.DashboardAuthConfig{
		ClientID:        "test-client",
		RedirectURL:     "http://rampart.example/auth/callback",
		SessionSecret:   "test-secret-at-least-32-bytes-long!",
		SessionDuration: time.Hour,
		RequiredRoles:   []string{"rampart-dashboard-viewer"},
	}, "realm_access.roles", logger)

	loginRec := httptest.NewRecorder()
	dash.Handler().ServeHTTP(loginRec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	authStateCookie := findCookie(t, loginRec.Result().Cookies(), authStateCookieName)

	stateCheckReq := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	stateCheckReq.AddCookie(authStateCookie)
	st, err := dash.getAuthState(stateCheckReq)
	if err != nil {
		t.Fatalf("could not read back auth state: %v", err)
	}
	mock.nextNonce = st.Nonce

	callbackReq := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+st.State+"&code=test-code", nil)
	callbackReq.AddCookie(authStateCookie)
	callbackRec := httptest.NewRecorder()
	dash.Handler().ServeHTTP(callbackRec, callbackReq)

	if callbackRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when access token lacks the required role, got %d", callbackRec.Code)
	}
	if findCookie(t, callbackRec.Result().Cookies(), sessionCookieName) != nil {
		t.Fatal("expected no session cookie to be set when access is denied")
	}
}

func TestLogoutRedirectsToEndSessionEndpointWithIDTokenHint(t *testing.T) {
	mock := newMockOIDCProviderWithToken(t, "https://idp.example/logout")
	mock.accessTokenClaims = map[string]any{"realm_access": map[string]any{"roles": []string{"viewer"}}}
	mock.idTokenClaims = map[string]any{"aud": "test-client"}

	provider, err := NewProvider(context.Background(), mock.Issuer)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	logger, _ := events.NewLogger("")
	dash := NewDashboardAuth(provider, config.DashboardAuthConfig{
		ClientID:              "test-client",
		RedirectURL:           "http://rampart.example/auth/callback",
		SessionSecret:         "test-secret-at-least-32-bytes-long!",
		SessionDuration:       time.Hour,
		PostLogoutRedirectURL: "http://rampart.example/",
	}, "realm_access.roles", logger)

	// Log in first so there's a session (and its ID token) to log out of.
	loginRec := httptest.NewRecorder()
	dash.Handler().ServeHTTP(loginRec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	authStateCookie := findCookie(t, loginRec.Result().Cookies(), authStateCookieName)
	stateCheckReq := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	stateCheckReq.AddCookie(authStateCookie)
	st, err := dash.getAuthState(stateCheckReq)
	if err != nil {
		t.Fatalf("could not read back auth state: %v", err)
	}
	mock.nextNonce = st.Nonce
	callbackReq := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+st.State+"&code=test-code", nil)
	callbackReq.AddCookie(authStateCookie)
	callbackRec := httptest.NewRecorder()
	dash.Handler().ServeHTTP(callbackRec, callbackReq)
	sessionCookie := findCookie(t, callbackRec.Result().Cookies(), sessionCookieName)
	if sessionCookie == nil {
		t.Fatal("expected login to succeed and set a session cookie")
	}

	// Now log out.
	logoutReq := httptest.NewRequest(http.MethodGet, "/auth/logout", nil)
	logoutReq.AddCookie(sessionCookie)
	logoutRec := httptest.NewRecorder()
	dash.Handler().ServeHTTP(logoutRec, logoutReq)

	if logoutRec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect on logout, got %d", logoutRec.Code)
	}
	loc, err := url.Parse(logoutRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("logout Location header is not a valid URL: %v", err)
	}
	if loc.Scheme+"://"+loc.Host+loc.Path != "https://idp.example/logout" {
		t.Fatalf("expected redirect to the provider's end_session_endpoint, got %s", loc)
	}
	q := loc.Query()
	if q.Get("client_id") != "test-client" {
		t.Fatalf("expected client_id=test-client in logout redirect, got %q", q.Get("client_id"))
	}
	if q.Get("post_logout_redirect_uri") != "http://rampart.example/" {
		t.Fatalf("expected post_logout_redirect_uri to be set, got %q", q.Get("post_logout_redirect_uri"))
	}
	if q.Get("id_token_hint") == "" {
		t.Fatal("expected id_token_hint to be set from the session's stored ID token")
	}

	clearedSession := findCookie(t, logoutRec.Result().Cookies(), sessionCookieName)
	if clearedSession == nil || clearedSession.MaxAge >= 0 {
		t.Fatal("expected logout to clear the local session cookie regardless of RP-initiated logout")
	}
}

func TestLogoutFallsBackToLocalRedirectWithoutEndSessionEndpoint(t *testing.T) {
	mock := newMockOIDCProviderWithToken(t, "") // provider does not advertise RP-Initiated Logout
	provider, err := NewProvider(context.Background(), mock.Issuer)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	logger, _ := events.NewLogger("")
	dash := NewDashboardAuth(provider, config.DashboardAuthConfig{
		ClientID:        "test-client",
		SessionSecret:   "test-secret-at-least-32-bytes-long!",
		SessionDuration: time.Hour,
	}, "realm_access.roles", logger)

	logoutRec := httptest.NewRecorder()
	dash.Handler().ServeHTTP(logoutRec, httptest.NewRequest(http.MethodGet, "/auth/logout", nil))

	if logoutRec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", logoutRec.Code)
	}
	if loc := logoutRec.Header().Get("Location"); loc != "/" {
		t.Fatalf("expected fallback redirect to \"/\" when no end_session_endpoint is advertised, got %q", loc)
	}
}

func findCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}
