package oidcauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/singhmarch86/rampart/internal/config"
	"github.com/singhmarch86/rampart/internal/events"
)

const authStateCookieName = "rampart_auth_state"
const authStateTTL = 10 * time.Minute

// authState is round-tripped through a short-lived signed cookie across
// the redirect to the OIDC provider and back, carrying the CSRF state
// value, the OIDC nonce, and the PKCE verifier — none of these can be
// stored server-side without session storage, so the signed-cookie
// pattern extends to this too, not just the logged-in session.
type authState struct {
	State    string    `json:"state"`
	Nonce    string    `json:"nonce"`
	Verifier string    `json:"verifier"`
	Expiry   time.Time `json:"exp"`
}

// DashboardAuth requires OIDC login (Authorization Code + PKCE) to reach
// the dashboard. It does not issue or manage tokens for anything other
// than this login flow itself.
type DashboardAuth struct {
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
	// accessTokenVerifier checks the access token specifically for roles.
	// Keycloak (and most providers) put realm/resource roles on the access
	// token, not the ID token — the ID token describes who authenticated,
	// the access token describes what they can do. Its audience is
	// typically NOT this OIDC client (Keycloak's default access tokens are
	// audienced to "account"), so this verifier skips the client-ID check
	// and only confirms signature/issuer/expiry.
	accessTokenVerifier *oidc.IDTokenVerifier
	sessions            *SessionManager
	stateSecret         []byte
	requiredRoles       []string
	rolesClaim          string
	logger              *events.Logger
	// endSessionEndpoint enables RP-initiated logout (OIDC's standard,
	// though not universally implemented, mechanism for also ending the
	// IdP's own session). Empty if the provider doesn't advertise one in
	// its discovery document, in which case logout falls back to clearing
	// only Rampart's local session — see handleLogout.
	endSessionEndpoint    string
	postLogoutRedirectURL string
}

// providerMetadata pulls fields from OIDC discovery that go-oidc's Provider
// doesn't expose directly — end_session_endpoint is a widely-supported
// but non-core-spec extension (RP-Initiated Logout 1.0).
type providerMetadata struct {
	EndSessionEndpoint string `json:"end_session_endpoint"`
}

func NewDashboardAuth(provider *oidc.Provider, cfg config.DashboardAuthConfig, rolesClaim string, logger *events.Logger) *DashboardAuth {
	var meta providerMetadata
	_ = provider.Claims(&meta) // best-effort; missing end_session_endpoint just disables RP-initiated logout

	return &DashboardAuth{
		oauth2Config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       cfg.Scopes,
		},
		accessTokenVerifier:   provider.Verifier(&oidc.Config{SkipClientIDCheck: true}),
		verifier:              provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		sessions:              NewSessionManager(cfg.SessionSecret, cfg.SessionDuration),
		stateSecret:           []byte(cfg.SessionSecret),
		requiredRoles:         cfg.RequiredRoles,
		rolesClaim:            rolesClaim,
		logger:                logger,
		endSessionEndpoint:    meta.EndSessionEndpoint,
		postLogoutRedirectURL: cfg.PostLogoutRedirectURL,
	}
}

// Handler serves /auth/login, /auth/callback, and /auth/logout. Mount it
// at "/auth/" alongside RequireAuth wrapping everything else.
func (d *DashboardAuth) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", d.handleLogin)
	mux.HandleFunc("/auth/callback", d.handleCallback)
	mux.HandleFunc("/auth/logout", d.handleLogout)
	return mux
}

// RequireAuth wraps the dashboard's own handler, redirecting to login when
// there's no valid session and returning 403 when the session is valid but
// lacks a required role.
func (d *DashboardAuth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := d.sessions.Verify(r)
		if err != nil {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}
		if !hasAnyRole(sess.Roles, d.requiredRoles) {
			http.Error(w, "forbidden: missing required dashboard role", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (d *DashboardAuth) handleLogin(w http.ResponseWriter, r *http.Request) {
	state := randomString(32)
	nonce := randomString(32)
	verifier := oauth2.GenerateVerifier()

	if err := d.setAuthState(w, authState{State: state, Nonce: nonce, Verifier: verifier, Expiry: time.Now().Add(authStateTTL)}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	url := d.oauth2Config.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	http.Redirect(w, r, url, http.StatusFound)
}

func (d *DashboardAuth) handleCallback(w http.ResponseWriter, r *http.Request) {
	st, err := d.getAuthState(r)
	if err != nil {
		http.Error(w, "login session expired or invalid, try again", http.StatusBadRequest)
		return
	}
	clearAuthStateCookie(w)

	if r.URL.Query().Get("state") != st.State {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	token, err := d.oauth2Config.Exchange(r.Context(), code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		d.logger.Log(events.Event{Action: events.ActionBlock, Layer: "oidc", Reason: "token exchange failed: " + err.Error(), ClientIP: clientIP(r), Method: r.Method, Path: r.URL.Path})
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "provider did not return an id_token", http.StatusBadGateway)
		return
	}
	idToken, err := d.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "id_token verification failed", http.StatusUnauthorized)
		return
	}
	if idToken.Nonce != st.Nonce {
		http.Error(w, "nonce mismatch", http.StatusUnauthorized)
		return
	}

	// Roles come from the access token, not the ID token — see the
	// accessTokenVerifier field comment for why. Verified here (not just
	// parsed) because it's a JWT we're about to trust for authorization
	// decisions, even though it just came from a direct token-endpoint
	// exchange.
	accessToken, err := d.accessTokenVerifier.Verify(r.Context(), token.AccessToken)
	if err != nil {
		http.Error(w, "access_token verification failed", http.StatusUnauthorized)
		return
	}
	var accessClaims map[string]any
	if err := accessToken.Claims(&accessClaims); err != nil {
		http.Error(w, "could not parse access token claims", http.StatusUnauthorized)
		return
	}
	roles := extractRoles(accessClaims, d.rolesClaim)

	if !hasAnyRole(roles, d.requiredRoles) {
		d.logger.Log(events.Event{Action: events.ActionBlock, Layer: "oidc", Reason: "authenticated but missing required dashboard role", ClientIP: clientIP(r), Method: r.Method, Path: r.URL.Path})
		http.Error(w, "your account does not have access to this dashboard", http.StatusForbidden)
		return
	}

	if err := d.sessions.Create(w, idToken.Subject, roles, rawIDToken); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleLogout always clears Rampart's own session. If the provider
// advertises an end_session_endpoint (RP-Initiated Logout), it also
// redirects there so the IdP's session ends too — without this, a user
// could "log out" of the dashboard and immediately get silently
// re-authenticated via the IdP's still-active SSO session on next visit.
func (d *DashboardAuth) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess, _ := d.sessions.Verify(r) // best-effort: still log out even if the session is already gone/invalid
	d.sessions.Clear(w)

	if d.endSessionEndpoint == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	endSessionURL, err := url.Parse(d.endSessionEndpoint)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	q := endSessionURL.Query()
	q.Set("client_id", d.oauth2Config.ClientID)
	if d.postLogoutRedirectURL != "" {
		q.Set("post_logout_redirect_uri", d.postLogoutRedirectURL)
	}
	if sess != nil && sess.IDToken != "" {
		q.Set("id_token_hint", sess.IDToken)
	}
	endSessionURL.RawQuery = q.Encode()
	http.Redirect(w, r, endSessionURL.String(), http.StatusFound)
}

// --- auth-state cookie (short-lived, separate from the login session) ---

func (d *DashboardAuth) setAuthState(w http.ResponseWriter, st authState) error {
	payload, err := json.Marshal(st)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, d.stateSecret)
	mac.Write(payload)
	value := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	http.SetCookie(w, &http.Cookie{
		Name:     authStateCookieName,
		Value:    value,
		Path:     "/auth/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  st.Expiry,
	})
	return nil
}

func (d *DashboardAuth) getAuthState(r *http.Request) (*authState, error) {
	c, err := r.Cookie(authStateCookieName)
	if err != nil {
		return nil, ErrNoSession
	}
	dot := -1
	for i := len(c.Value) - 1; i >= 0; i-- {
		if c.Value[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return nil, ErrInvalidSession
	}
	payload, err := base64.RawURLEncoding.DecodeString(c.Value[:dot])
	if err != nil {
		return nil, ErrInvalidSession
	}
	sig, err := base64.RawURLEncoding.DecodeString(c.Value[dot+1:])
	if err != nil {
		return nil, ErrInvalidSession
	}
	mac := hmac.New(sha256.New, d.stateSecret)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, ErrInvalidSession
	}
	var st authState
	if err := json.Unmarshal(payload, &st); err != nil {
		return nil, ErrInvalidSession
	}
	if time.Now().After(st.Expiry) {
		return nil, ErrSessionExpired
	}
	return &st, nil
}

func clearAuthStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: authStateCookieName, Value: "", Path: "/auth/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		Expires: time.Unix(0, 0), MaxAge: -1,
	})
}

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
