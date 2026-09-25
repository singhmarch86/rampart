package oidcauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

// mockOIDCProvider is a minimal but real OIDC discovery + JWKS server,
// backed by a real RSA keypair, so tests exercise actual signature
// verification rather than a stub that always says "valid".
type mockOIDCProvider struct {
	Server *httptest.Server
	Issuer string
	key    *rsa.PrivateKey
	keyID  string
}

// newMockOIDCProviderNoServerYet generates the keypair and returns a
// mockOIDCProvider without starting an HTTP server, so callers that need a
// custom mux (e.g. adding a /token endpoint) can build on top of it.
func newMockOIDCProviderNoServerYet(t *testing.T) *mockOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating test RSA key: %v", err)
	}
	return &mockOIDCProvider{key: key, keyID: "test-key-1"}
}

func (m *mockOIDCProvider) serveKeys(w http.ResponseWriter, r *http.Request) {
	jwk := jose.JSONWebKey{Key: &m.key.PublicKey, KeyID: m.keyID, Algorithm: "RS256", Use: "sig"}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
}

func newMockOIDCProvider(t *testing.T) *mockOIDCProvider {
	t.Helper()
	m := newMockOIDCProviderNoServerYet(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                m.Issuer,
			"authorization_endpoint":                m.Issuer + "/auth",
			"token_endpoint":                        m.Issuer + "/token",
			"jwks_uri":                              m.Issuer + "/keys",
			"userinfo_endpoint":                     m.Issuer + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", m.serveKeys)

	m.Server = httptest.NewServer(mux)
	m.Issuer = m.Server.URL
	t.Cleanup(m.Server.Close)
	return m
}

// signToken builds and signs a JWT with the given claims merged over
// sensible defaults (iss, exp). Pass claims as a map for flexibility (test
// cases need to set arbitrary nested claims like realm_access.roles).
func (m *mockOIDCProvider) signToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: m.key}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{"kid": m.keyID},
	})
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	full := map[string]any{
		"iss": m.Issuer,
		"exp": josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		"iat": josejwt.NewNumericDate(time.Now()),
		"sub": "test-subject",
	}
	for k, v := range claims {
		full[k] = v
	}

	raw, err := josejwt.Signed(signer).Claims(full).Serialize()
	if err != nil {
		t.Fatalf("serializing token: %v", err)
	}
	return raw
}
