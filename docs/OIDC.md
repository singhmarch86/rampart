# OIDC: dashboard login + API role enforcement

Rampart can integrate with an existing OIDC identity provider — Keycloak,
Auth0, Okta, or anything else that speaks standard OpenID Connect. It does
**not** replace one: no user store, no login UI, no token issuance. Two
independent features share the `oidc` config block:

1. **Dashboard login** (`oidc.dashboard_auth`) — requires OIDC login
   (Authorization Code + PKCE) to view the analytics dashboard, closing
   the "no authentication" gap noted since Phase 4.
2. **API RBAC enforcement** (`oidc.api_rbac`) — validates OIDC access
   tokens on requests to your protected app and enforces per-route role
   requirements before forwarding, the same pattern Kong's OIDC plugin or
   Envoy's JWT filter use.

Neither requires the other; enable one, both, or neither.

## Why Rampart doesn't become an identity provider

Building a correct, secure OAuth2/OIDC Authorization Server is a large,
security-critical undertaking — user storage, login UI, session
management, JWKS key rotation, refresh token rotation and reuse
detection. A bug in a WAF means a missed attack or an annoying false
positive; a bug in an *identity provider* means account takeover across
every app that trusts it. That's a categorically different blast radius,
and it's why "don't roll your own auth" is close to universal security
advice. Rampart integrates with a dedicated IdP instead — the same
architecture Kong+Keycloak, Envoy+Auth0, and AWS API Gateway+Cognito use.

## A real gotcha found building this: roles live on the access token, not the ID token

Verified live against a real Keycloak instance during development: the
**ID token** Keycloak issues by default does not include the
`realm_access.roles` claim — only the **access token** does. This is
correct, standard OIDC hygiene (the ID token describes *who
authenticated*; the access token describes *what they can do*), but it
means role-based access control needs to read the access token
specifically. Rampart's dashboard login does this — verifying the access
token (signature, issuer, expiry) separately from the ID token (which is
still used for the identity/nonce check) — see finding #6 in
[FINDINGS.md](FINDINGS.md) for the full story. If you're configuring
`roles_claim` for a different provider, check which token it actually
puts roles on.

## Dashboard login walkthrough (Keycloak example)

1. In your Keycloak realm, create a client (confidential, Standard Flow
   enabled) with a redirect URI matching `oidc.dashboard_auth.redirect_url`
   exactly (e.g. `http://localhost:9090/auth/callback`).
2. Create a realm role (e.g. `rampart-dashboard-viewer`) and assign it to
   whichever users should see the dashboard.
3. Set `oidc.enabled: true`, `oidc.dashboard_auth.enabled: true`, the
   client ID/secret, and `required_roles: ["rampart-dashboard-viewer"]`.
4. Generate a session secret: `openssl rand -hex 32`.

Visiting the dashboard now redirects to Keycloak's login page; after
login, users without the required role get a 403, not the dashboard.

**Note:** logout (`/auth/logout`) clears Rampart's own session cookie but
does not perform RP-initiated logout against the IdP — if your IdP session
is still active, visiting the dashboard again may silently re-authenticate
without showing a login form. This is a known scope limitation, not
implemented yet.

## API RBAC walkthrough

```yaml
oidc:
  enabled: true
  issuer_url: "https://keycloak.example.com/realms/myrealm"
  api_rbac:
    enabled: true
    rules:
      - path_prefix: "/admin"
        required_roles: ["admin"]
      - path_prefix: "/api"
        required_roles: []   # any valid token, no specific role needed
```

Requests to `/admin/*` without a valid `Authorization: Bearer <token>`
header get 401; a valid token missing the `admin` role gets 403. Requests
to `/api/*` just need any validly-signed, unexpired token.

This expects the access token to be a JWT signed by the issuer (true of
Keycloak and most modern providers). A provider issuing opaque access
tokens would need token-introspection support instead, which isn't
implemented here.

## Session model

Dashboard sessions are a signed cookie (HMAC-SHA256), not server-side
storage — there's no database to configure. The tradeoff: logout
overwrites the cookie rather than invalidating a server-side record, so a
stolen, still-valid session cookie remains valid until it naturally
expires (`session_duration`, default 8h). Keep that duration reasonably
short rather than open-ended.
