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

### Logout

`/auth/logout` clears Rampart's own session cookie, and — if the provider
advertises an `end_session_endpoint` in its discovery document (Keycloak
and most modern providers do) — also redirects there to end the IdP's own
session (RP-Initiated Logout), passing `id_token_hint` so the IdP doesn't
need a confirmation page. Set `oidc.dashboard_auth.post_logout_redirect_url`
to where the IdP should send the browser back afterward.

**Keycloak-specific gotcha, found while testing this:** the post-logout
redirect URI is *not* a top-level field on the client — the Admin REST API
rejects `postLogoutRedirectUris` outright. It has to go under the client's
`attributes` map instead:
```json
{"attributes": {"post.logout.redirect.uris": "http://localhost:9090/*"}}
```
In the Keycloak admin console UI this is just another entry in the client's
"Valid post logout redirect URIs" field — the REST API's field name is just
non-obvious.

If the provider doesn't advertise an `end_session_endpoint`, logout falls
back to only clearing Rampart's local session — the IdP session may remain
active, and a later visit could silently re-authenticate via SSO without
showing a login form.

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

## Dashboard rate limiting

`dashboard.rate_limit` protects the dashboard's own port — including
`/auth/login` and `/auth/callback` when OIDC dashboard auth is enabled —
the same way `rate_limit` protects the main proxy. This was missing
entirely until a hardening pass caught it (finding #7 in
[FINDINGS.md](FINDINGS.md)): the dashboard is a separate `http.Server`
that was never threaded through the same middleware as the main proxy
chain. Defaults are tighter than the main proxy's (5 req/s, burst 10) since
dashboard traffic is normally low-volume, but generous enough for the
live event stream (`/api/stream`) to hold its connection open.

## Session model

Dashboard sessions are a signed cookie (HMAC-SHA256), not server-side
storage — there's no database to configure. The tradeoff: logout
overwrites the cookie rather than invalidating a server-side record, so a
stolen, still-valid session cookie remains valid until it naturally
expires (`session_duration`, default 8h). Keep that duration reasonably
short rather than open-ended.
