# Changelog

## Unreleased (to be tagged v0.2.0)

Everything since v0.1.1. The first version published as a tagged GitHub
release with a Docker image on `ghcr.io` (see the note under v0.1.0).

**Security fixes** (each with root cause, fix and verification in
[docs/FINDINGS.md](docs/FINDINGS.md)):
- Server-side template injection (`{{7*7}}`) was not blocked; custom WAF
  rule added (#9).
- A one-character path-case change (`/REST/User/Login`) bypassed the
  brute-force lockout, mass-assignment validation, and, most seriously,
  OIDC role enforcement (#10, #11).
- Behind a load balancer every client looked like the same IP, so one
  attacker's lockout hit everyone; `trusted_proxies` added (#12).
- No read or idle timeouts, so slow clients could hold connections open
  indefinitely; `server.read_timeout` / `server.idle_timeout` added (#13).
- `waf.mode: detect` logged nothing, so the documented "try it in detect
  mode first" workflow showed an empty log; it now records `detect` events
  for requests it would have blocked, kept separate from block counts in the
  dashboard and `rampart-analyze` (#16).
- README and roadmap claimed geo-blocking, which was never implemented;
  corrected (#14).

**New:**
- `waf.paranoia_level` (1-4, default 1): choose the OWASP CRS paranoia
  level. Measured tradeoff in `benchmarks/RESULTS.md`: level 2 raises
  detection but wrongly blocked 38% of GoTestWAF's legitimate samples
  (9% at level 1), so try it in `mode: detect` first.
- Optional TLS termination with your own cert/key (`tls.*`).
- `rampart -version`, plus a `NOTICE` file and filled-in copyright.
- Plain Kubernetes manifests in `deploy/k8s/` for `kubectl apply`.
- `rampart-analyze`: offline triage report from the block-event log.
- `scripts/test-attacks.sh`: one-payload-per-class attack suite for a
  running instance.
- `scripts/test-crs-coverage.sh`: one canary per OWASP CRS category,
  mapping what the default paranoia level does and doesn't block. Found
  that XXE and two template-injection syntaxes were not blocked, both now
  fixed at the default level (#15).
- XML external-entity (XXE) check in the WAF middleware, and the template
  rule extended to `{% %}` and `<% %>` syntaxes.
- `scripts/security-assessment.sh`: deployment self-assessment with nmap,
  openssl and curl (open ports, TLS 1.0/1.1 refused, risky methods, block-page
  leaks); results in `docs/SELF-ASSESSMENT.md`.
- Release workflow publishing the image to `ghcr.io` on a version tag.

**Behavior change:** requests slower than 60s to *upload* are now cut off
by the default `server.read_timeout`; raise it or set it to `0` for large
uploads over slow links.

## v0.1.1 — hardening pass

Two real gaps closed, both verified live against a real Keycloak instance
(see [docs/FINDINGS.md](docs/FINDINGS.md) #7 and [docs/OIDC.md](docs/OIDC.md)):

- **Dashboard rate limiting**: the dashboard's HTTP server (including
  `/auth/login`/`/auth/callback` under OIDC dashboard auth) previously had
  no rate limiting of its own, unlike the main proxy. Fixed via a new
  `dashboard.rate_limit` config and a reusable `ratelimit.Middleware`.
- **RP-initiated logout**: `/auth/logout` now ends the IdP's own session
  too (via `end_session_endpoint` + `id_token_hint`) when the provider
  supports it, not just Rampart's local session cookie.

## v0.1.0 — initial release

*Note: v0.1.0 and v0.1.1 were development milestones and were never tagged
or published as GitHub releases or images; v0.2.0 above is the first
tagged release.*

First public repository state. All of the following is implemented, tested, and
verified against real running targets (OWASP Juice Shop, a real Keycloak
instance) — see [docs/FINDINGS.md](docs/FINDINGS.md) for the bugs found
and fixed along the way, and [benchmarks/RESULTS.md](benchmarks/RESULTS.md)
for independent WAF benchmark numbers.

- **Network layer**: reverse proxy, IP allow/deny, per-IP rate limiting
- **Application WAF**: Coraza + OWASP Core Rule Set, custom SecLang rule
  support, benchmarked with GoTestWAF
- **API abuse detection**: credential-stuffing/token-abuse blocking, JSON
  Schema request validation
- **Live analytics dashboard**: top attackers, block reasons, timeline,
  live event feed over SSE
- **Cloud-native packaging**: Docker (distroless, non-root), Helm chart,
  Terraform module for AWS ECS Fargate
- **OIDC integration**: dashboard login and API role/permission
  enforcement against an existing identity provider (Keycloak, Auth0,
  Okta, ...)

License: Apache 2.0.
