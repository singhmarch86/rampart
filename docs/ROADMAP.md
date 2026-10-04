# Roadmap

| Phase | Scope |
|---|---|
| 0. Foundations | Repo scaffold, license, architecture doc |
| 1. Network-layer core | Reverse proxy, IP allow/deny, per-IP rate and concurrency limiting, YAML rule config — **done**. Geo-blocking was in the original plan and is **not implemented**; connection-level protection shipped later as read/idle timeouts (see 7.8) |
| 2. Application WAF | Coraza + OWASP CRS integration, custom rule DSL, validated against OWASP Juice Shop |
| 3. API / mobile-backend protection | Credential-stuffing detection, token-abuse detection, REST/GraphQL schema validation |
| 4. Attack analytics dashboard | Event pipeline, local storage, web dashboard |
| 5. Cloud-native packaging | Docker image, Helm chart, ingress/sidecar mode, Terraform module |
| 5.5 OIDC integration | Dashboard login + API role/permission enforcement against an existing IdP (Keycloak, Auth0, Okta, ...); not an identity provider itself |
| 6. Community release | CI, security disclosure policy, contribution docs, issue/PR templates, launch materials — **done** |
| 7. Hosted Console (paid tier) | Separate SaaS build: multi-node fleet management, longer retention, threat-intel feed. Not started. |
| 7.5 Hardening pass | RP-initiated logout, dashboard rate limiting — **done**, see docs/FINDINGS.md #7 and docs/OIDC.md |
| 7.6 Self-scan | `govulncheck` + `gosec` against Rampart's own Go source, wired into CI — **done**, see docs/FINDINGS.md #8 |
| 7.7 Offline attack triage | `rampart-analyze`: a separate binary that turns a window of the block-event log into a Markdown triage report (top attackers, multi-vector IPs, traffic bursts), optionally narrated by an LLM (Anthropic API, BYO key) — **done**, see docs/ANALYZE.md. Deliberately scoped down from an earlier "auto-suggest new WAF rules" idea once it became clear the block-only event log (no payload, no allowed-traffic record) can't support that — see "Considered and parked" below. |
| 7.8 Network-layer hardening | Path-case bypass fixes across API-abuse, schema validation and RBAC; optional TLS termination (bring your own cert); `trusted_proxies` for correct client IPs behind a load balancer; read/idle timeouts — **done**, see docs/FINDINGS.md #10-#13 |

## Considered and parked

- **Training a custom ML/LLM model to detect novel attacks.** Would need
  labeled attack/benign traffic to train on. Rampart has no production
  deployment yet, so no real attacker traffic exists to learn from — and
  the obvious shortcut ("label everything the existing rules blocked as
  malicious") is circular: it only teaches a model to imitate rules that
  already exist, not catch what they miss. Revisit once there's a real
  deployment with real traffic, and even then, via public labeled datasets
  (e.g. CSIC 2010, or GoTestWAF's own payload corpus) evaluated with the
  same rigor as the base64 fix (docs/FINDINGS.md #2) — benchmarked
  before/after, false-positive rate checked — not trained on Rampart's own
  block log.

## Known limitations (tracked, not yet implemented)

- **No live cluster verification for the Helm chart** — `helm lint`/`helm template` pass cleanly, but it hasn't been deployed to a real Kubernetes cluster in this project's testing so far.
- **Terraform module untested via `terraform validate`** — the CLI wasn't available in the environment this was built in; written carefully against the documented provider schema but not run.
- **API RBAC policy rules are static YAML**, requiring a redeploy to change which routes need which roles. A database-backed policy store (not an identity store — Rampart still doesn't own user/role data) would let this be updated at runtime; not built yet.
- **`rampart-analyze`'s LLM narration step: the graceful-failure path is live-verified, the actual narration content is not.** Run against the real Anthropic API with an invalid key, the tool behaved exactly as designed — printed `narration failed, continuing with tables only: analyze: API error (authentication_error): API key is invalid.` to stderr and still wrote the full tables-only report rather than aborting. What's still unchecked: what a real model actually says in the `## Summary` section with a *valid* key, and whether it stays inside the system prompt's boundary (no claiming to find coverage gaps, no drafting rule syntax). The deterministic aggregation and the HTTP request/response handling are unit-tested against a fake server (`internal/analyze/llm_test.go`), but that's not the same as a human reading real model output.
