# Launch post drafts

Drafts only — nothing here gets posted automatically. Copy, edit to sound
like you, and post yourself. Recommended order: wait until there's a
tagged release on a public GitHub repo before posting any of these (a dead
link in a Show HN post is a bad first impression).

---

## Show HN (news.ycombinator.com)

**Title:** `Show HN: Rampart – self-hosted WAF/rate-limiter/OIDC gateway, one binary`

**Body:**

I got tired of stitching together nginx + ModSecurity + fail2ban + a
separate OIDC gateway plugin + a bolted-on Grafana pipeline every time a
project needed real request-level security. Rampart is what I wanted
instead: one Go binary that does WAF (Coraza + OWASP CRS), rate limiting,
credential-stuffing detection, JSON Schema request validation, OIDC-based
RBAC, and a live analytics dashboard — configured in one YAML file.

A few things I think are worth mentioning specifically:

- The WAF is benchmarked with GoTestWAF (an actual open-source WAF
  evaluation tool, not a number I made up): baseline 63%, found that 0% of
  base64-encoded attacks were being caught by default CRS config, fixed it
  with a targeted anti-evasion rule, re-benchmarked at 65% with the
  false-positive rate unchanged. Full numbers: [link to benchmarks/RESULTS.md]
- Every real bug found while building this — six so far — is documented
  with root cause, fix, and how it was verified:
  [link to docs/FINDINGS.md]. I think a security tool should hold itself
  to the same "verify, don't just claim" standard it applies to traffic.
- OIDC integration was tested against a real Keycloak instance (not
  mocks) — caught a real bug where roles were being read from the wrong
  token (ID token vs access token), which would have broken RBAC on every
  stock Keycloak setup.

It's not trying to replace Cloudflare/Imperva at their scale, and it's not
trying to replace Keycloak/Auth0 — it integrates with your existing IdP
rather than reinventing one. Apache 2.0, self-hosted.

Repo: [link]. Feedback very welcome, especially on the WAF rule coverage —
I know it's not complete and I'd rather know where the gaps are.

---

## r/netsec

**Title:** `Rampart: self-hosted WAF + rate-limiting + OIDC RBAC gateway, benchmarked with GoTestWAF`

**Body:**

Built this because I wanted a single self-hosted tool covering
network/app/API-layer defense instead of assembling nginx + ModSecurity +
fail2ban + a separate OIDC plugin. Sharing here specifically because I
tried to hold it to a real verification standard rather than just shipping
and hoping:

- WAF layer is Coraza + OWASP CRS, independently benchmarked with
  GoTestWAF. Found and fixed a base64-evasion gap (CRS at default paranoia
  level doesn't decode base64 args before running SQLi/XSS detection —
  documented tradeoff on their end, but still a real bypass if you know to
  look for it). Numbers and methodology: [link]
- Credential-stuffing detection was tested against a real login endpoint,
  and testing surfaced a real lockout-evasion bug (interleaving a
  throwaway malformed request reset the failure counter) — fixed, with a
  regression test.
- OIDC/RBAC was verified against an actual Keycloak instance, full
  browser-driven Authorization Code + PKCE flow, not mocked. Found that
  Keycloak's default config puts realm roles on the access token, not the
  ID token — worth knowing if you're building anything similar.

Full findings log with root cause/fix/verification for every bug:
[link to docs/FINDINGS.md]. Genuinely interested in adversarial feedback
on the WAF rule coverage or the RBAC token validation logic
(`internal/oidcauth/rbac.go` and `internal/waf/`) — this is exactly the
kind of code where I'd rather get told about a flaw here than find out
some other way.

Apache 2.0. [repo link]

---

## r/selfhosted

**Title:** `Rampart – one binary for WAF + rate limiting + login-protected dashboard, in front of any app`

**Body:**

If you self-host anything and want real protection in front of it
(SQLi/XSS filtering, rate limiting, brute-force lockout on login
endpoints) without running five separate containers, this might be useful.

`docker compose up` gets you Rampart running in front of a demo vulnerable
app (OWASP Juice Shop) so you can see it actually blocking attacks and
watch the live dashboard fill in. Pointing it at your own app is a one-line
config change (`upstream: http://your-app:port`).

What it does:
- Blocks SQLi/XSS/common attack patterns (OWASP Core Rule Set)
- Rate limits and blocks IPs that hammer your login endpoint
- Live dashboard showing what got blocked and why (top attacker IPs,
  block reasons, timeline)
- Optional: if you already run Keycloak/Authentik/Auth0/etc., Rampart can
  require login to view the dashboard and enforce role-based access on
  specific routes of your app

Distroless Docker image, runs as non-root, Helm chart if you're on k8s.
Apache 2.0, no telemetry, nothing phones home.

[repo link] — happy to answer setup questions here.
