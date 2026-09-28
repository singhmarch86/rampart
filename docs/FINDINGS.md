# Findings: bugs and vulnerabilities found during development, and their fixes

This is a running log, kept alongside the code as Rampart is built, of every
real bug or vulnerability found in Rampart *itself* — not in a target app —
along with how it was found, the fix, and how the fix was verified. The
point of a firewall project is to catch attack patterns; it should hold
itself to the same standard rather than assuming its own logic is correct
because it compiles and the happy path works.

Entries are newest first.

---

## 9. WAF: server-side template injection payloads pass through unblocked

**Found:** Writing `scripts/test-attacks.sh` — a one-shot suite covering
one payload per vulnerability class, meant to be runnable against either a
local instance or the live public demo, complementing the continuous
`scripts/demo-traffic.sh` generator. Run live against the public demo
(`http://34.29.169.231:8080`), a bare SSTI probe (`{{7*7}}` on the search
endpoint) came back `200` instead of the `403` every other category in the
suite got. Re-checked directly with `curl` (not just the script) to rule
out a script bug before trusting the result — repeatable, not a fluke.

**The gap:** OWASP CRS at the paranoia level this demo runs has no rule
that recognizes a bare `{{ expression }}` pattern as an attack signature —
unlike SQLi/XSS/path traversal/command injection/NoSQL/LDAP injection,
which CRS's core rule set does cover natively, and unlike the base64-SQLi
case (finding #2), this isn't an encoding-evasion problem on top of
existing coverage — there's no base rule to evade around in the first
place. Not exploitable *on this specific demo* (Juice Shop's search
endpoint doesn't feed the query into a template engine, so the payload is
inert here), but the WAF layer itself doesn't recognize the pattern, which
would matter against a real target that does use a server-side template
engine (a real, common vulnerability class — Jinja2, Freemarker,
Thymeleaf, Velocity, etc. have all had real-world SSTI CVEs leading to
RCE).

**Status: documented, not yet fixed.** Left as a known, verified gap
rather than silently working around it in the test script (the check
stays in `scripts/test-attacks.sh` with an inline comment, and is expected
to legitimately fail until this is addressed) or overclaiming it's
covered. A fix would look like finding #2's: a targeted custom SecLang
rule matching template-expression syntax across the handful of common
engines, verified against both true positives and legitimate-looking
`{{`/`}}`-containing input (Angular/Vue template literals in a request
body, for instance) before shipping.

**Verified:** Confirmed independently outside the test script (`curl -G
--data-urlencode 'q={{7*7}}' http://34.29.169.231:8080/rest/products/search`
→ `200`, repeated on a fresh request after the demo had otherwise settled)
and ruled out rate-limiting/lockout interference as the cause (a separate,
unrelated timing issue hit the *same test run* — see the script's pacing
comment — but the SSTI result was 200 both under load and after slowing
requests down, so it isn't that).

---

## 8. Rampart had never pointed a scanner at its own Go source

**Found:** All seven findings above came from behavioral testing — a WAF
benchmark, a live login flow against real Keycloak, driving a real browser.
None came from static analysis or dependency scanning of Rampart's own
code, which is a real gap for a security tool to have. Ran `govulncheck`
(known CVEs, filtered to ones actually reachable from Rampart's call
graph) and `gosec` (Go-specific security anti-patterns) for the first time.

**govulncheck: 7 reachable vulnerabilities, all in the Go standard library
itself** (`net/url` quadratic-complexity, `crypto/tls` post-handshake and
ECH issues, `net/http` missing `ReadHeaderTimeout` on the HTTP/2 upgrade
path, `encoding/xml` and `encoding/asn1` missing recursion-depth guards,
and a `golang.org/x/net/idna` Punycode-validation gap) — every one already
fixed in a later Go/module patch release; this was a stale toolchain and a
stale `golang.org/x/net`, not a code bug.

**gosec: 7 findings, of which 2 were real and 5 were false positives**
gosec can't statically resolve whether a file path or a boolean came from
a request or from the operator's own config — it flags both the same way:
- **Real: `internal/events/events.go` opened its event log at `0o644`.**
  That file records attack traffic detail (source IPs, request paths);
  tightened to `0o600`.
- **Real: `internal/proxy/proxy.go`'s error handler logged
  `r.Method`/`r.URL.Path` with `%s` (CWE-117, log injection).**
  `r.URL.Path` is already percent-decoded, so a request path like
  `/foo%0d%0aFAKE-LOG-LINE` arrives containing a literal CR/LF — logged
  with `%s` that forges a second, fake log line in whatever reads
  Rampart's stdout/stderr. Switched to `%q`; verified with a standalone
  repro that `%q` renders an embedded `\r\n` as the two-character escape
  sequence `\r\n` in the output, not a real line break.
- **False positive (G124, ×2):** `internal/oidcauth/session.go`'s two
  `http.Cookie` literals already set `HttpOnly: true`, `Secure: sm.secure`,
  and `SameSite: http.SameSiteLaxMode` — gosec flags this because
  `sm.secure` is a field read, not a literal `true`, and can't statically
  verify `NewSessionManager` always sets it `true` outside tests.
- **False positive (G304, ×3):** `internal/config/config.go`'s config-file
  path, `internal/events/events.go`'s log path, and
  `internal/waf/waf.go`'s custom-rules directory are all operator-supplied
  (CLI flag or config file) at process startup, never from a request —
  gosec's path-traversal check can't distinguish that from a genuinely
  attacker-reachable path.

All five false positives are suppressed with an inline `#nosec` comment
naming the specific rule and explaining why, rather than disabling the
rule wholesale — so a *new* G304/G124 finding elsewhere still surfaces.

**The fix:**
- `go get go@1.26.6` (auto-upgraded further to `go1.26.8`) and `go get
  golang.org/x/net@latest` to clear the standard-library and dependency
  CVEs.
- `0o600` file permission for the event log
  ([internal/events/events.go](../internal/events/events.go)).
- `%q` instead of `%s` for request-derived values in the proxy's error log
  ([internal/proxy/proxy.go](../internal/proxy/proxy.go)).
- Five `#nosec`-annotated false positives, each with an inline reason.
- Added a `security` job to CI (`.github/workflows/ci.yml`) running both
  scanners on every push, so this doesn't silently regress.

**Verified:** `govulncheck ./...` → "No vulnerabilities found." `gosec
./...` → 0 issues, 6 nosec (5 suppressions plus the log-injection line,
which carries its own suppression once the `%q` fix was verified). `go
build`, `go vet`, and `go test -race ./...` all pass unchanged.

---

## 7. Dashboard server had no rate limiting of its own

**Found:** During a deliberate hardening pass (not live-triggered by a test
failure this time) — reviewing `cmd/rampart/main.go` side by side with
`internal/proxy/proxy.go` while implementing RP-initiated logout made the
asymmetry obvious: the main proxy chain wraps every request in
`ratelimit.Middleware` (and IP filtering), but the dashboard's `http.Server`
was just `Handler: dashboardHandler` — nothing in front of it at all.

**The bug:** Anyone who could reach the dashboard port — including,
notably, `/auth/login` and `/auth/callback` once OIDC dashboard auth is
enabled — had no rate limiting whatsoever. Bound to `127.0.0.1` by default
this is low-severity, but the documented escape hatch (putting an
authenticating reverse proxy in front and exposing it more broadly) had no
safety net under it if someone forgot this specific gap, and it's exactly
the kind of asymmetry that's easy to introduce by adding a second
`http.Server` without threading it through the same middleware discipline
as the first.

**The fix:** Extracted the proxy's rate-limiting middleware into a reusable
`ratelimit.Middleware` (also removing duplicated `clientIP`/`withRateLimit`
logic from `internal/proxy/proxy.go` in the process), added a
`dashboard.rate_limit` config section with its own sane defaults (5 req/s,
burst 10, 10 concurrent — enough for normal dashboard use plus the SSE
event stream, tight enough to matter), and wired it as the outermost
wrapper on the dashboard handler so it covers `/auth/*` and the analytics
routes equally.

**Verified:** Rebuilt and fired 15 rapid requests at the dashboard root —
first 10 passed (matching the configured burst), the next 5 got 429, and
the event log correctly attributed them to a new `dashboard-ratelimit`
layer, distinguishable from the main proxy's `ratelimit` layer in the same
event stream.

---

## 6. OIDC dashboard login: roles read from the wrong token

**Found:** During the OIDC/RBAC feature build, via live testing against a
real Keycloak instance (not a mock) — set up a real realm, client, role,
and user, then drove the actual browser-based Authorization Code + PKCE
login flow. The dashboard denied a user who genuinely had the required
role, with the log reason "authenticated but missing required dashboard
role" despite the role assignment being correct.

**The bug:** Dashboard login extracted roles from the **ID token**'s
claims. Keycloak's default "roles" client scope mapper adds
`realm_access.roles` to the **access token**, not the ID token — decoding
a real token confirmed the ID token had no `realm_access` claim at all.
This is correct, standard OIDC hygiene on Keycloak's part (the ID token
describes who authenticated; the access token describes what they can
do), but it meant role-based access control was reading a token that
structurally couldn't have the claim, so it would have failed for
literally every user, on any stock Keycloak setup, indefinitely.

**The fix:** Added a second verifier for the access token specifically
(`SkipClientIDCheck: true`, since Keycloak's default access-token audience
is `"account"`, not the OIDC client ID) and extract roles from it, while
still using the ID token for identity/nonce verification — that part *is*
what the ID token is for.

**Verified:** Confirmed by decoding a real Keycloak-issued ID token and
access token side by side (only the access token had `realm_access`), then
rebuilt and re-ran the full browser login flow against the same live
Keycloak instance — role check passed, dashboard rendered. Added two
regression tests
(`TestDashboardCallbackExtractsRolesFromAccessTokenNotIDToken` and a
companion negative test confirming denial still works when the role is
genuinely absent) using a mock OIDC provider with a real `/token` endpoint,
so this can't regress silently.

---

## 5. Docker: event log write fails with "permission denied" in the container

**Found:** Phase 5 (cloud-native packaging), while testing the Docker image
with event logging enabled — not caught by inspection, only by actually
running the built image.

**The bug:** The distroless `nonroot` base image runs the process as UID
65532, but `COPY` in a Dockerfile sets root ownership on copied files
*regardless* of the base image's configured `USER` — that's a build-time
operation, not something that inherits the runtime user. `/app` (and the
default `events_path: "rampart-events.jsonl"`, resolved relative to that
WORKDIR) was root-owned with no write access for the nonroot user. Any
deployment with the default config and event logging enabled would fail at
startup:
```
events logger: open /app/rampart-events.jsonl: permission denied
```
This would have been especially easy to miss because `docker build` and a
quick `docker run` with logging *disabled* both succeed cleanly — the bug
only surfaces once someone turns on the feature the whole dashboard depends
on.

**The fix:** Separated a dedicated `/data` directory, created and `chown`'d
to UID 65532 in the builder stage, then copied into the final stage with
`--chown=65532:65532`. `/app` stays root-owned and read-only (deliberate for
a distroless security tool); `/data` is the only writable path, declared as
a `VOLUME` so it's easy to persist. The image's baked-in default config is
now generated at build time (via `sed` in the builder stage, which has a
shell) to point `events_path` at `/data/rampart-events.jsonl` instead of the
local-binary-appropriate relative path in `configs/rampart.example.yaml`.

**Verified:** Rebuilt, ran the image with the default config, confirmed no
fatal error and the process stayed up (previously it exited immediately).
Confirmed definitively with `docker cp` pulling `/data/rampart-events.jsonl`
out of the running container (distroless has no shell/exec, so this was the
way to check rather than `docker exec ls`).

---

## 4. Dashboard: directory listing instead of the actual page

**Found:** Phase 4 (analytics dashboard), during live browser verification —
the first screenshot showed a bare `dashboard.html` link instead of the
dashboard.

**The bug:** `http.FileServer(http.FS(sub))` mounted at `/` only
auto-serves a file literally named `index.html`; our embedded file was
named `dashboard.html`, so requests to `/` fell through to FileServer's
directory-listing behavior instead.

**The fix:** Replaced the FileServer mount with a direct handler that
writes the embedded `dashboard.html` bytes for `/` and 404s everything else
— simpler and more explicit than renaming the file to fit FileServer's
convention.

**Verified:** Reloaded the dashboard in the browser pane, confirmed the
actual UI rendered; then generated live traffic and confirmed Server-Sent
Events updates worked end to end.

---

## 3. API-abuse guard: failure-streak reset let attackers dodge lockout

**Found:** Phase 3 (API/mobile-backend abuse detection), during live manual
testing against Juice Shop's real login endpoint — a credential-stuffing
block test produced a different number of attempts-before-block than
expected, which prompted a closer look rather than just shrugging it off as
"close enough."

**The bug:** The guard reset an IP's failure streak on **any** response that
wasn't a configured failure status code — including a 400 from the schema
validator (a different Rampart layer entirely). An attacker could interleave
one real credential guess with one throwaway malformed request (guaranteed
400, costs nothing) to keep resetting their failure count and dodge the
lockout indefinitely. This is a real, practical evasion technique, not a
theoretical one — it directly undermines the one feature whose entire job is
stopping credential stuffing.

**The fix:** Only a genuine 2xx success now resets the streak. Anything else
— a 400, a 403 from the WAF, a 404 — is left untouched rather than treated
as an implicit "this attempt didn't count against you."

**Verified:** Added a regression test
(`TestNonFailureNonSuccessDoesNotResetStreak`) covering the exact scenario,
then re-ran the live test against Juice Shop interleaving real failed
logins with malformed requests designed to trigger the old reset path —
confirmed the block now triggers on the 5th real failure regardless of what
runs between them.

---

## 2. WAF: 0% block rate on base64-encoded attack payloads

**Found:** Phase 2 (application WAF), via an independent benchmark
(GoTestWAF, an open-source WAF evaluation tool) — not something that would
have been discovered by manual testing, since nobody manually thinks to
try every encoding variant of every payload category.

**The bug:** OWASP CRS at the default paranoia level does not blindly
base64-decode every request argument before running SQLi/XSS detection —
deliberately, since decoding everything would cause false positives on
legitimate base64 data (JWTs, image data URIs, uploads). But that tradeoff
means a trivially base64-encoded attack payload sails through untouched:
235 out of 235 Base64Flat-encoded attack payloads in the benchmark bypassed
detection completely.

**The fix:** Added a targeted custom SecLang rule
(`configs/waf-custom-rules/02-anti-evasion-base64.conf`) that decodes each
argument/body with `base64DecodeExt` and re-runs the *same*
`@detectSQLi`/`@detectXSS` operators CRS itself uses on the decoded value —
narrow by design, so it only fires when a value is both valid-looking
base64 **and** decodes to something matching a known attack signature.

**Verified:** Sanity-checked directly (harmless base64 passes, base64-
encoded SQLi blocked), then re-ran the full GoTestWAF suite: overall score
63.12% → 65.25%, Base64Flat block rate 0% → 24%, and — the number that
actually matters for a fix like this — the false-positive rate held exactly
steady (90.78% true-negative, unchanged), meaning more attacks were caught
without the WAF becoming trigger-happy on legitimate traffic. Full numbers
in [`benchmarks/RESULTS.md`](../benchmarks/RESULTS.md).

---

## 1. (Reference) The gaps this whole exercise is built around

Not a Rampart bug — the starting motivation. Common vulnerability classes in
real applications (banking apps in particular) that a firewall layer like
Rampart is meant to catch even when the application code has bugs:
IDOR/BOLA, client-side transaction tampering, weak OTP/session handling,
credential stuffing, and mass-assignment via unexpected request fields.
Phases 2 (WAF), 3 (API abuse + schema validation) directly target these.
See the banking-app vulnerability discussion earlier in this project's
history for the full breakdown and the legal practice targets
(InsecureBankv2, Damn Vulnerable Bank) used to validate against.
