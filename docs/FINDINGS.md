# Findings: bugs and vulnerabilities found during development, and their fixes

This is a running log, kept alongside the code as Rampart is built, of every
real bug or vulnerability found in Rampart *itself* — not in a target app —
along with how it was found, the fix, and how the fix was verified. The
point of a firewall project is to catch attack patterns; it should hold
itself to the same standard rather than assuming its own logic is correct
because it compiles and the happy path works.

Entries are newest first.

---

## 15. CRS coverage probe: XXE and two template-injection syntaxes aren't blocked

**Found:** Wrote `scripts/test-crs-coverage.sh`, one standard canary per OWASP
CRS attack category (23 probes, all aimed at localhost), and ran it against
an isolated local instance at the default paranoia level (1). First run:
18 passed, 5 not blocked. Each of the five was investigated before being
called a gap, because "not blocked" can also mean "below the anomaly
threshold" or "my probe was wrong".

**What each one turned out to be:**
- **HTTP response splitting (CRLF): my probe's bug, not a gap.** `curl
  --data-urlencode` double-encoded the `%0d%0a` I passed, so the WAF saw
  literal text. With real CR/LF bytes the request is blocked (`403`). The
  script is fixed and carries a comment explaining it.
- **XXE: a real gap.** An XML body declaring an external entity
  (`<!ENTITY a SYSTEM "file:///etc/passwd">`) got `500`. That `500` is
  Juice Shop's, not Rampart's: Rampart logged no block and no error, and
  Juice Shop returns `500` for any XML body at that endpoint, even a
  benign `<x>test</x>`. So the request reached the app. CRS's request rules
  contain no rule that matches an `<!ENTITY` or `<!DOCTYPE` declaration at
  all. Inert on this demo (the app doesn't parse the XML), but it would
  matter for a target whose XML parser resolves external entities (file
  read, SSRF). **Correction, found while testing `waf.paranoia_level`:** at
  levels 2 and 3 this probe returns `403`, which looks like detection but
  isn't. The event log shows `Outbound Anomaly Score Exceeded`: the WAF
  blocked Juice Shop's *error response* (which trips CRS's response-leak
  rules), not the request. The request still reaches the app at every
  level, so the gap stands. It also shows a limit of this script: a `403`
  doesn't say whether the block was request-side or response-side.
- **`{% %}` and `<%= %>` template syntaxes: a real gap, and an incomplete
  fix of #9.** Both returned `200`. Only CRS rule 934180 matches them, and
  it is PL2-only; Rampart runs PL1. The custom rule I added for #9
  (`03-ssti-double-brace.conf`) only matches `{{ }}`, so Jinja2/Twig
  statement blocks and ERB/JSP/EJS expression tags are still open. #9
  fixed the syntax I tested and I called the category closed.
- **Bare `;id`: only caught at PL3.** A short command with no arguments
  passed (`200`) at levels 1 and 2 and is blocked (request-side) at level
  3. CRS does have PL1 rules aimed at short and no-argument commands
  (932235 "2-3 chars", 932340 "No Arguments"), yet neither caught this
  probe; the PL3 rules (932237, 932301) are the likely ones, but I didn't
  confirm which rule fires. Consistent with a false-positive tradeoff
  (words like `id` are common), though I haven't shown that is the reason.
  The `; cat /etc/passwd` form in `test-attacks.sh` is blocked at PL1.

**What passed (19):** TRACE method, scanner user-agent, response splitting,
both LFI probes, RFI, Windows command injection, Shellshock-style header,
PHP injection, Log4Shell lookups in both a parameter and a header, Java
class access, SSRF to the cloud metadata address, prototype pollution,
time-based SQLi, `javascript:` URI XSS, `${7*7}` (blocked by a CRS rule I
didn't identify), and the two sanity requests.

**The static picture behind it:** counting rules by their paranoia-level
tag in the vendored CRS v4.25.0 files, much of the rule set doesn't run at
PL1: RCE has 19 PL1 rules and 28 at PL2-3, SQLi has 20 at PL1 and 40 at
PL2-4, Java has 6 at PL1 and 8 higher. XSS is the other way (26 at PL1, 7
higher).

**Limits of this probe:** one canary per category, so a pass doesn't prove a
category is covered, and a fail isn't automatically a gap (CRS blocks at a
cumulative score, 5 by default).

**What `waf.paranoia_level` changes (added in response to this finding).**
The same 23 probes, local Juice Shop, today's code:
- **Level 1:** 19 pass, 4 not blocked (the four above).
- **Level 2:** 22 pass. Both template syntaxes are now blocked (CRS rule
  934180), and the XXE probe "passes" only via the response-side block
  described above. Only `;id` is still not blocked.
- **Level 3:** all 23 pass, `;id` included.

That isn't a free fix, because the cost is false positives: in a GoTestWAF
run at each level, the share of the 141 legitimate-text samples wrongly
blocked went from 9% at level 1 to 38% at level 2, 43% at level 3 and 100%
at level 4 (full table and caveats in `benchmarks/RESULTS.md`). So raising
the level closes the template gap, but at a cost most deployments won't
accept without tuning, which supports fixing known gaps with narrow custom
rules (as #9 did) rather than turning the dial up.

**The fix (both real gaps, at the default level):**
- **Template syntaxes:** `03-ssti-double-brace.conf` now also covers
  `{% ... %}` and `<% ... %>` / `<%= ... %>`, with the same narrow design as
  the `{{ }}` rule (an operator between two operands, a known dangerous
  primitive, or `import`/`include`/`extends` inside the tags), and it now
  inspects XML text values too.
- **XXE:** a check in the Go middleware (`internal/waf/waf.go`) that blocks
  an XML request body declaring an external general or parameter entity,
  logged as a normal WAF block and respecting `mode: detect`. It's in Go, not
  a SecLang rule, because a rule can't be written for it: tested directly,
  for an XML body `REQUEST_BODY` and `REQUEST_BODY_LENGTH` are empty (they
  work for a form body) and the parser exposes only text values, so the
  DOCTYPE is unreachable. My first attempt, a SecLang rule, blocked nothing
  and the tests caught it.

**A second mistake the tests caught:** my first template regex tried to skip
an opener's marker character (`<%-`) by "consuming it first", but the regex
engine just matched the `-` as an operator instead, wrongly blocking the
benign `<%- name %>`. Fixed by requiring an operator to sit between two
operands; the benign case is now a test.

**Verified, with the real binary against Juice Shop at level 1:**
- Coverage probe: 22 of 23 pass (was 19). XXE and both template syntaxes are
  blocked, and the XXE block is logged request-side with its own reason.
  The one miss is bare `;id` (level 3 only, above).
- Core attack suite (`test-attacks.sh`): 14 of 14, no regressions.
- GoTestWAF at level 1: legitimate samples passed 90.78%, identical to
  before, so no new false positives on that set; application-security
  detection 56.21% to 56.97%, overall 65.32% to 65.51%.
- Unit tests load the real shipped rules and cover both sides: blocked
  (`{% print 7*7 %}`, `<%= 7*7 %>`, `{% import os %}`, external, parameter
  and PUBLIC entities, lowercase keywords) and left alone (`{{user.name}}`,
  `use {% tags %} in Jinja`, `<%- name %>`, `100% sure`, plain XML, an XHTML
  doctype with no entity), plus detect mode for XXE.

**Not covered, stated plainly:** an internal entity (`<!ENTITY a "text">`,
the "billion laughs" shape), XML in an encoding the WAF doesn't decode
(e.g. UTF-16), and bare `;id` below level 3. The real defense against XXE is
disabling external entities in the application's XML parser.

**Status:** fixed at the default level, except for the limits above.

---

## 14. The README and roadmap claimed geo-blocking, which doesn't exist

**Found:** While reviewing what a stranger sees on the repo's front page,
the README's scope list read "IP allow/deny lists, rate limiting,
geo-blocking, connection-flood mitigation", and `docs/ROADMAP.md` listed
the same as shipped in phase 1. `grep -rniE "geo|maxmind|country"` over
the Go code, configs and docs found no implementation: the IP filter is
CIDR allow/deny only, there is no GeoIP database or lookup anywhere.
Geo-blocking was in the original plan and was never built; the docs kept
describing the plan as if it were the product.

**Impact:** not a security hole, a credibility one. Someone evaluating a
security tool who checks a headline feature and finds it missing will
reasonably discount everything else. The "connection-flood mitigation"
wording was also generous for what existed at the time (per-IP rate and
concurrency limits).

**The fix:** README and roadmap now describe what is implemented (per-IP
rate and concurrency limits, read/idle timeouts, real-client-IP
resolution, optional TLS termination), and say plainly that geo-blocking
and volumetric DDoS protection are not implemented. The roadmap phase-1
row keeps the history: geo-blocking was planned, not built.

**Verified:** a repo-wide search for geo-blocking terms found exactly two
places that claimed it (the README scope list and the roadmap's phase-1
row). Both now say it is not implemented; the only remaining mentions are
those honest ones.

**Why it's logged here:** the rest of this file is bugs found by testing
behavior. This one was found by reading the docs as a skeptical reader
would, and it's the same class of problem (the tool not matching its own
description) one level up.

---

## 13. No read or idle timeouts: a slow client could hold connections open forever

**Found:** Same network-layer review as #12. `cmd/rampart/main.go` set
only `ReadHeaderTimeout` (10s) on both `http.Server`s. With `ReadTimeout`
and `IdleTimeout` unset, nothing bounded how long a client could take to
send a request body, or how long an idle keep-alive connection stayed open.

**Impact:** availability only, not a data-exposure bug. A client that sends
valid headers promptly and then drips the body (slowloris-style), or opens
many connections and goes quiet, ties up connections indefinitely. The
per-IP limits don't substitute for dropping stalled connections: an idle
keep-alive socket isn't a request at all, a set of slow clients spread
across many IPs stays under any per-IP cap, and none of this is a
request-content attack the WAF can see.

**Verified before fixing**, with the real binary and a raw-socket client:
a connection that sent headers promising 1000 body bytes then sent one, and
a keep-alive connection that finished a request then went silent, were both
still open after 8 seconds with no limit anywhere.

**The risk checked before fixing:** a naive `ReadTimeout` can interact badly
with a reverse proxy and a server-sent-events dashboard. Tested in isolation
first: with `ReadTimeout` at 2s, a handler that responds after 5s completed
normally and its request context was not canceled. Go applies the read
deadline to reading the request, not to how long the response takes.
`WriteTimeout` is a different story (it would cut off long responses and
the dashboard stream), so there is deliberately none.

**The fix:** `server.read_timeout` (default 60s, whole request including
body) and `server.idle_timeout` (default 120s), `0` disables, applied to
both the proxy and dashboard listeners.

**Verified after**, same binary and probes with both set to 3s: the
slow-body connection and the idle connection were both closed by the
server. Regression checks with `read_timeout` at 3s: a 5-second upstream
response through Rampart still returned `200`, and the dashboard's
`/api/stream` stayed open for the full 8 seconds. Full test suite, vet and
gosec clean. Helm and k8s manifests need no change; the defaults apply
when the section is absent.

**Behavior change worth knowing:** the 60s default means a single request
that takes longer than that to *upload* is now cut off. Raise
`read_timeout` (or set it to `0`) for large uploads over slow links.

**Known wart, not fixed:** a client cut off mid-body gets a `502` and an
"upstream error" log line, because the proxy's error handler reports every
failure that way. The connection is closed either way; `408` would be more
accurate.

---

## 12. Behind a load balancer, every client looked like the same IP

**Found:** Asked "can we do more at the network layer?" and checked how
Rampart identifies clients. `grep -rn "RemoteAddr\|X-Forwarded"` showed
the rate limiter, brute-force lockout, WAF, RBAC and schema layers each
derive the client IP from `r.RemoteAddr` alone, and nothing reads
`X-Forwarded-For`. That's right for a directly exposed Rampart. It's wrong
for the deployment modes this repo documents: behind a cloud load
balancer, an Ingress controller (the Helm and `kubectl apply` paths), or a
CDN, `RemoteAddr` is the proxy, for every user.

**Impact:** per-IP features collapse into one global bucket. One attacker
tripping the login lockout locks out every legitimate user; the per-IP
rate limit becomes a single shared limit; `firewall.deny` can only ever
block the proxy itself, and the event log and dashboard attribute all
traffic to one "attacker IP".

**Verified before fixing**, with a real binary and a stub upstream that
always returns 401 (lockout after 2 failures): client A (header
`X-Forwarded-For: 203.0.113.1`) failed twice and was locked out. Client B
(`203.0.113.2`), a different user who had never failed once, was locked
out on their first attempt: `429`.

**The fix:** a `trusted_proxies` allowlist and an outermost middleware
(`internal/realip`) that rewrites `r.RemoteAddr` to the real client, so
every layer is fixed without touching five call sites. The header is
honored only when the direct peer is a listed proxy; the chain is walked
right to left, skipping trusted hops, and the first untrusted address is
the client. Trusting the header from anyone would be its own
vulnerability (a client could pick its own IP to dodge lockouts), hence
an allowlist and not a switch. Empty by default, which is a no-op, so
direct-exposure deployments are unchanged. Applied to both the proxy and
the dashboard listener, and wired into the Helm chart and k8s manifests.

**Verified after:** same scenario with the proxy trusted: A locked out on
the third attempt, B's first attempt `401`, tracked separately. With
`trusted_proxies` set to a range that doesn't include the peer, the
header was ignored and B was locked out again, so a spoofed header buys
nothing. 11 unit tests cover trusted/untrusted peers, a spoofed leftmost
entry, multiple trusted hops, all-trusted chains, malformed or missing
headers, multi-line headers, IPv6 and bare-IP entries. `go vet`, full
test suite and gosec clean; `helm lint` and `helm template` pass with and
without the new value.

**Not covered:** only `X-Forwarded-For`; the standardized `Forwarded`
header, `X-Real-IP` and PROXY protocol aren't read. This assumes a trusted
proxy appends the address it saw to `X-Forwarded-For` (standard for
cloud load balancers and Ingress controllers). One that forwards a
client-supplied header untouched, without appending, would let clients
spoof; list only proxies you control.

---

## 11. OIDC RBAC guard: same path-case bypass, but on the authorization layer

**Found:** Immediately after fixing finding #10 - rather than stopping at
two fixed instances, checked whether the same `strings.HasPrefix`
case-sensitivity pattern had been copy-pasted anywhere else.
`grep -n "HasPrefix" internal/oidcauth/*.go` found a third, independent
implementation in `internal/oidcauth/rbac.go`'s `match()`, structurally
identical to the two already fixed.

**The bug, and why it's more severe than #10:** `RBACGuard.Middleware`
calls `g.match(r)`; if no rule matches, it calls `next.ServeHTTP(w, r)`
directly - **no token verification, no role check, nothing.** Findings
#10's two bugs skipped *abuse detection* layers (brute-force lockout,
mass-assignment validation) - a meaningful gap, but the request still had
to be independently valid to do anything. This one skips *authorization
itself*. A route configured with `path_prefix: /admin` and
`required_roles: [admin]` provides **zero protection** against a request
to `/Admin/dashboard` - no bearer token required at all, regardless of
role.

**Verified with a regression test against the real mock-OIDC test harness
(not curl against a live instance this time - the existing test
infrastructure here, a real JWT-signing mock provider with discovery +
JWKS, made this the more precise way to prove it):** wrote
`TestRBACPathPrefixMatchIsCaseInsensitive` first, confirmed it failed
against the unfixed code - a request to `/Admin/dashboard` with **no
Authorization header at all** returned `200`, not `401`. Then applied the
fix and confirmed it now correctly returns `401` with no token, and `403`
for a valid token missing the required role, on both `/Admin/dashboard`
and `/ADMIN/dashboard`.

**The fix:** identical to finding #10 - lowercase both sides of the
comparison in `rbac.go`'s `match()`. Same root cause (Express's default
case-insensitive routing vs. Go's case-sensitive `strings.HasPrefix`),
same one-line fix, now applied in all three places that independently
implement path-scoped rule matching.

**Verified:** `go build`, `go vet`, and the full `internal/oidcauth` suite
pass (18 tests, including the new one and all 6 pre-existing RBAC tests
unchanged). `gosec ./internal/oidcauth/...`: 0 issues. Worth noting what
this finding is really about: the first fix (#10) wasn't "done" just
because two call sites were patched - the underlying *pattern* (rolling
your own case-sensitive path matching) needed checking everywhere it
might have been duplicated, and it had been, a third time, in the most
security-sensitive place of the three.

---

## 10. API-abuse and schema validation: path-case bypass skips both layers

**Found:** Deliberate adversarial pass after closing finding #9 - looked
for the next class of bug rather than waiting for the test suite to trip
over one. `internal/apiabuse/apiabuse.go` and `internal/schema/schema.go`
both scope their rules by `path_prefix`, matched with
`strings.HasPrefix(req.URL.Path, r.PathPrefix)`. Go's `strings.HasPrefix`
is case-sensitive. Juice Shop (and most Node/Express targets) is not:
Express's default `case sensitive routing` setting is `false`, so
`/REST/User/Login` reaches the exact same handler as `/rest/user/login`.
That mismatch means a request whose path case doesn't literally match the
configured `path_prefix` skips the rule entirely, while the protected app
processes it normally.

**The bug, verified on an isolated local instance (fresh Juice Shop +
freshly built image, not the shared live demo - its per-IP counters were
already contaminated by a full day of testing and gave noisy, hard-to-read
results):**
- Mass-assignment payload (`isAdmin: true`) to `/rest/user/login` →
  `400`, correctly blocked by schema validation. The identical payload to
  `/REST/User/Login` → `401` - schema validation never ran, and Juice
  Shop itself processed the request and returned its own real auth
  failure. Confirmed `403` still fires for WAF-layer attacks (SQLi) via
  the same uppercase path, isolating the bug to the two path-scoped
  layers specifically, not a general case bug.
- Brute-force lockout: 6 straight failed logins to `/REST/User/Login`
  (fresh IP-state) → `401` every time, never the `429` that a 6th failure
  triggers reliably against `/rest/user/login` (verified back-to-back on
  the same fresh instance, same IP, only the path case differed).

**Impact:** a trivial, one-character path-case change fully bypasses both
credential-stuffing lockout and mass-assignment/request-shape validation
- two of Rampart's four detection layers - while looking, from the
attacker's side, identical to a normal request against the real app. The
WAF layer is unaffected since Coraza's rules aren't scoped by
`path_prefix` at all; they apply to `ARGS`/`REQUEST_BODY` regardless of
path.

**The fix:** Lowercase both sides of the comparison in each `matches()`
function (`apiabuse.go` and `schema.go` - same root cause, same fix,
applied identically in both). Deliberately kept as a plain
`strings.ToLower` comparison rather than a shared helper or a
precomputed-lowercase cache field, matching the existing code's style;
this isn't a hot enough path to justify the extra abstraction.

**Verified:** Rebuilt, reran the exact same isolated-instance comparison:
mass-assignment now `400` regardless of case (`lowercase`, `UPPERCASE`,
and `MiXeD` all tested); 6 uppercase-path failures now correctly trip
`429` on the 6th, same as lowercase; a lowercase request against an
already-uppercase-tripped lockout also correctly gets `429` - confirming
the fix unifies state across case variants rather than just patching one
direction. All existing unit tests in both packages still pass unchanged
(`TestBlocksAfterMaxFailures`, `TestIsolatedPerIP`,
`TestUnexpectedFieldRejected`, etc.). Full `scripts/test-attacks.sh`
suite on a completely fresh instance: 14/14.

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

**Root cause, precisely:** OWASP CRS v4 does ship an SSTI-adjacent rule
(`934180` in `REQUEST-934-APPLICATION-ATTACK-GENERIC.conf`), but two
things make it not apply here — confirmed by reading the actual vendored
rule source in the Go module cache
(`coraza-coreruleset/v4@v4.25.0`), not assumed:
1. It's gated to paranoia level 2 (`tag:'paranoia-level/2'`); Rampart
   runs at CRS's default, PL1, so the rule isn't even active.
2. Even at PL2, its regex (`\{%[^%}]*%}|<%=?[^%>]*%>`) only matches
   `{% ... %}` and `<% ... %>` - it does not match bare `{{ ... }}` at
   all, which is the single most common SSTI proof-of-concept syntax
   (Jinja2/Twig/Mustache/Handlebars) and exactly what `{{7*7}}` uses.

**The fix:** A targeted custom rule
([`configs/waf-custom-rules/03-ssti-double-brace.conf`](../configs/waf-custom-rules/03-ssti-double-brace.conf)),
same anti-evasion pattern as finding #2's base64 rule - narrow on
purpose. It requires an arithmetic operator (`+-*/%`) or a known
reflection/RCE primitive (`__class__`, `__import__`, `self.`, `config.`,
`request.`, `constructor.`, `exec(`, `system(`, `popen(`, `__proto__`)
inside the double braces, not just any `{{...}}` - so a legitimate
Angular/Vue-style template string or plain `{{user.name}}` in submitted
text has neither and passes through untouched. Active regardless of
paranoia level, matching how the base64 rule is also PL-independent.

**Verified:** Built the image locally (had to fall back to
`DOCKER_BUILDKIT=0 docker build` - `docker compose build`'s buildx bake
path hit an unrelated local permissions error on this machine) and ran it
against an isolated Juice Shop container.
- True positives, all `403`: the original `{{7*7}}`, plus
  `{{7*'7'}}`, `{{ self.__class__ }}`, `{{ config.items() }}`.
- False-positive checks, all `200`: `{{user.name}}`, `{{laptop}}`,
  and empty `{{ }}`.
- Normal traffic (`/`, a plain search) unaffected, still `200`.
- Full `scripts/test-attacks.sh` suite re-run against the fixed local
  instance: 14/14 passed, including this one - previously 13/14 with
  this as the sole failure.

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
