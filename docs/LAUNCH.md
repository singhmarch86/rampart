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
- Every real bug found while building this — eight so far — is documented
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

---

## LinkedIn

**Body:**

I built a self-hosted firewall from scratch — then spent as much time
trying to break it as building it.

Rampart sits in front of a web app and blocks attacks in real time — SQL
injection, XSS, credential stuffing, malformed requests — as one binary
with one config file, instead of stitching together nginx + ModSecurity +
fail2ban + a log pipeline + a dashboard.

The part I'm actually proud of isn't the feature list. It's this:

→ Benchmarked independently with GoTestWAF — not a self-reported number.
Found a real gap: 0% block rate on base64-encoded attack payloads. Fixed
it with a targeted rule. Re-benchmarked: 63.12% → 65.25%, false-positive
rate held exactly steady.

→ Every real bug found during development — 8 so far — is logged publicly
with root cause, the fix, and how it was verified. Including one where an
attacker could dodge a brute-force lockout by interleaving one real login
guess with a throwaway malformed request.

→ Then I pointed govulncheck and gosec at Rampart's own source for the
first time and found a log-injection bug in my own error handler.

Most self-hosted security tools ask you to trust a README. I'd rather show
the log of everything that was wrong and how it got fixed.

Open source, Apache 2.0. [link]

#buildinpublic #appsec #opensource

---

## LinkedIn — ModSecurity comparison

**Body:**

"How does your WAF compare to X?" is usually unanswerable honestly —
published WAF benchmark numbers online are mostly AI-generated SEO junk
that don't even match how vendors name their own products. So instead of
citing someone else's number, I ran the comparison myself.

Rampart's WAF layer is Coraza — a from-scratch Go reimplementation of
ModSecurity, the original open-source WAF engine that the OWASP Core Rule
Set was actually built for. I benchmarked both, same tool (GoTestWAF), same
target app, same ruleset, same paranoia level — the only variable was the
engine.

                        Overall   True-positive   False-positive rate
ModSecurity (bare)       63.27%      48.20%            9.22%
Rampart (baseline)       63.12%      47.63%            9.22%
Rampart (+ custom rule)  65.25%      55.93%            9.22%

ModSecurity vs. Rampart's baseline is within noise of each other — meaning
Coraza's reimplementation of the ModSecurity engine is faithful to the
original, not a degraded copy. The ~2-point gap to Rampart's final number
is real, measurable value from one targeted custom rule (closing a
base64-encoding evasion gap both engines share by default at paranoia
level 1) — and the false-positive rate held exactly steady while it
closed, which is the number that actually matters: more attacks caught
without the WAF getting trigger-happy on legitimate traffic.

But the score gap actually understates the comparison. This benchmark
isolates the WAF layer only — rate limiting and IP filtering were off for
both runs. So ModSecurity's 63.27% is its *entire* product at this layer:
bare, nothing else. Rampart's 65.25% is one layer of a product that also
ships credential-stuffing detection, request-schema validation, rate
limiting, and a live analytics dashboard. Matching that around a
ModSecurity core means separately bolting on fail2ban, a rate limiter, and
a log pipeline — the exact "five tools stitched together" problem I built
Rampart to avoid in the first place.

Full numbers, reproduction steps, and the raw methodology:
[link to benchmarks/RESULTS.md]

Open source, Apache 2.0. [repo link]

#buildinpublic #appsec #opensource #waf

---

## LinkedIn series — one real bug per post

A content-calendar set, one post per entry in `docs/FINDINGS.md`. Each is
a real bug found in Rampart's own code, not a target app — root cause,
fix, and how it was verified, pulled directly from the findings log. Post
these spaced out (a few days apart), not all at once — they read better
as an ongoing series than a dump.

### Post: the credential-stuffing bypass (finding #3)

I built a feature specifically to stop credential stuffing — then found a
way around my own defense while testing it.

The rule: 5 failed logins from one IP in a minute → blocked for 5 minutes.
Straightforward.

The bug: the failure counter reset on *any* non-success response, not just
a real failed login. So an attacker could interleave one real password
guess with one throwaway malformed request (guaranteed to fail
differently, costs nothing) — and the counter would reset before ever
hitting 5.

That's not a theoretical gap. It's a complete bypass of the one feature
whose entire job is stopping this exact attack.

The fix: only a genuine success resets the streak now. Everything else —
a 400, a 403, a 404 — gets left alone. Added a regression test for the
exact interleaving pattern so it can't come back silently.

Found by testing the feature adversarially, not by code review — the kind
of bug that only shows up when you try to break your own tool instead of
just checking it does the happy path.

Full writeup: [link to docs/FINDINGS.md#3]

#buildinpublic #appsec #opensource

---

### Post: the bug a screenshot caught (finding #4)

Sometimes the best bug-finding tool is just looking at the thing you
built.

Built the analytics dashboard, wired it up, took a screenshot to check it
looked right. Instead of the dashboard: a bare directory listing with one
link on it.

The cause: Go's `http.FileServer` only auto-serves a file literally named
`index.html`. My embedded dashboard file was named `dashboard.html`. One
character of mismatch, and instead of an error, you get a silently
"working" file browser instead of your actual app.

Fixed by writing a direct handler instead of leaning on FileServer's
naming convention. Simpler and more explicit anyway.

This is exactly why "verified live in a browser" is a real line in this
project's findings log, not decoration — a passing `go build` and a
clean `go vet` would never have caught this. Only looking at the actual
rendered page would.

[link to docs/FINDINGS.md#4]

#buildinpublic #appsec

---

### Post: the container that worked right up until it didn't (finding #5)

`docker build` — clean. `docker run` — starts fine. Enable the one
feature the whole dashboard depends on (event logging) — crashes
immediately with "permission denied."

Root cause: the Dockerfile's `COPY` sets root ownership on every file it
copies, *regardless* of the base image's configured non-root user. My
distroless image runs as UID 65532, but `/app` — including the default
event-log path — was root-owned with no write access for that user.

The nasty part: this would pass every quick sanity check. Build works.
Run works. Only fails once someone turns on the one feature that writes
to disk — which is also the feature the entire analytics story depends
on.

Fix: a dedicated `/data` volume, `chown`'d to the runtime UID in the
build stage, kept separate from the read-only `/app`.

Verified with `docker cp` pulling the log file out of a running
container — distroless has no shell, so that's the only way to actually
confirm a write succeeded rather than just "process didn't crash."

[link to docs/FINDINGS.md#5]

#buildinpublic #docker #appsec

---

### Post: the OIDC bug that would have broken RBAC for every user, always

Tested role-based access control against a real Keycloak instance (not a
mock) — and a user with the correct role kept getting denied.

The bug: I was reading roles off the **ID token**. Keycloak's default
config puts `realm_access.roles` on the **access token** instead — which
is actually correct, standard OIDC hygiene (ID token = who you are,
access token = what you can do). But it meant role checks were reading a
token that structurally could never have the claim.

This wasn't an edge case. It would have failed for every user, on any
stock Keycloak setup, indefinitely — the kind of bug that's invisible in
a unit test with mocked tokens and only shows up against the real thing.

Fixed by verifying the access token specifically for role extraction,
while still using the ID token for identity. Confirmed by decoding a real
Keycloak-issued token pair side by side — only one of them had the claim.

Two regression tests now cover this exact distinction so it can't
silently regress.

[link to docs/FINDINGS.md#6]

#buildinpublic #oidc #appsec

---

### Post: the security tool whose own dashboard had zero rate limiting

Found this one during a deliberate hardening pass, not a bug report:
comparing the main proxy chain against the dashboard's own server side by
side.

The main proxy: rate-limited, IP-filtered, every layer wired through.
The dashboard's `http.Server`: nothing in front of it at all. Including
`/auth/login` and `/auth/callback` once OIDC login is enabled.

Low severity in the default config (dashboard's bound to loopback only),
but it meant the documented escape hatch — putting an authenticating
proxy in front to expose it more broadly — had no safety net under it if
anyone forgot this specific gap.

Fixed by extracting the proxy's rate-limiter into something reusable and
wiring it onto the dashboard too, with its own tighter defaults (5 req/s
vs the main proxy's 10 — enough for normal use plus the live event
stream, tight enough to matter).

Verified by firing 15 rapid requests at the dashboard: 10 passed matching
the configured burst, the next 5 got 429'd, and it showed up as a
distinct `dashboard-ratelimit` layer in the event log.

[link to docs/FINDINGS.md#7]

#buildinpublic #appsec

---

### Post: I finally pointed a scanner at my own code

Seven bugs above — all found by testing Rampart's *behavior*: benchmarking
the WAF, driving real login flows, screenshotting the dashboard. None of
that touches Rampart's own source code for vulnerabilities.

So I ran `govulncheck` and `gosec` against it for the first time.

`govulncheck`: 7 CVEs, all in the Go standard library itself, none of
them code bugs — just a stale toolchain. Fixed with one `go get`.

`gosec`: 7 findings, 2 real.
→ The event log (records attack traffic — IPs, request paths) was
world-readable. Tightened to owner-only.
→ The proxy's error handler logged the raw request path with `%s`.
Since Go already URL-decodes that path, a crafted request like
`/foo%0d%0aFAKE-LOG-LINE` would land as a literal newline in the log —
letting an attacker forge a second, fake log line in my own output.
Switched to `%q`, which escapes it instead. Verified with a standalone
repro that it actually does.

The other 5 gosec findings were false positives — flagged and suppressed
with an inline comment explaining exactly why, not silenced with a
blanket rule disable.

Now wired into CI so this runs on every push, not just once.

[link to docs/FINDINGS.md#8]

#buildinpublic #appsec #golang

---

## LinkedIn — architecture thesis (not a bug post)

**Body:**

The pitch for Rampart in one sentence: don't reinvent proven security
engines, build the integration layer that's actually missing.

The WAF isn't a novel detection algorithm — it's Coraza running the OWASP
Core Rule Set, the same rules ModSecurity uses (verified: benchmarked
both, see the comparison post). The identity layer isn't a new auth
system — it's an OIDC relying party against whatever IdP you already run
(Keycloak, Auth0, Okta). Building either of those from scratch would be
a categorically riskier undertaking: a bug in a WAF means a missed
attack; a bug in a homegrown identity provider means account takeover
across every app that trusts it.

What's actually new is the integration: one binary, one config file, that
gets you WAF + rate limiting + credential-stuffing detection + schema
validation + OIDC RBAC + a live dashboard, instead of the realistic
alternative — nginx + ModSecurity + fail2ban + a separate OIDC gateway
plugin (Kong's is Enterprise-only) + a bolted-on Grafana pipeline, each
with its own config language and no shared view of an attack that spans
layers.

"Don't roll your own crypto/auth" is close to universal security advice.
I'd add: don't roll your own WAF signatures either, when a proven engine
and a well-maintained ruleset already exist. Spend the engineering effort
on the seams between tools instead — that's where the actual toil is.

[repo link]

#buildinpublic #appsec #softwarearchitecture

---

## LinkedIn — rampart-analyze

**Body:**

Added an offline companion tool to Rampart this week, and the interesting
part is what I *didn't* build.

The original idea: analyze the block-event log, have an LLM suggest new
WAF rules for patterns it's seeing. Reasonable-sounding feature.

Then I actually checked what data the log contains. Every layer in
Rampart only logs **block** decisions — no request payload, no record of
allowed traffic. Which means: it can't reveal a coverage gap (a missed
attack, by definition, is never logged), and there's no payload captured
to draft a new rule from.

So I scaled the feature down to match what the data actually supports:
`rampart-analyze` reads the block-event log and produces a plain
triage report — top attackers, IPs that triggered more than one
detection layer, traffic bursts — optionally narrated in plain English
by an LLM whose system prompt explicitly forbids it from claiming to
find gaps or draft rules, because the data can't back that claim.

Separate binary from the core proxy, on purpose — running the firewall
itself never needs an API key or outbound network call.

I'd rather ship the smaller, honest version of a feature than the bigger
one that quietly overclaims.

[link to docs/ANALYZE.md]

#buildinpublic #appsec #llm

---

## LinkedIn — the live demo

**Body:**

Wanted to see Rampart actually working, not just passing tests, so I
stood up the full demo stack — Rampart in front of OWASP Juice Shop — and
threw real attack traffic at it: SQL injection, XSS, a brute-force login
attempt.

Every single one got blocked before it reached the app, and showed up on
the live dashboard in real time: 5 WAF blocks (anomaly scores of 5, 15,
and 20 depending on payload severity), 4 API-abuse blocks once the login
attempts crossed the 5-failure threshold — dashboard populated with the
attacker IP, the block reasons, a live event feed, no manual work per
attack.

`docker compose up` gets you the same demo locally in one command if you
want to try breaking it yourself.

[repo link]

#buildinpublic #appsec #demo

---

## LinkedIn — try it yourself, live

**Body:**

Rampart is now running publicly, in front of a deliberately vulnerable
practice app (OWASP Juice Shop) — not a screenshot, not a staged video,
an actual instance you can attack right now.

http://34.29.169.231:8080 — the protected app itself. Try a SQL injection
in the search box, or brute-force the login. It's built to be broken.

http://34.29.169.231:9090 — the live dashboard. Watch your own attack
attempts show up in real time: blocked reason, source IP, which layer
caught it (WAF, brute-force lockout, schema validation).

Nothing about this is staged — it's the same binary and config anyone
running `docker compose up` from the repo gets locally.

Repo (Apache 2.0): https://github.com/singhmarch86/rampart

#buildinpublic #appsec #opensource #demo

---

### Post: the gap the test suite itself found (finding #9)

Wrote a one-shot test suite this week — one payload per vulnerability
class, run against the live public demo, pass/fail per category. Point
was verification, not marketing. It found something.

Nine categories blocked clean: SQLi, XSS, path traversal, command
injection, NoSQL injection, LDAP injection, base64-encoded SQLi,
mass-assignment, brute-force lockout.

One didn't: a bare `{{7*7}}` — server-side template injection — sailed
straight through, 200 instead of a block.

Checked it wasn't a fluke (repeatable, confirmed with a standalone curl
outside the script) and checked why: unlike the base64-SQLi gap I found
and closed earlier (an encoding trick around a rule that *does* exist),
this one has no base rule to evade — OWASP CRS at this paranoia level
just has no signature for template-expression syntax at all.

Not exploitable on *this* demo specifically (Juice Shop's search endpoint
doesn't feed into a template engine), but it's a real, documented gap —
SSTI has led to real RCEs in the wild (Jinja2, Freemarker, Thymeleaf,
Velocity). Logged it the same way as the other 8 findings: root cause,
why it's not exploitable here, what a real fix looks like. Not fixed yet
— that's next.

[link to docs/FINDINGS.md#9]

#buildinpublic #appsec #opensource

---

## LinkedIn — what it actually took to make the demo public

**Body:**

The build was the easy part. Making it *publicly reachable* surfaced a
different kind of bug.

First VM: the smallest free-tier instance (1GB RAM). `docker build`
just... stopped. No crash, no error — the kernel log showed
`virtio_balloon` messages, the signal a VM gives off when it's memory
starved, and zero build progress for several minutes straight. Not a
Rampart bug, just genuinely not enough RAM to compile Rampart and build
the Juice Shop image side by side.

Bumped to a 2GB instance. Same config otherwise. Build finished in a few
minutes.

Then the dashboard timed out on the first request after the containers
reported "started." Before assuming another bug, I tunneled in over SSH
(raw port 22 was blocked, so through GCP's IAP instead) and checked
directly: both containers running, both ports listening on 0.0.0.0. The
first curl had just landed while Juice Shop was still finishing its own
boot — a retry a few seconds later returned 200 immediately.

Neither of these makes it into the "8 bugs found in Rampart" findings
log, because neither one was a Rampart bug — they were infrastructure
reality checks, and I think that distinction matters. A public demo isn't
proof of correctness by itself; you still have to verify what's actually
running, not just trust that "containers say started" means "working."

Live now: http://34.29.169.231:8080 (attack it), dashboard at
http://34.29.169.231:9090 (watch it happen).

[repo link]

#buildinpublic #appsec #devops #gcp

---

## LinkedIn — why self-hosted, for a security tool specifically

**Body:**

"Why would anyone run their own WAF instead of just using Cloudflare?"
Fair question — for most people, they shouldn't. Cloudflare/AWS
WAF/Imperva are better resourced, get threat-intel feeds Rampart never
will, and require zero infrastructure to run.

The case for self-hosted isn't "better," it's "different tradeoffs," and
for a *security* tool specifically I think one of those tradeoffs matters
more than usual: you can read every line deciding what blocks your
traffic and what doesn't.

A cloud WAF's rule engine is opaque by necessity — it's their product,
their IP, and it changes underneath you without a changelog you get to
read. That's fine for a lot of use cases. But "trust us, we're blocking
the right things" is a harder sell for the exact category of tool whose
entire job is a trust decision on every request.

Rampart's answer: Coraza + OWASP CRS, the same open rule set ModSecurity
uses — auditable, not a black box — wrapped in one binary you run
yourself, with every bug found during its own development logged
publicly (root cause, fix, verification) rather than patched silently.
Nothing here is trying to out-scale Cloudflare. It's trying to be the
version you can actually read.

[repo link]

#buildinpublic #appsec #opensource #softwarearchitecture
