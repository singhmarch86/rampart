# Launch post drafts

Drafts only — nothing here gets posted automatically. Copy, edit to sound
like you, and post yourself. Recommended order: wait until there's a
tagged release on a public GitHub repo before posting any of these (a dead
link in a Show HN post is a bad first impression).

## Suggested LinkedIn posting order (day-by-day)

One post a day, not a batch dump — LinkedIn reach rewards consistency
over volume, and posting several at once just cannibalizes each other.
Covers all 15 LinkedIn drafts here plus the 6 in
[scryer/docs/LAUNCH.md](https://github.com/singhmarch86/scryer/blob/main/docs/LAUNCH.md),
interleaved. Intros go first so later posts have context; the bug-finding
series lands mid-sequence once people know what the projects are;
benchmarks/deployment/thesis close it out.

**Week 1 — introduce both projects**
1. Rampart — "LinkedIn" (main intro, "I built a self-hosted firewall from scratch...")
2. Scryer — "LinkedIn — why Scryer exists"
3. Rampart — "LinkedIn — architecture thesis"
4. Scryer — "LinkedIn — architecture thesis"
5. Rampart — "LinkedIn — the live demo"
6. Rampart — "LinkedIn — try it yourself, live"
7. Scryer — "LinkedIn — try it yourself"

**Week 2 — findings, one bug per post**
8. Rampart — "Post: the credential-stuffing bypass (finding #3)"
9. Scryer — "LinkedIn — the Spring rule pack that shrank by 86% once I checked"
10. Rampart — "Post: the bug a screenshot caught (finding #4)"
11. Scryer — "LinkedIn — SARIF and skipping the UI nobody needed built"
12. Rampart — "Post: the container that worked right up until it didn't (finding #5)"
13. Rampart — "Post: the OIDC bug that would have broken RBAC for every user, always"
14. Scryer — "LinkedIn — pointing a scanner at the scanner"

**Week 3 — benchmarks, deployment, close**
15. Rampart — "Post: the security tool whose own dashboard had zero rate limiting"
16. Rampart — "Post: I finally pointed a scanner at my own code"
17. Rampart — "LinkedIn — ModSecurity comparison" (strongest credibility post — good candidate to boost)
18. Rampart — "Post: the gap the test suite itself found (finding #9)"
19. Rampart — "Post: closing the gap the test suite found (finding #9, the fix)"
20. Rampart — "Post: the bypass hiding in a one-character case change (finding #10)"
21. Rampart — "Post: the same bug, a third time, in the authorization layer (finding #11)"
22. Rampart — "LinkedIn — what it actually took to make the demo public"
23. Rampart — "LinkedIn — rampart-analyze"
24. Rampart — "LinkedIn — why self-hosted, for a security tool specifically" (closing thesis)

---

## LinkedIn — v2 format test: "try to break it" (hold until the demo has a domain + HTTPS)

Why this exists: the long story-format posts reached ~9,000 impressions
but sent about one tracked visit to the repo (GitHub Traffic, 14 days).
The link sat below "see more" and pointed at a raw `http://` IP. This
version leads with the hook, keeps the link in the first lines, and gives
a reason to click. Success measure: unique visitors from outside GitHub in
the repo's Traffic > Referring sites panel over the following 7 days.

Replace `[DOMAIN]` once the demo is served over HTTPS. Attach one image:
a screenshot of the dashboard's "Top block reasons" panel, or a terminal
showing `{{7*7}}` returning 403.

**Body:**

Try to break my firewall. It's live, and it's meant to be attacked.

https://[DOMAIN] is Rampart, a self-hosted WAF I built, sitting in front
of a deliberately vulnerable app (OWASP Juice Shop).

Try a SQL injection in the search box. Try `{{7*7}}`: that one slipped
past it until I found the gap and fixed it. Hammer the login and watch it
lock you out. https://[DOMAIN]:9090 shows what it blocks, live.

If you find a bypass, I want to hear it. 16 real findings are already
logged with root cause and fix, including bugs in my own code.

Repo: https://github.com/singhmarch86/rampart

#appsec #opensource #waf

---

## LinkedIn series — WAF tips (educational, one tip per post)

Short, hook-first posts that teach something useful and don't depend on
anyone caring about Rampart yet. Tips 1-8 come from bugs found and
verified in Rampart itself (linked); tips 9-10 are general WAF knowledge
that was not tested here, so keep them worded as general advice. Pair one
a week with the demo link once the demo has a domain and HTTPS. Don't
claim Rampart does anything beyond what its docs say.

### Tip 1: WAF path rules must ignore case

A WAF rule that protects `/admin` with a case-sensitive match is bypassed
by `/Admin` whenever the backend is case-insensitive. Express is by
default.

I found this in three places in my own firewall, including the one that
enforces roles: a request with no token at all returned 200. After fixing
the first two, grep for the same pattern everywhere. The third copy was
the worst one.

https://github.com/singhmarch86/rampart/blob/main/docs/FINDINGS.md#11-oidc-rbac-guard-same-path-case-bypass-but-on-the-authorization-layer

#appsec #waf #golang

### Tip 2: behind a load balancer, tell your WAF which proxies to trust

Without it, every user looks like the load balancer's IP. One attacker
trips the login lockout and everyone is locked out; per-IP rate limits
become one shared limit.

The fix is a list of trusted proxies, and honoring `X-Forwarded-For` only
from them. Trust the header from anyone and a client can pick its own IP
to dodge every limit.

https://github.com/singhmarch86/rampart/blob/main/docs/FINDINGS.md#12-behind-a-load-balancer-every-client-looked-like-the-same-ip

#appsec #waf #kubernetes

### Tip 3: check which paranoia level a rule needs

OWASP CRS ships a template-injection rule. It never fired for me, for two
reasons: it only runs at paranoia level 2, and its pattern doesn't match
`{{ }}` at all, the most common injection syntax.

I found that by reading the actual rule source, not the docs. If a
category matters to you, test it with a real payload and check which
level its rule needs.

https://github.com/singhmarch86/rampart/blob/main/docs/FINDINGS.md#9-waf-server-side-template-injection-payloads-pass-through-unblocked

#appsec #waf #owasp

### Tip 4: test your WAF with encoded payloads

At CRS's default level, 0% of the base64-encoded attacks in my benchmark
were blocked. It doesn't decode everything on purpose, because that would
flag legitimate data like tokens and images.

One narrow custom rule (decode, then run the same detectors) closed the
gap, and the false-positive rate didn't move. Whatever WAF you run, send
it the attacks in encoded form too.

https://github.com/singhmarch86/rampart/blob/main/docs/FINDINGS.md#2-waf-0-block-rate-on-base64-encoded-attack-payloads

#appsec #waf #owasp

### Tip 5: measure false positives, not just blocks

A WAF that blocks everything has perfect detection and is useless. When
you benchmark, report the false-positive rate next to the block rate.

When I added a rule that raised the score by about 2 points, the number I
cared about was that the false-positive rate stayed exactly the same.

https://github.com/singhmarch86/rampart/blob/main/benchmarks/RESULTS.md

#appsec #waf #benchmarking

### Tip 6: only a real success should reset a lockout counter

If any non-failure response resets the brute-force counter, an attacker
interleaves one real password guess with one junk request that fails
differently. The counter never reaches the limit.

Only a genuine success should reset it. Everything else leaves it alone.

https://github.com/singhmarch86/rampart/blob/main/docs/FINDINGS.md#3-api-abuse-guard-failure-streak-reset-let-attackers-dodge-lockout

#appsec #waf #authentication

### Tip 7: validate the shape of a request, not just its content

`{"email": "a@b.com", "password": "x", "isAdmin": true}` contains nothing
a signature would flag. A JSON Schema that forbids unexpected fields on
the login endpoint rejects it anyway.

Some attacks have no malicious-looking string in them. The problem is a
field that shouldn't be there.

https://github.com/singhmarch86/rampart/blob/main/docs/DETECTION.md#3-schema-validation--shape-not-signature

#appsec #waf #api

### Tip 8: don't put a write timeout on a streaming proxy

Read and idle timeouts stop slow-body and idle-connection attacks. A write
timeout looks like the same kind of protection, but it cuts off legitimate
long responses and live event streams.

I tested it: with a 3s read timeout, a 5s upstream response and an open
live stream still worked, while the slow clients were dropped.

https://github.com/singhmarch86/rampart/blob/main/docs/FINDINGS.md#13-no-read-or-idle-timeouts-a-slow-client-could-hold-connections-open-forever

#appsec #waf #golang

### Tip 9: one rule hit can be enough to block (general advice)

CRS doesn't count rule hits. It adds up points per hit and blocks at a
threshold. By default the threshold is 5 and one critical rule is worth
5, which is why block reasons read "Total Score: 20".

When you're chasing a false positive, add a targeted exclusion for that
rule instead of raising the threshold for everything.

#appsec #waf #owasp

### Tip 10: a WAF buys time, it doesn't fix the bug (general advice)

A WAF blocks known patterns before they reach the app. It's a speed bump,
not a fix: fix the vulnerable code too.

And know what it can't see: DOM-based XSS, business-logic flaws, and
authorization bugs where the request looks perfectly normal.

https://github.com/singhmarch86/rampart/blob/main/docs/DETECTION.md#out-of-scope-on-purpose-networktransport-layer-attacks

#appsec #waf #security

---

## LinkedIn — new material since the first batch (October 2026)

Drafted after the earlier series. Every number below was measured in this
repo (sources linked or named); nothing here is an estimate. Order is a
suggestion: the first two are the strongest, and each stands alone.

### Post: my README listed a feature my firewall doesn't have (finding #14)

My README said my firewall does geo-blocking. My roadmap listed it as
shipped.

I went looking for the code and there isn't any. No GeoIP database, no
lookup, nothing. Geo-blocking was in the original plan and I never built
it, but the docs kept describing the plan as if it were the product.

Nobody had caught it. I found it by reading my own front page the way a
skeptical stranger would. If someone evaluating a security tool checks one
headline feature and finds it missing, they'll reasonably discount
everything else.

The README now says what's actually implemented and says plainly what
isn't. While I was in there I also found my changelog described two
releases that were never tagged on GitHub. Fixed that too.

Most of my bug-hunting has been testing behavior. This one was just
reading. Worth doing before anyone else does it for you.

https://github.com/singhmarch86/rampart/blob/main/docs/FINDINGS.md#14-the-readme-and-roadmap-claimed-geo-blocking-which-doesnt-exist

#buildinpublic #appsec #opensource

### Post: I probed my WAF with one test per OWASP rule category (finding #15)

I wrote a script that sends one standard test string per OWASP Core Rule
Set category at my WAF, 23 in total, against a local copy only.

First run: 5 not blocked. Then the part that matters: I checked each one
before calling it a gap.

→ One was my own bug. My test double-encoded the payload, so the WAF saw
literal text. With the real bytes it was blocked.
→ One (XXE) really wasn't blocked: OWASP CRS has no rule for external XML
entities at all.
→ Two template-injection syntaxes got through, because the rule that
covers them only runs at a higher paranoia level. My earlier fix covered
one syntax and I'd called the whole category closed.
→ One short command (`;id`) was only caught at the highest level I tried.

And a trap: XXE looked blocked at higher paranoia levels. The event log
said otherwise. The WAF wasn't recognizing the attack, it was blocking the
app's error page on the way out. A 403 isn't proof of detection.

19 of 23 passed on the first clean run. The 4 that didn't were each worth
knowing about.

https://github.com/singhmarch86/rampart/blob/main/docs/FINDINGS.md#15-crs-coverage-probe-xxe-and-two-template-injection-syntaxes-arent-blocked

#buildinpublic #appsec #waf #owasp

### Post: turning up your WAF's paranoia level isn't free (measured)

OWASP CRS has four paranoia levels. Higher means more rules and more
detection. I assumed the cost was "some false positives". I measured it,
same tool and same target at each level (GoTestWAF against Juice Shop, one
run each). "Detects" is GoTestWAF's application-attack score:

Level 1: detects 56%, wrongly blocks 13 of 141 legitimate samples (9%)
Level 2: detects 63%, wrongly blocks 53 of 141 (38%)
Level 3: detects 66%, wrongly blocks 61 of 141 (43%)
Level 4: detects 69%, wrongly blocks 141 of 141 (100%)

Two things stood out. The tool's own overall score peaks at level 2, which
makes level 2 look like the winner while more than a third of legitimate
traffic gets blocked. And level 4 blocked everything, so it's unusable
untuned.

Caveats, because they matter: one run per level, one target, and the
legitimate set is 141 short synthetic samples, not real traffic. Treat the
percentages as indicative and measure on your own traffic in detect mode.

Takeaway: for a known gap, a narrow custom rule usually beats turning the
dial up for everything.

https://github.com/singhmarch86/rampart/blob/main/benchmarks/RESULTS.md

#buildinpublic #appsec #waf #owasp

### Post: what Rampart replaces, and what it doesn't

People keep asking if my open-source WAF replaces nginx + ModSecurity +
fail2ban. The honest answer is a split one.

What it replaces, for HTTP traffic in front of one app:
→ the ModSecurity module (it embeds Coraza, a Go reimplementation of the
same engine, running the same OWASP rules)
→ fail2ban's web-login job (it counts failed logins as they happen and
blocks the IP for a while)
→ the log-and-dashboard glue (live dashboard, block-event log)

What it doesn't:
→ nginx. One upstream per instance, no static files, load balancing,
caching or rewrites. In Kubernetes it sits behind your Ingress, not
instead of it.
→ fail2ban for anything that isn't HTTP. No SSH, no mail. Its blocks are
HTTP 429s, not firewall drops, and counters live in memory per instance.
→ ModSecurity's detailed audit log. It records blocks only.

Saying where a tool stops is worth more than a bigger claim. "One binary
instead of five tools" is true for the security stack. It isn't true for
your whole edge.

https://github.com/singhmarch86/rampart

#buildinpublic #appsec #opensource #waf

### Post: closing the gaps my own probe found (and the two mistakes on the way)

Follow-up to the WAF probe. Two real gaps: XML external entities (XXE) had
no rule at any paranoia level, and two template-injection syntaxes were
only covered by a higher-level rule. Both are closed at the default level
now. The interesting part is how.

Mistake 1: I wrote the XXE rule first. It blocked nothing. I tested why
instead of guessing: for an XML request body, the rule language gets an
empty body variable, and the DOCTYPE where the attack lives isn't exposed
at all. It works for form bodies, not XML. So the check moved into the Go
code that already holds the raw bytes.

Mistake 2: my first template regex blocked a harmless `<%- name %>`,
treating the dash as an operator. A test caught it before it shipped. The
fix was requiring an operator to sit between two operands.

Verified on the real binary: the probe went from 19 to 22 of 23 passing,
the core attack suite stayed at 14 of 14, and in the benchmark the share of
legitimate samples passed stayed at exactly 90.78%, so no new false
positives on that set.

Not covered, and I say so in the docs: internal entities, XML in encodings
like UTF-16, and one short command that only the strictest level catches.
The real XXE defense is turning off external entities in your XML parser.

https://github.com/singhmarch86/rampart/blob/main/docs/FINDINGS.md#15-crs-coverage-probe-xxe-and-two-template-injection-syntaxes-arent-blocked

#buildinpublic #appsec #waf #owasp

### Optional post: my real marketing numbers (only if you want to share them)

Build-in-public, including the numbers that don't flatter me.

One of my posts reached about 9,000 impressions. GitHub's traffic panel
for the repo, same period: 3 unique visitors, 19 page views. LinkedIn was
credited with 1 visit.

The repo also showed 306 clones from 106 unique cloners, which sounds
great until you notice that almost nobody viewed the page. Those are
almost certainly bots and scanners, not people.

What I take from it: impressions measure feed appearances, not interest.
I was writing for readers and not giving anyone a reason to click. Changes
I'm making: a live demo people can attack, a README whose first screen
makes sense, and a one-command quick start.

I'll report back with the new numbers.

https://github.com/singhmarch86/rampart

#buildinpublic #opensource #appsec

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

### Post: closing the gap the test suite found (finding #9, the fix)

Follow-up to the SSTI gap the test suite found: it's closed now, and the
root cause was more specific than "CRS doesn't cover this."

Turns out CRS v4 *does* ship a rule aimed at this class of attack — id
934180, matching `{% ... %}` and `<% ... %>`. Two reasons it never fired:
it's gated to paranoia level 2, and Rampart runs at CRS's default, PL1.
And even at PL2, that rule's own regex doesn't match bare `{{ ... }}` at
all — which is the single most common SSTI proof-of-concept syntax
(Jinja2/Twig/Mustache/Handlebars), and exactly what the test payload
(`{{7*7}}`) used. Found this by reading the actual vendored rule source
in the Go module cache, not by guessing from CRS's docs.

Fix: a targeted custom rule, same anti-evasion pattern as the base64 gap
from a few weeks back — requires an arithmetic operator or a known
RCE/reflection primitive (`__class__`, `config.`, `exec(`, etc.) inside
the double braces, not just any `{{...}}`. A legitimate Angular/Vue-style
`{{user.name}}` has neither and passes through untouched — verified that
directly, not assumed.

Built the image locally, stood up an isolated test instance, threw four
real SSTI variants at it (all blocked) and three benign double-brace
lookalikes (all passed through clean), then re-ran the full test suite:
14/14, up from 13/14.

[link to docs/FINDINGS.md#9]

#buildinpublic #appsec #opensource

---

### Post: the bypass hiding in a one-character case change (finding #10)

After closing the SSTI gap, I went looking for the next bug instead of
waiting for a test to trip over one. Found something worse.

Two of Rampart's four detection layers — credential-stuffing lockout and
mass-assignment schema validation — scope themselves by URL path prefix,
matched with Go's `strings.HasPrefix`. Case-sensitive.

Express (what Juice Shop, and most Node backends, run on) treats routes
as case-insensitive by default. `/REST/User/Login` and `/rest/user/login`
hit the exact same handler on the app side.

So a mass-assignment payload (`isAdmin: true`) sent to `/rest/user/login`
gets blocked — 400. The identical payload to `/REST/User/Login`? 401 —
schema validation never ran, the app processed it directly. Six straight
failed logins to the uppercase path: never once triggered the lockout
that reliably fires on the 6th failure against the lowercase path.

A one-character case change, and two of four protection layers just...
don't apply. The WAF layer was unaffected — it isn't path-scoped — which
is how I isolated this to exactly these two.

Fix: lowercase both sides of the comparison. Verified on a fresh isolated
instance both directions — the bypass is closed, and blocking state now
correctly unifies across case variants (get locked out via the uppercase
path, and the lowercase path is locked out too, same as it should always
have been).

[link to docs/FINDINGS.md#10]

#buildinpublic #appsec #opensource

---

### Post: the same bug, a third time, in the authorization layer (finding #11)

I fixed a case-sensitivity bug in two places. Then I did the thing I
should have done first: grepped the codebase for the same pattern.

Third copy. In the OIDC role-based access control guard — the layer whose
entire job is deciding who's allowed in.

Here's why that one is worse. The guard asks "does this request match a
protected path?" If yes, it checks the token and the role. If no, it
passes the request straight through, with no checks at all. And the path
match was case-sensitive.

So with `/admin` configured to require an admin role, a request to
`/Admin/dashboard` with no token whatsoever returned 200. Not a 403. Not
a 401. The guard just didn't recognize the path as protected.

The two earlier instances skipped abuse detection. This one skipped
authorization itself.

How I verified it: wrote the regression test first and watched it fail
against the unfixed code. No Authorization header, 200 instead of 401.
Then applied the fix and watched it pass. No token on `/Admin/dashboard`
now gets 401, and a valid token without the admin role on `/ADMIN/dashboard`
gets 403, same as on `/admin`.

The part worth taking away isn't the one-line fix, it's that fixing two
call sites didn't mean the bug was fixed. The pattern, hand-rolling
case-sensitive path matching, had been copy-pasted, and the most
security-sensitive copy was the one I hadn't looked at yet. After this
one I swept the whole codebase. These three were the only instances.

[link to docs/FINDINGS.md#11]

#buildinpublic #appsec #oidc #golang

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
