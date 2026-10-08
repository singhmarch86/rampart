# Detection: how Rampart decides what counts as an attack

This is a living reference for every detection mechanism Rampart runs, kept
alongside the code the same way `docs/ROADMAP.md` and `docs/FINDINGS.md`
are — add a new section here whenever a new detection layer or rule class
ships, rather than letting this go stale. Each section covers what the
layer looks at, how it decides to block, and a concrete example from an
actual run (not a hypothetical), so the reasoning is checkable, not just
asserted.

Rampart runs four independent layers in front of every request. Each one
answers a different question about "is this bad" — a request only needs to
trip *one* to get blocked.

---

## 1. WAF — pattern matching with a cumulative anomaly score

**Config:** `waf.*` — Coraza engine running the OWASP Core Rule Set (CRS),
plus any custom rules in `waf.custom_rules_dir`.

**What it looks at:** the request's URL, headers, and body, checked against
thousands of CRS rules — each rule looks for one specific suspicious
pattern (a SQL keyword in an odd position, a `<script>` tag, a path
traversal sequence, a known exploit signature, etc.).

**How it decides to block:** not "one match = block." Each rule that fires
adds points to an **anomaly score** for that request; only once the total
score crosses a threshold does Rampart block it. This exists specifically
so one borderline signal doesn't block a legitimate request, but several
suspicious signals stacking up does.

**Example, from a live run against the `docker-compose.yml` demo stack
(Rampart in front of OWASP Juice Shop):**

| Payload sent | Result |
|---|---|
| `1' OR '1'='1` | `403`, anomaly score 20 |
| `' UNION SELECT * FROM users--` | `403`, anomaly score 20 |
| `<script>alert(1)</script>` | `403`, anomaly score 15 |
| `<img src=x onerror=alert(1)>` | `403`, anomaly score 5 |

Different payloads trip different combinations of rules, hence different
scores — the dashboard's "Top block reasons" table shows each distinct
score as its own line (`Inbound Anomaly Score Exceeded (Total Score: N)`),
which is why you'll see several WAF rows for what looks like "the same"
block reason.

**Custom rules close specific gaps CRS leaves open by design.** CRS at the
default paranoia level doesn't base64-decode every argument before running
SQLi/XSS detection (decoding everything would false-positive on legitimate
base64 — JWTs, image data URIs, uploads), so a base64-encoded attack
payload sails through untouched otherwise.
[`configs/waf-custom-rules/02-anti-evasion-base64.conf`](../configs/waf-custom-rules/02-anti-evasion-base64.conf)
decodes each argument/body with `base64DecodeExt` and re-runs the same
`@detectSQLi`/`@detectXSS` operators CRS itself uses — narrow by design, so
it only fires when a value is both valid base64 *and* decodes to something
matching a known attack signature. Verified via GoTestWAF: Base64Flat block
rate 0% → 24%, false-positive rate unchanged. Full story in
[docs/FINDINGS.md #2](FINDINGS.md#2-waf-0-block-rate-on-base64-encoded-attack-payloads).

**Two more gaps closed outside the rule set.** CRS has no request rule for
XML external entity (XXE) declarations, and its rule for the `{% %}` and
`<% %>` template syntaxes only runs at paranoia level 2. The template
syntaxes are covered by `configs/waf-custom-rules/03-ssti-double-brace.conf`.
XXE is checked in Go (`internal/waf/waf.go`) instead of in a rule, because
for an XML body the rule language can't see the raw body where the
declaration lives. Details, limits and the false-positive check in
[docs/FINDINGS.md #15](FINDINGS.md#15-crs-coverage-probe-xxe-and-two-template-injection-syntaxes-arent-blocked).

**Paranoia level (`waf.paranoia_level`, 1-4, default 1).** CRS ships its
rules in tiers: higher levels run more rules and catch more, and wrongly
block more legitimate traffic. Many rules only exist above level 1 (for
example, most of the RCE and SQLi rules, and the template-injection rule for
`{% %}` / `<% %>` syntax). Measured with GoTestWAF against Juice Shop
(`benchmarks/RESULTS.md` has the full table and caveats):

| Level | App-security detection | Legitimate samples wrongly blocked |
|---|---|---|
| 1 (default) | 56% | 13 of 141 (9%) |
| 2 | 63% | 53 of 141 (38%) |
| 3 | 66% | 61 of 141 (43%) |
| 4 | 69% | 141 of 141 (100%) |

Practical guidance: leave it at 1 unless you have a reason. To try a higher
level, set `mode: detect` first so matches are logged but not blocked, and
watch for false positives on your own traffic; GoTestWAF's legitimate set is
141 short synthetic samples, so these percentages are indicative, not a
prediction for your application. Known gaps are usually better closed with a
narrow custom rule (as in the base64 example above) than by raising the
level for everything.

---

## 2. API-abuse — behavior over time, not request content

**Config:** `api_abuse.rules[]` — one rule per auth-gated endpoint you want
watched.

**What it looks at:** nothing about the *content* of any single request.
It counts responses per client IP against a configured endpoint over a
sliding window.

**How it decides to block:** if an IP racks up `max_failures` responses
matching `failure_status_codes` within `window`, that IP is blocked from
that endpoint for `block_duration`. The default demo rule
(`login-brute-force`) watches `POST /rest/user/login` for `401`s: 5
failures in 1 minute → blocked for 5 minutes.

**Example, from the same live run:** 5 login attempts with the wrong
password each returned `401` (genuine auth failures, not blocked); the 6th
and 7th attempts — same IP, same endpoint, within the window — returned
`429` before Juice Shop's own login handler even ran.

**A subtlety worth knowing, because it was a real bug once:** only a
genuine success (2xx) resets an IP's failure streak. An earlier version
reset the streak on *any* non-failure response, including a `400` from
the schema-validation layer below — which let an attacker interleave one
real guess with one throwaway malformed request (guaranteed 400, costs
nothing) to dodge the lockout indefinitely. See
[docs/FINDINGS.md #3](FINDINGS.md#3-api-abuse-guard-failure-streak-reset-let-attackers-dodge-lockout).

---

## 3. Schema validation — shape, not signature

**Config:** `schema_validation.rules[]` — one JSON Schema per route.

**What it looks at:** whether a request body matches the JSON Schema
declared for that route — field names, types, and whether unexpected
fields are present at all.

**How it decides to block:** no "attack pattern" needs to be present. A
login request that includes an unexpected `isAdmin` field, or a field of
the wrong type, gets rejected purely because a legitimate client would
never send that shape — this catches mass-assignment-style attacks that
don't look like anything on a WAF signature list, because there isn't one
to write: the problem is what's *present*, not what's malicious-looking.

---

## 4. Rate limiting — pure volume, no inspection at all

**Config:** `rate_limit.*` (main proxy) and `dashboard.rate_limit.*`
(dashboard's own port, added separately — see
[docs/FINDINGS.md #7](FINDINGS.md#7-dashboard-server-had-no-rate-limiting-of-its-own)
for why it needed its own config rather than inheriting the proxy's).

**What it looks at:** request count per client IP per second, plus burst
allowance and max concurrent in-flight requests.

**How it decides to block:** too many requests too fast from one IP gets
`429`d, regardless of what's in those requests. This is the layer that
catches raw flood/DoS-shaped traffic that wouldn't trip WAF or API-abuse
at all, because there's nothing content-wise to flag.

---

## 5. Host allow-list — which names this deployment serves

Config: `allowed_hosts` (a list; empty disables the layer). Event layer:
`hostguard`.

An application that builds an absolute URL from the request's `Host` or
`X-Forwarded-Host` lets an attacker choose the domain inside that URL. The
usual victim is the password-reset email: request a reset for someone else's
account with `Host: evil.example`, and the real service emails them a link to
the attacker's server carrying a valid reset token. It is a phishing link
sent from the legitimate service, and no content rule can recognise it,
because `evil.example` is an ordinary hostname. Only the operator knows which
names are legitimate, so this layer takes that list.

It rejects, with a 403 and a `hostguard` block event, any request whose
`Host` is missing or not on the list, or that names an unlisted host in
`X-Forwarded-Host`, `X-Host` or the `host=` of `Forwarded`. Every
comma-separated element and every repeated header line is checked. Matching
is case-insensitive and ignores a trailing dot; `example.com` matches any
port, `example.com:8443` only that port, and `*.example.com` matches
subdomains but not `example.com` itself. Malformed values (spaces, `@`, `/`,
a non-numeric port) never match. The block reason is a fixed string, not the
offending value, so probes do not each become a separate dashboard row.

Placement: after the IP filter and rate limiter, before the OIDC, API-abuse,
schema and WAF layers. It does not cover the dashboard port.

Measured (before, WAF at paranoia level 1, bare file server behind): `Host:
evil.example`, `X-Forwarded-Host: evil.example` and a bare-IP `Host` all
passed. After, with `allowed_hosts: [shop.example.com, "*.shop.example.com"]`
on the real binary: allowed hosts (including a subdomain and a port) returned
200; `Host: evil.example`, a bare-IP `Host`, a good `Host` with
`X-Forwarded-Host: evil.example`, and a good `Host` with `Forwarded:
host=evil.example` all returned 403, each logged once as `hostguard`.

Limits: it protects only deployments that set the list. A wildcard entry
trusts every subdomain, so a taken-over subdomain is accepted. It does not
stop open redirects or injected links in pages, which are separate gaps (see
below); it also does not make an application that trusts `Host` safe from
anything other than a hostname the operator did not list.

---

## Out of scope, on purpose: network/transport-layer attacks

Rampart is an L7 reverse proxy — every layer above inspects HTTP requests
*after* a connection has already been established. That boundary means a
few real attack classes are structurally outside what Rampart can detect,
not because of a missing rule but because Rampart never sees the traffic
in question at all.

**Man-in-the-middle and DNS spoofing.** Both happen *before* a request
reaches Rampart: a MITM intercepts the connection between the client and
whatever terminates TLS; DNS spoofing redirects the client to a different
IP entirely, one Rampart never receives traffic on. From Rampart's vantage
point, an intercepted connection and a legitimate one are indistinguishable
— it only ever sees the second hop.

`tls.*` (see `configs/rampart.example.yaml`) lets Rampart terminate TLS
directly with an operator-provided cert/key, which narrows this — but it's
a mitigation, not detection, and the actual protection happens in the
*client's* browser, not in Rampart. If a MITM'd or DNS-spoofed client
connects to an attacker's endpoint instead of Rampart's, that attacker
doesn't have Rampart's private key; the client's own certificate
validation is what refuses the connection. Rampart itself still has zero
visibility into an attempt happening elsewhere — enabling `tls.*` doesn't
change that, it just makes the client-side defense possible to rely on.

**Phishing.** A fake lookalike domain or a deceptive email never touches
Rampart's request path at all — it's infrastructure Rampart doesn't sit in
front of. The *aftermath* of phishing (an attacker using a stolen
credential to log into the real app) is covered by the API-abuse guard's
brute-force/credential-stuffing detection above, but that's a different
claim: Rampart limits what a phished credential is worth, it doesn't
detect the phishing itself. What it can do is shut one phishing enabler that
does reach it: Host-header poisoning of password-reset links, via
`allowed_hosts` (section 5). Open redirects (`/redirect?to=https://evil`) and
an injected `<a href>` in a reflected page are not blocked: CRS has no rule
for either, so the application has to validate redirect targets and encode
output.

None of this is a roadmap item to "fix" — it's a permanent architectural
boundary worth stating plainly, the same way `docs/ANALYZE.md` states
what `rampart-analyze` can't claim from block-only event data.

## gRPC and protobuf: not supported

Binary protobuf bodies and gRPC traffic do not work through Rampart today.
Tested with a real gRPC server (health service: a unary call and a
server-streaming call) behind a local Rampart, using the client and server
in `scripts/grpc-probe/`:

| Path | Result |
|---|---|
| Client straight to the gRPC server (control) | works, stream delivers messages |
| Via Rampart over TLS, WAF off | **502**: the proxy speaks HTTP/1.1 to the upstream, and a gRPC server only speaks HTTP/2 |
| Via Rampart over TLS, WAF on | **403** on both calls, even for a harmless health check: the CRS scored the binary request at 18 (threshold 5) |
| Via Rampart on plain HTTP | fails at connection setup: the plain listener does not do HTTP/2 without TLS (h2c) |

So there is no gRPC protocol coverage to describe: it is blocked, or
broken, before any rule could say anything about its content. Independently
of that, the WAF cannot see inside a protobuf message (Coraza has no
protobuf body processor), and schema validation is JSON-only. Not tested,
because the upstream hop fails first: streaming through the WAF's response
buffering, and HTTP/2 trailers. See finding #17.

---

## Adding a new layer or rule class

When a new detection mechanism ships, add a section here in the same
shape: config keys, what it looks at, how it decides to block, and a real
example (a live request/response pair or a benchmark number, not a
description of intended behavior). If it closes a gap found the same way
finding #2's base64 gap was, link the relevant `docs/FINDINGS.md` entry
rather than restating it.
