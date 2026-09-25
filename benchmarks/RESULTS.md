# WAF benchmark results

**Reproduce:** `./benchmarks/run.sh` (needs Docker and a target on
`localhost:3000` — see the script header). Raw reports aren't committed
(regeneratable, would bloat repo history); this file is the durable record.

Measured with [GoTestWAF](https://github.com/wallarm/gotestwaf) (Wallarm's
open-source WAF evaluation tool, presented at Black Hat Arsenal USA 2022),
run against Rampart's WAF layer in isolation (rate limiting and IP filtering
disabled for this run — see `configs/rampart.benchmark.yaml` — so results
reflect WAF detection specifically, not the full stack).

**Target:** Rampart proxying to a local OWASP Juice Shop instance, Coraza +
OWASP Core Rule Set at default paranoia level 1.

**Methodology note:** we could not find trustworthy published GoTestWAF
scores for other WAFs to compare against — the numbers circulating in search
results for "2026 WAF benchmarks" cite product names/version strings
(e.g. "Cloudflare WAF 3.0") that don't match how those vendors actually
name their products, which is a strong signal of AI-generated SEO content,
not real data. So there's no trustworthy external baseline here. What we do
have is a reproducible, honest measurement of our own config, and a record
of concretely improving it — which is arguably more useful than an
unverifiable comparison anyway.

## Baseline (Phase 2 ship, CRS default config, no custom rules)

Run: 2026-09-25, `benchmarks/reports-baseline/`

| Metric | Score |
|---|---|
| Overall score | **63.12%** |
| True-positive (attacks blocked) | 47.63% (321/674 blocked, 353 bypassed) |
| True-negative (legit traffic passed) | 90.78% (128/141 passed correctly, i.e. **9.22% false-positive rate**) |

### Where the gaps were

By encoder — this is the finding that mattered:

| Encoder | Block rate |
|---|---|
| Plain | 55% |
| URL | 75% |
| **Base64Flat** | **0%** (0/235 blocked) |

Every single Base64-encoded attack payload bypassed the WAF — 235 requests,
by far the largest chunk of the 353 total bypasses. This is not a bug in
CRS: it deliberately does not blindly base64-decode every request argument
before running SQLi/XSS detection, because a lot of legitimate traffic
contains base64 (JWTs, image data URIs, file uploads) and decoding
everything would push the false-positive rate up a lot. It's a real
tradeoff CRS makes at paranoia level 1, not an oversight — but it's also a
real, exploitable gap for anyone who thinks to base64-encode their payload.

By attack category, worst-covered at PL1 (excluding Base64Flat, which
dominated everything):

| Category | Block rate |
|---|---|
| xml-injection | 0% (n=7) |
| ldap-injection | 8% |
| mail-injection | 12% |
| shell-injection | 19% |
| nosql-injection | 24% |
| sst-injection (server-side template) | 25% |
| path-traversal | 30% |
| sql-injection | 40% |
| xss-scripting | 40% |
| community-xss | 94% |

## Fix: targeted anti-evasion rule for Base64

Added [`configs/waf-custom-rules/02-anti-evasion-base64.conf`](../configs/waf-custom-rules/02-anti-evasion-base64.conf):
decodes each request argument and body with `base64DecodeExt`, then runs the
*same* `@detectSQLi`/`@detectXSS` operators CRS itself uses on the decoded
value. Narrow by design — it only fires when a value is both valid-looking
base64 **and** decodes to something that matches a known attack signature,
so harmless base64 (a JWT, an image) should pass through unaffected.

Verified before adding it to the benchmark config:
- `echo -n 'hello world' | base64` as a query param → 200 (unaffected)
- `echo -n "' OR '1'='1" | base64` as a query param → 403 (caught)

## After the fix

Run: 2026-09-25, `benchmarks/reports/`

| Metric | Baseline | After anti-evasion rule | Change |
|---|---|---|---|
| Overall score | 63.12% | **65.25%** | +2.13pp |
| True-positive rate (attacks blocked) | 47.63% | **55.93%** | +8.30pp |
| True-negative rate (false-positive check) | 90.78% | **90.78%** | unchanged |
| Base64Flat encoder block rate | 0% (0/235) | **24%** (56/235) | +24pp |

The false-positive rate holding exactly steady while the true-positive rate
rose is the result worth trusting here — it means the rule caught more real
attacks without becoming trigger-happy on legitimate traffic, which is
exactly the design goal (only fire when decoded content matches a known
attack signature, not just "looks like base64").

Base64Flat rose to 24%, not near 100%, because the rule only re-runs
`@detectSQLi`/`@detectXSS` on the decoded value — base64-encoded
shell-injection, LDAP-injection, and path-traversal payloads (which showed
up as separate low-scoring categories in the baseline) still get through,
since those need their own detection logic. That's the next concrete target
if someone wants to keep pushing this number up: either broaden the
anti-evasion rule to more operators, or address those categories directly at
a higher CRS paranoia level and re-measure the false-positive tradeoff.

## Honest limitations of this benchmark

- Single run each, not averaged — GoTestWAF's payload set is deterministic per
  version so this should be reproducible, but we haven't done repeat runs to
  check variance.
- Paranoia level 1 only. CRS's own docs note PL2-4 catch more but raise the
  false-positive rate; that trade-off hasn't been explored here yet.
- The `Plain`/`URL` encoder categories still have real gaps (ldap-injection,
  mail-injection, shell-injection, xml-injection) that this fix doesn't touch —
  those would need either a higher paranoia level or their own targeted
  custom rules, following the same measure-then-fix loop as above.
- This is Rampart's WAF layer only; the false-positive rate on *real*
  application traffic (as opposed to GoTestWAF's synthetic false-positive
  test set) hasn't been measured yet — that requires running against actual
  production-shaped traffic, which is a Phase 4 (analytics) concern.
