# Video scripts

Outlines for you to record yourself (screen capture + narration) — not
scripts I can produce as actual video. Each is built from something
already verified in this repo, not invented for the video. Keep them
short (5-10 min); a demo that drags loses more credibility than it gains.

---

## 1. Quick start — from clone to blocking your first attack

**Goal:** show how little setup this takes.

1. `git clone` the repo, `cd` in.
2. `go build -o bin/rampart ./cmd/rampart` — narrate: "one binary, no
   runtime dependencies."
3. `cp configs/rampart.example.yaml configs/rampart.yaml` — open it,
   scroll through briefly, point out `upstream` is the only thing you
   *must* change.
4. `docker compose up` instead, for the zero-config path — narrate this
   is Rampart in front of a bundled OWASP Juice Shop instance.
5. Open `localhost:8080` in a browser — show the app working normally.
6. Send one attack: `curl "localhost:8080/rest/products/search?q=1' OR '1'='1"`
   — show the 403.
7. Open `localhost:9090` — show the dashboard with that one block already
   logged.

**Close:** "That's the whole setup. Next video: what it actually looks
like under real attack traffic."

---

## 2. Live attack demo — SQLi, XSS, and brute-force, blocked in real time

**Goal:** the most visually convincing demo — this is the dashboard
screenshot from `docs/LAUNCH.md`'s "the live demo" post, but live.

1. `docker compose up`, open the dashboard at `localhost:9090` side by
   side with a terminal.
2. Fire the SQLi payloads one at a time, narrating each:
   - `1' OR '1'='1`
   - `' UNION SELECT * FROM users--`
   - `<script>alert(1)</script>`
   Watch the dashboard tiles update live (Server-Sent Events, no refresh
   needed) after each one.
3. Fire 6-7 failed logins at `/rest/user/login` in a loop — show the
   first 5 return 401, the 6th+ return 429 once the brute-force threshold
   trips.
4. Point at the "Top block reasons" table — explain the anomaly-score
   numbers (`Inbound Anomaly Score Exceeded (Total Score: N)`) briefly:
   each matched CRS rule adds points, only crossing a threshold blocks.
5. Point at "IPs that triggered more than one layer" — explain this is
   the signal for a more deliberate, scripted attacker vs. one-off noise.

**Close:** point at `docs/DETECTION.md` for the full breakdown of how each
layer decides what counts as an attack.

---

## 3. The benchmark story — GoTestWAF, a real gap, and a fix

**Goal:** the credibility piece — show the verification methodology, not
just the number.

1. Screen-share `benchmarks/RESULTS.md`. Explain GoTestWAF briefly:
   independent tool, not self-reported.
2. Walk through the baseline table: 63.12% overall, then the encoder
   breakdown — stop on Base64Flat: 0%. Explain *why* (CRS deliberately
   doesn't decode every argument by default, tradeoff against false
   positives on real base64 data like JWTs).
3. Show the fix: `configs/waf-custom-rules/02-anti-evasion-base64.conf` —
   narrate what it does (decode, re-run the same detection CRS already
   has, only on the decoded value).
4. Show the after-numbers: 65.25% overall, Base64Flat 0% → 24%,
   false-positive rate *unchanged* — explain why that unchanged number is
   the one that actually matters (more attacks caught without becoming
   trigger-happy).
5. Show the ModSecurity comparison section — explain the setup (same
   tool, same ruleset, same paranoia level, different engine) and what
   the two numbers being close together actually proves (Coraza is a
   faithful reimplementation, not a degraded copy).

**Close:** "Full reproduction steps are in the doc if you want to run
this yourself and check the numbers."

---

## 4. OIDC setup — dashboard login against real Keycloak

**Goal:** show the integration working end to end, and be upfront about
the one real gotcha found building it.

1. Stand up Keycloak (docker or existing instance). Create a realm,
   a confidential client, a role, assign it to a test user — follow
   `docs/OIDC.md`'s walkthrough on screen.
2. Set `oidc.enabled`, `oidc.dashboard_auth.enabled`, client ID/secret,
   `required_roles` in the config. Generate a session secret with
   `openssl rand -hex 32`.
3. Restart Rampart, visit the dashboard — show the redirect to Keycloak's
   real login page, log in, land back on the dashboard.
4. Try a user *without* the role — show the 403.
5. Narrate the gotcha from finding #6: roles live on the access token,
   not the ID token, on stock Keycloak — mention it briefly as "the kind
   of thing you'd only find by testing against the real provider, not a
   mock."

**Close:** point at `docs/OIDC.md` for the API RBAC side too (per-route
role enforcement on the proxied app, not just the dashboard).

---

## 5. rampart-analyze — turning the block log into a triage report

**Goal:** show the tool, and be explicit on screen about its boundaries
(this is the point of the tool, not a caveat to rush past).

1. Run the live-attack demo from video 2 first (or reuse its event log).
2. `go build -o bin/rampart-analyze ./cmd/rampart-analyze`
3. `./bin/rampart-analyze -events rampart-events.jsonl -out report.md`
4. Open `report.md` — walk through the tables: top attackers, top block
   reasons, multi-vector IPs, bursts.
5. Read the scope callout out loud, on screen: this only covers requests
   already blocked — it can't find coverage gaps or draft new rules,
   because that data isn't in the log. Say plainly why that's a
   deliberate scope limit, not a missing feature.
6. Optionally: show `-narrate` with `ANTHROPIC_API_KEY` set, and point out
   the system prompt (`internal/analyze/llm.go`) that keeps the model's
   summary inside the same boundary.

**Close:** "Separate binary from the core proxy, on purpose — the
firewall itself never needs an API key to run."
