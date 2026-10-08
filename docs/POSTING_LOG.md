# Posting log

Tracks which drafts from [LAUNCH.md](LAUNCH.md) (and Scryer's
[LAUNCH.md](https://github.com/singhmarch86/scryer/blob/main/docs/LAUNCH.md))
have actually been handed over as finalized, ready-to-copy text, so the
next "give me a post" doesn't repeat one already given.

**Important limitation:** I (the assistant) only know what I've *handed
over in chat* — the "Given" column. I have no visibility into LinkedIn
itself and can't confirm what you've actually clicked "Post" on. Check
the "Posted" column yourself; leave it blank until you have.

| # | Project | Post | Given | Posted |
|---|---|---|---|---|
| 1 | Rampart | Main intro ("I built a self-hosted firewall from scratch...") | 2026-09-28 | |
| 2 | Rampart | Try it yourself, live (real demo URLs) | 2026-09-28 | |
| 3 | Rampart | Architecture thesis | 2026-09-29 | |
| 4 | Rampart | Live demo recap | 2026-09-29 | |
| 5 | Rampart | Finding #3 — credential-stuffing bypass | 2026-09-30 | 2026-09-30 |
| 6 | Rampart | Finding #4 — the bug a screenshot caught | 2026-09-30 | |
| 7 | Rampart | Finding #5 — the container that worked right up until it didn't | 2026-09-30 | |
| 8 | Rampart | Finding #6 — the OIDC bug that would have broken RBAC for every user | 2026-10-01 | |
| 9 | Rampart | Finding #7 — the security tool whose own dashboard had zero rate limiting | 2026-10-02 | |
| 10 | Rampart | Finding #8 — I finally pointed a scanner at my own code | 2026-10-02 | |
| 11 | Rampart | ModSecurity comparison (reformatted: no table, softened "SEO junk" line) | 2026-10-03 | 2026-10-03 |
| 12 | Rampart | Finding #9 — the gap the test suite itself found (two-parter, fix post is next) | 2026-10-04 | |
| 13 | Rampart | WAF tip 1 — path rules must ignore case | 2026-10-06 | |
| 14 | Rampart | WAF tip 2 — behind a load balancer, tell your WAF which proxies to trust | 2026-10-06 | 2026-10-07 |
| 15 | Rampart | WAF tip 3 — check which paranoia level a rule needs | 2026-10-08 | |
| - | Scryer | Why Scryer exists (gap-discovery story) | 2026-09-29 | on hold, per request |

Add a row here every time a new draft is finalized and handed over —
whether from the calendar in `LAUNCH.md` or a one-off. Use the post's
short name from `LAUNCH.md`'s "Suggested LinkedIn posting order" list
where one exists, so the two documents stay easy to cross-reference.

## WAF tips series

Ten short educational posts saved in `LAUNCH.md` under "LinkedIn series —
WAF tips" (Tip 1 to Tip 10). Saved, not yet handed over as finalized text.
Tips 1-8 are from verified Rampart findings; 9-10 are general advice. Also
saved: the "try to break it" v2-format post, held until the demo has a
domain and HTTPS. Add a row to the main table above when one is handed over.

## New material, October 2026

Saved in `LAUNCH.md` under "LinkedIn — new material since the first batch",
not yet handed over as finalized text: the false README claim (#14), the
CRS probe (#15), the measured paranoia-level tradeoff, "what Rampart
replaces and what it doesn't", the fix post for #15, and an optional post
sharing the real traffic numbers. Add a row to the main table when one is
handed over. Also still held: a v0.2.0 release post (not drafted until the
tag and image exist).

## Other platforms

LinkedIn is the only channel actually in progress. Drafts for these exist
in `LAUNCH.md` (Rampart) — finalized with real links, ready whenever
started. Not started yet as of 2026-09-30.

| Platform | Post | Status |
|---|---|---|
| Show HN | `Show HN: Rampart – self-hosted WAF/rate-limiter/OIDC gateway, one binary` | not started |
| r/netsec | `Rampart: self-hosted WAF + rate-limiting + OIDC RBAC gateway, benchmarked with GoTestWAF` | not started |
| r/selfhosted | `Rampart – one binary for WAF + rate limiting + login-protected dashboard, in front of any app` | not started |
