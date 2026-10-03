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
| - | Scryer | Why Scryer exists (gap-discovery story) | 2026-09-29 | on hold, per request |

Add a row here every time a new draft is finalized and handed over —
whether from the calendar in `LAUNCH.md` or a one-off. Use the post's
short name from `LAUNCH.md`'s "Suggested LinkedIn posting order" list
where one exists, so the two documents stay easy to cross-reference.

## Other platforms

LinkedIn is the only channel actually in progress. Drafts for these exist
in `LAUNCH.md` (Rampart) — finalized with real links, ready whenever
started. Not started yet as of 2026-09-30.

| Platform | Post | Status |
|---|---|---|
| Show HN | `Show HN: Rampart – self-hosted WAF/rate-limiter/OIDC gateway, one binary` | not started |
| r/netsec | `Rampart: self-hosted WAF + rate-limiting + OIDC RBAC gateway, benchmarked with GoTestWAF` | not started |
| r/selfhosted | `Rampart – one binary for WAF + rate limiting + login-protected dashboard, in front of any app` | not started |
