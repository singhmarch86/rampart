# rampart-analyze: offline attack triage

`rampart-analyze` reads a window of Rampart's JSONL event log and produces
a Markdown triage report: top attackers, top block reasons, IPs that
triggered more than one detection layer, and traffic bursts. It's a
separate binary from `rampart` itself — the core proxy has no dependency
on this tool or on any external API, so running the firewall never
requires network access beyond your own upstream.

Reports also include a **Top WAF rules** table (rule ID, attack class,
description, hits) built from the `rules` on WAF events. It counts blocked and
detect-mode ("would block") events alike, since it answers "which rules fire".
Events logged before this field existed simply contribute no rules.

## Scope — read this before trusting a report

Every event in `rampart-events.jsonl` is a **block** decision (the one
exception: with `waf.mode: detect` the WAF logs `"action":"detect"` events
for requests it would have blocked but let through; the report counts these
on a separate line and keeps them out of every block figure) recording
only `time`, `layer`, `reason`, `client_ip`, `method`, and `path` (see
`internal/events`). No layer logs allowed traffic, and none capture the
request payload (query string or body).

That means this tool can summarize and triage attacks Rampart **already
caught**. It cannot, and doesn't claim to:

- **Find gaps in detection coverage.** An attack that slipped through was,
  by definition, never blocked, so it never appears in this log. Finding
  gaps needs an independent, labeled benchmark instead — see
  [docs/FINDINGS.md #2](FINDINGS.md#2-waf-0-block-rate-on-base64-encoded-attack-payloads),
  where GoTestWAF (not this tool) found the base64-evasion gap.
- **Draft a new detection rule.** There's no request payload in the log to
  base one on — only a fixed reason string per rule that already fired.

What it's actually for: turning "here's 4,000 log lines" into "here's what
happened, and what's worth a human decision" — e.g. a persistent
multi-vector attacker worth an explicit `firewall.deny` entry, or a burst
worth reviewing as scripted traffic.

## Usage

```sh
go build -o bin/rampart-analyze ./cmd/rampart-analyze
./bin/rampart-analyze -events rampart-events.jsonl -since 168h -out report.md
```

- `-events` — path to the JSONL log (matches `logging.events_path` in your
  `rampart.yaml`). Defaults to `rampart-events.jsonl`.
- `-since` — how far back to include (default `168h`, one week).
- `-out` — where to write the Markdown report (default `rampart-report.md`).
- `-narrate` — add a plain-English summary on top of the tables, written by
  Claude via the Anthropic API (default `true`, but automatically skipped
  with a warning if `ANTHROPIC_API_KEY` isn't set — the tables-only report
  still gets written either way). The model is told explicitly what it
  does and doesn't have (see `internal/analyze/llm.go`'s system prompt):
  no drafting rules, no claiming to have found a coverage gap, stick to
  the aggregated counts it was given.

## What it produces

A Markdown file with:

- Per-layer counts
- Top attacker IPs
- Top block reasons
- Most-targeted paths
- IPs that triggered more than one detection layer ("multi-vector")
- Traffic bursts (≥10 blocked requests from one IP within 5 minutes — a
  simplified, fixed-bucket signal for "this looks scripted," not a precise
  sliding-window count; see `internal/analyze/aggregate.go`'s doc comment)

The deterministic tables are the source of truth; the narrative section
(when present) is clearly labeled as commentary on top of them, not a
separate claim.

## Design note: why a separate binary

`rampart` itself has zero dependency on this package or on any external
API — building and running the firewall never requires an Anthropic API
key or outbound network access beyond your configured `upstream`. Keeping
`rampart-analyze` as its own `cmd/` entry point, rather than a subcommand
of `rampart`, keeps that boundary at the build-dependency level, not just
a runtime flag.
