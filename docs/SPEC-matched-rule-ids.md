# Spec: record which rules fired (and make detect mode record anything)

Status: **proposed, not built.** Written 2026-10-08 from experiments on the
current code; every "verified" statement below was checked, and the open
questions at the end are what is not.

## Why

Block events say *that* something was blocked but not *which rules* made it
so. For a CRS block the reason is the last matched rule's message, which is
always the evaluation rule: `Inbound Anomaly Score Exceeded (Total Score: 5)`.
You can't tell from the log whether that 5 was a SQL-injection rule or a
false positive on a harmless field, and tuning CRS (exclusions, paranoia
level) needs exactly that. This session hit it repeatedly: I couldn't say
which rule blocked `${7*7}` or `;id`, and had to use throwaway tests to look.

Related bug found while checking this: detect mode, the documented way to
preview a stricter setting, writes nothing to the event log
(`docs/FINDINGS.md` #16). Per-rule data is worthless for tuning if the
preview mode records nothing, so fixing that is phase 0.

## What was verified

All against `coraza/v3` v3.7.0 and CRS v4.25.0, via throwaway tests:

1. `tx.MatchedRules()` holds about 63 entries per request, **even for a
   clean request**. Almost all are CRS bookkeeping (initialization and
   paranoia-gate rules like 901100, 934013): severity unset (-1), empty
   message, variable `TX:*`.
2. A real detection is distinguishable. For `' OR '1'='1`, rule 942100 had
   severity 2, tags `paranoia-level/1` and `attack-sqli`, matched variable
   `ARGS:q`, message "SQL Injection Attack Detected via libinjection".
3. `MatchedRule.Disruptive()` is `true` for every entry in block mode
   (bookkeeping included), so it can't be used as a filter.
4. The evaluation rule 949110 (`Inbound Anomaly Score Exceeded`) appears in
   the matched list **in detect mode too**, flagged non-disruptive, and not
   at all for a clean request. Its matched variable is
   `TX:blocking_inbound_anomaly_score`, whose value is the score.
5. Detect mode writes 0 bytes to the event log; block mode writes one event
   for the same request (#16).
6. The matched data exposes the variable name and key (`ARGS:q`) separately
   from its value, so the name can be logged without the attacker's payload.

## Goals

- Every WAF event (block or would-be block) lists the rules that
  contributed, with enough detail to write a targeted exclusion.
- Detect mode emits events for requests that would have been blocked.
- No change to existing fields, so current readers keep working.
- No attacker-supplied payload text in events by default.

## Non-goals (for now)

- Recording *allowed* traffic or full payloads (needed for the learning ideas
  later; a separate decision with its own privacy review).
- Suggesting exclusions automatically. This spec only makes the data exist.
- Changing what gets blocked.

## Design

### Event schema (additive)

New optional fields on `events.Event`, all `omitempty`:

```json
{
  "action": "block",
  "layer": "waf",
  "reason": "Inbound Anomaly Score Exceeded (Total Score: 5)",
  "score": 5,
  "rules": [
    {"id": 942100, "msg": "SQL Injection Attack Detected via libinjection",
     "severity": 2, "pl": 1, "tags": ["attack-sqli"], "var": "ARGS:q"}
  ],
  "rules_omitted": 0
}
```

- `score`: the value of `TX:blocking_inbound_anomaly_score` read from rule
  949110's matched data (not parsed out of the message text).
- `rules`: the contributing rules, selected as below, in match order, capped
  at 10; `rules_omitted` counts the rest.
- `pl`: from the rule's `paranoia-level/N` tag (omitted if absent, e.g. custom
  rules). `var`: variable name and key only, never the value.

### Which matched rules count as "contributing"

Include a matched rule when its severity is set (>= 0) **and** its message is
non-empty, **or** its ID is in the custom range (>= 1,000,000) with a
non-empty message. Exclude the evaluation rules (949110, 959100) themselves
since they're already summarized by `reason` and `score`. This drops the
~60 bookkeeping rules (verified above) and keeps CRS detections and ours
(custom rules set `severity`).

### Detect mode

A new `Action` value, `"detect"`, meaning "would have been blocked". After
request processing in detect mode, if rule 949110 (or the outbound
equivalent) is in the matched list, emit an event with `action: "detect"`
and the same `score` and `rules` as a block would carry, then let the
request continue. A clean request emits nothing.

### Consumers (must change together, or detect events corrupt the counts)

- `internal/analytics/store.go` and `internal/analyze/aggregate.go` count
  **every** event as a block, and `docs/ANALYZE.md` and the comment atop
  `aggregate.go` both state that every event in the log is a block decision.
  Detect events break that assumption. Both must either skip
  `action: "detect"` in block counts or count it separately; the dashboard
  should label them "would block".
- Phase 2 adds a "Top rules" view keyed on rule ID (the data this exists for).
- `eventlog.Read` decodes into the struct, so unknown fields are ignored;
  old logs without the new fields still parse.

### Privacy

- The dashboard serves recent events over its API, publicly on the demo, and
  already includes client IPs and request paths. New fields must be no more
  sensitive than that: rule IDs, messages, severities, tags and variable
  names are fine; matched **values** (attacker input, which can contain
  tokens or passwords from a mis-targeted field) are not logged.
- An opt-in `logging.include_matched_values` (default off, truncated to 64
  bytes, with a warning) is deferred to a later phase and needs its own
  decision.

## Phases

0. **Detect-mode events** (fixes #16). Smallest change and the prerequisite:
   emit `action: "detect"` events, update the two consumers so counts stay
   correct, add the docs fix. Tests: detect mode logs an event for an attack
   and none for a clean request; block counts unchanged.
1. **Rule details on events.** Add `score`, `rules`, `rules_omitted`;
   selection logic above; tests with the real CRS (attack gives the expected
   rule ID and `ARGS:q`; a clean request gives no rules; a custom rule
   appears with its ID).
2. **Dashboard and report.** "Top rules" panel and a rules table in
   `rampart-analyze`; `docs/DETECTION.md` section on reading it.
3. **Later, separately decided:** allowed-traffic sampling, opt-in matched
   values, exclusion suggestions.

## Open questions

- Is severity-set the right filter for every CRS version, or do some real
  detections lack a severity? Check against a broader payload set in phase 1
  (the experiment used one SQLi payload).
- Chained rules: Coraza reports one match per chain; confirm which variable
  and message are attributed.
- Event size: confirm 10 rules fits comfortably in the dashboard's recent-
  events buffer and the JSONL file at realistic attack volumes.
- Does the outbound path (response-side blocks, 959100) need the same
  treatment? It looked relevant for the XXE probe at higher paranoia levels,
  where the "block" was on the response, so probably yes.

## Not decided here

Whether detect events should also be written when the engine is in block
mode but the request was below the threshold (near misses). Useful for
tuning, but it's more volume and a different feature.
