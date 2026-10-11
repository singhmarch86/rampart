# LinkedIn group "WAF Security": growth plan

Internal, not for external linking. Written 2026-10-11.

What this can and can't do: it is a plan plus ready-to-paste text. Nothing
here posts, invites or messages anyone; you do that. No growth number is
promised, because none of these are measured yet. Track the numbers in the
last section and keep what works. LinkedIn changes group features and limits
often, so check the current settings screen before relying on any detail.

## Why a group stays small by default

A group only grows when (1) people can find it, (2) the first screen tells
them why to join, and (3) there is something worth coming back to. Most new
groups fail on the third: a few posts, no replies, then silence, which a new
visitor reads as a dead group and leaves.

## 1. Setup checklist (do once, 20 minutes)

- [ ] **Listed in search**: set the group to be discoverable, not hidden.
- [ ] **Name**: "WAF Security" is clear. Consider adding the audience:
      "WAF Security: practical web application firewall tuning". Keywords in
      the name are what search matches.
- [ ] **Description** (first ~2 lines are what people see; text below):
- [ ] **Rules** (short, below): groups with visible rules get less spam.
- [ ] **Cover image and logo**: a simple dark card with the group name and
      "OWASP CRS - Coraza - ModSecurity - tuning - false positives".
- [ ] **Pin a welcome post** (below) so a visitor sees activity and a prompt.
- [ ] **Turn on join requests** with a one-question screen ("What do you
      work on?") only if spam appears; open joining grows faster.

### Description (paste)

> Practical, vendor-neutral discussion of web application firewalls:
> tuning OWASP CRS, ModSecurity and Coraza, cutting false positives,
> detect-mode rollouts, rate limiting and API protection. Real configs and
> real test results welcome; sales pitches are not. New here? Introduce
> yourself and tell us which WAF you run.

### Rules (paste)

> 1. Be specific: share the rule, the log line, the number. No vague claims.
> 2. No product pitches or recruiter posts. One link to your own project per
>    post is fine if it adds something.
> 3. Test only systems you own or are authorized to test. No help attacking
>    other people's sites.
> 4. Say when you are not sure. "I haven't verified this" is welcome.

## 2. Seed the first 30 days

Post 3 times a week for the first four weeks, and reply to every comment the
same day. A visitor judges the group by its last three posts.

### Welcome post (pin it)

> Welcome to WAF Security.
>
> This group is for people who run, tune or break web application
> firewalls: ModSecurity, Coraza, OWASP CRS, cloud WAFs, anything.
>
> To get started, reply with:
> 1. Which WAF do you run (or want to)?
> 2. The most annoying false positive you've fought.
>
> I'll start: I run Coraza with OWASP CRS, and the first thing I learned is
> that detect mode only helps if it actually logs what it would have blocked.
> (Mine didn't until I checked.)

### Weekly rhythm (reuse what already exists in `LAUNCH.md`)

| Day | Post type | Source |
|---|---|---|
| Mon | **Tip**: one short WAF tip | Tips 1-10 in `LAUNCH.md` ("WAF tips" series), one per week |
| Wed | **Question** to the group | Prompts below |
| Fri | **Result**: a real measured finding | `docs/FINDINGS.md` entries, one per week |

Do not paste the same post in your profile feed and the group on the same
day; post the group version a day later with a different opening line.

### Ten discussion prompts (one per post, in the group)

1. What's the worst false positive you've had, and how did you exclude it
   without weakening the rule for everyone?
2. Paranoia level 1, 2 or 3 in production? What did you measure?
3. Detect mode first, then block: how long did you run detect mode before
   switching? What changed your mind?
4. Do you test your WAF with a payload suite (GoTestWAF, your own), or only
   look at logs? What did the suite find that logs didn't?
5. Where do you stop trusting `X-Forwarded-For`, and who sets it in your
   setup?
6. A WAF can't see inside gRPC or protobuf. What do you put in front of
   those?
7. Host header: do you pin the hostnames your apps serve, or trust whatever
   arrives? (Password-reset poisoning.)
8. Rate limiting at the WAF, the CDN, or the app? What broke when you moved
   it?
9. What does your WAF log, and what do you wish it logged? (Matched rule IDs?
   Allowed traffic samples?)
10. One rule you wrote yourself that CRS didn't have. What was the gap?

## 3. Bring people in (without spamming)

- **Footer on every profile post**: one line, no link spam. "Discussing WAF
  tuning in my group: WAF Security." Put the group link in the first comment
  rather than the body, which also tests whether links in the body cost reach.
- **Invite 1st-degree connections who work in security, DevOps or
  platform engineering**, with the message below. Invite a few each day, not
  all at once, and only people who would plausibly care.
- **Comment on other people's WAF and AppSec posts** with something useful
  (a measured number, a correction, a question), then mention the group only
  when it's relevant. Comments get seen by their audience, which is how a
  small account reaches new people.
- **GitHub**: add the group link to the repo's About box and the README
  "Community" section. Anyone who reads `docs/FINDINGS.md` is the right
  audience. (Ask before I edit those; the README is the public front page.)
- **Cross-link, don't duplicate**: in the group, link to the findings; in
  profile posts, link to the group once a week.

### Invite message (paste, edit the first line per person)

> Hi <name>, saw you work on <their area>. I started a small group for
> people tuning WAFs (ModSecurity, Coraza, OWASP CRS): real configs, false
> positives, what worked. No pitches. Would you join, or tell me what you'd
> want it to cover? <group link>

## 4. Make it worth returning to

- **A pinned "start here" post** listing the best five threads (update it
  monthly), so a new member isn't dropped into the feed cold.
- **A monthly roundup**: three best questions answered, one rule or exclusion
  shared, one number measured. Short.
- **Credit members** by name when they teach you something. People return to
  groups where they were thanked.
- **Moderate fast**: remove pitches and recruiter spam within a day. A
  spammy group stops getting organic joins.
- **Don't oversell**: say what you've verified and what you haven't, as in the
  posts so far. That candor is the group's differentiator against vendor
  pages.

## 5. Measure (check weekly, 5 minutes)

| Metric | Where | Why |
|---|---|---|
| Members, new per week | group page | growth |
| Posts and comments per week, and who comments | group page | health: aim for most posts getting a reply |
| Join source | ask in the welcome question ("how did you find us?") | which channel works |
| Profile post to group clicks | link in first comment, then LinkedIn's analytics | does cross-posting convert |

If after four weeks members are growing but comments aren't, the content
prompts are the problem. If comments are fine but members are flat,
discovery is the problem: more invites and more useful comments elsewhere.

## Not recommended

- Buying members or engagement pods: they inflate numbers with people who
  never read the group, and make real posts look dead by comparison.
- Mass auto-invites or DMs: they get accounts restricted and the group
  looks like spam.
- Reposting vendor marketing: the group's value is that it isn't.

## Appendix: first three group posts (final text)

Post these in order, a day or two apart, and reply to every comment the same
day. Replace `<GROUP LINK>` where it appears. Numbers are from this repo's own
measurements (`benchmarks/RESULTS.md`, `docs/FINDINGS.md`).

### Post 1 (day 1, pin it): welcome

Welcome to WAF Security.

This group is for people who run, tune or break web application firewalls: ModSecurity, Coraza, OWASP CRS, cloud WAFs, anything.

No pitches, no recruiter posts. Real configs, real log lines and real numbers are what make a group like this worth reading.

To get started, reply with:
1. Which WAF do you run (or want to)?
2. The most annoying false positive you've fought.
3. How did you find this group?

I'll go first: I run Coraza with OWASP CRS, and the first thing I learned is that "run it in detect mode first" only helps if detect mode actually logs what it would have blocked. Mine didn't, and I only noticed when I checked the log file.

### Post 2 (day 3): tip

Tip: read the rule IDs, not the score.

With OWASP CRS, almost every block says the same thing: "Inbound Anomaly Score Exceeded". SQL injection, XSS, path traversal, all identical. That message tells you the total crossed the threshold. It tells you nothing about which rule fired, so it tells you nothing about what to exclude.

What I do now is log the contributing rules with each event: the rule ID, its description, which parameter matched (never the value, because that's attacker input and can hold secrets).

Example from a real detect-mode run: a SQL injection string hit 942100 on the `q` parameter. A path traversal hit 930100, 930110 and 930120. A Log4Shell string hit 944150. Once you can see that, tuning stops being guesswork: a rule that keeps firing on legitimate traffic is the one to exclude.

One catch: a payload that mixes many attack types can trip well over a dozen rules, so cap what you log per event and count the rest.

What do you log per blocked request today?

### Post 3 (day 5): question

Question for the group: which paranoia level do you actually run in production, and what did you measure?

For reference, here's what I measured on OWASP CRS, with the same tool and the same target at each level (GoTestWAF against Juice Shop, one run each). "Detects" is the tool's application-attack score:

Level 1: detects 56%, wrongly blocks 13 of 141 legitimate samples (9%)
Level 2: detects 63%, wrongly blocks 53 of 141 (38%)
Level 3: detects 66%, wrongly blocks 61 of 141 (43%)
Level 4: detects 69%, wrongly blocks 141 of 141 (100%)

Caveats: one run per level, one target, and the legitimate set is 141 short synthetic samples, not real traffic. I'd treat the percentages as indicative only, which is why I'm asking.

- Which level are you on, and why?
- Did you move up from 1, and how did you find out what it would block before turning it on?
- Anyone running level 2 with exclusions? What did the exclusion list end up looking like?

Join the discussion: <GROUP LINK>
