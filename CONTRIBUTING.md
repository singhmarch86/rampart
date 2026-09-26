# Contributing to Rampart

Thanks for considering it. This project holds itself to a "verify, don't
just claim" standard (see [docs/FINDINGS.md](docs/FINDINGS.md)) — the same
bar applies to contributions.

## Before you start

- For anything non-trivial, open an issue first to discuss the approach.
  Saves you rewriting a PR that doesn't fit the project's direction.
- Check [docs/ROADMAP.md](docs/ROADMAP.md) — if it's already planned,
  say so in your issue rather than duplicating effort.

## Development setup

```sh
go build -o bin/rampart ./cmd/rampart
go test ./...
go vet ./...
gofmt -l .   # should print nothing
```

For live testing against a real target:
```sh
docker run -d -p 3000:3000 bkimminich/juice-shop
cp configs/rampart.example.yaml configs/rampart.yaml
./bin/rampart -config configs/rampart.yaml
```

## What a good PR looks like here

- **Tests, not just a working demo.** Every existing feature has unit
  tests; new ones should too. If you're touching the WAF, apiabuse, or
  oidcauth packages, look at their `*_test.go` files for the expected bar
  (e.g. `internal/oidcauth` signs real JWTs against a mock JWKS server
  rather than stubbing verification).
- **`go test -race ./...` passes.** Several packages have concurrent
  state (rate limiter, apiabuse guard, analytics store); race conditions
  here are real bugs, not theoretical.
- **If you found a real bug while building this, it goes in
  `docs/FINDINGS.md`**, not just fixed silently. What you found, how, the
  fix, how you verified it. See existing entries for the format.
- **`gofmt` clean, `go vet` clean.** CI checks both.

## Reporting bugs vs. vulnerabilities

Regular bugs: open a GitHub issue.

Security vulnerabilities (WAF bypass, auth bypass, privilege escalation,
DoS): see [SECURITY.md](SECURITY.md) — do not open a public issue.

## Adding WAF rules or JSON Schemas

Custom rule/schema examples live in `configs/waf-custom-rules/` and
`configs/schemas/`. If you're adding a genuinely useful detection rule
(not project-specific), consider contributing it there with a comment
explaining what it catches and why the default OWASP CRS doesn't already
cover it — see `configs/waf-custom-rules/02-anti-evasion-base64.conf` for
the expected level of detail.

## Code style

Standard Go idioms. No comments explaining *what* code does (names should
do that) — comments should explain *why*, when it's non-obvious. See the
existing codebase for the expected voice; a lot of the "why" here comes
from bugs found during development, and it's worth preserving that context
rather than trimming it out.
