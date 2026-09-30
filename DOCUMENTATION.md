# Documentation

An index of everything in this repo. Start with **Quick start** below if
you just want to run it; everything else is organized by what you're
trying to do.

## Quick start

```sh
go build -o bin/rampart ./cmd/rampart
cp configs/rampart.example.yaml configs/rampart.yaml
# edit configs/rampart.yaml: set upstream to the app you're protecting
./bin/rampart -config configs/rampart.yaml
```

Or, zero-setup: `docker compose up` — runs Rampart in front of a bundled
OWASP Juice Shop instance. Attack it at `localhost:8080`, dashboard at
`localhost:9090`.

A single-page HTML reference with the same content plus config tables and
inline samples: [docs/manual.html](docs/manual.html).

## How Rampart works

| Doc | What it covers |
|---|---|
| [README.md](README.md) | What Rampart is, why it exists, current scope |
| [docs/DETECTION.md](docs/DETECTION.md) | How each of the four detection layers (WAF, API-abuse, schema validation, rate limiting) decides what counts as an attack, with real examples |
| `internal/config/config.go` | The full configuration struct — every YAML key, its type, default, and validation rule, as Go doc comments |

## Integrating and deploying

| Doc | What it covers |
|---|---|
| [docs/OIDC.md](docs/OIDC.md) | Dashboard login and API role enforcement against an existing identity provider (Keycloak, Auth0, Okta, ...) |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Docker, Helm (Kubernetes), and Terraform (AWS ECS Fargate) |
| [docs/NETWORK_HARDENING.md](docs/NETWORK_HARDENING.md) | Network-layer hardening beyond what Rampart itself does (DDoS protection, OS-level firewall) |
| [docs/ANALYZE.md](docs/ANALYZE.md) | `rampart-analyze` — the offline tool that turns the block-event log into a triage report, and exactly what it can't tell you |

## Evidence — verify, don't just claim

| Doc | What it covers |
|---|---|
| [docs/FINDINGS.md](docs/FINDINGS.md) | Every real bug or vulnerability found in Rampart itself during development (8 so far), with root cause, fix, and how the fix was verified |
| [benchmarks/RESULTS.md](benchmarks/RESULTS.md) | GoTestWAF benchmark results, including a from-scratch comparison against standalone ModSecurity (the trustworthy external baseline published numbers online don't provide) |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Phase-by-phase build history, what's done, what's deliberately parked and why |

## Project

| Doc | What it covers |
|---|---|
| [SECURITY.md](SECURITY.md) | How to report a vulnerability (not via a public issue) |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community guidelines |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [docs/LAUNCH.md](docs/LAUNCH.md) | Draft launch posts (Show HN, Reddit, LinkedIn) — internal, not for external linking |
| [docs/POSTING_LOG.md](docs/POSTING_LOG.md) | Which drafts have actually been handed over and (self-reported) posted — internal |
| [docs/VIDEO_SCRIPTS.md](docs/VIDEO_SCRIPTS.md) | Outlines for demo videos — internal, not for external linking |
