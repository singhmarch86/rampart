# Rampart

A self-hosted, open-core firewall and attack-analytics platform. Rampart sits
in front of your application as a reverse proxy and blocks network-, application-,
and API-layer attacks in one place, then gives you a single dashboard to see
what was blocked and why.

## Why

Most teams stitch together nginx + ModSecurity + fail2ban + a log pipeline +
a dashboard to get this. Rampart aims to ship it as one binary with sane
defaults, so a small team gets WAF + rate-limiting + analytics without
assembling five tools.

## Status

Early development. Not production-ready yet. See [docs/ROADMAP.md](docs/ROADMAP.md).

## Scope

- **Network layer** — IP allow/deny lists, rate limiting, geo-blocking, connection-flood mitigation
- **Application layer (WAF)** — OWASP Top 10 detection via the Coraza engine + OWASP Core Rule Set
- **API / mobile-backend layer** — credential-stuffing detection, token-abuse detection, request-schema validation
- **Analytics** — attack timeline, top attackers, rule-hit dashboard
- **Cloud-native** — Docker image, Helm chart, Terraform module

## License

Apache 2.0 — see [LICENSE](LICENSE). The core engine is and will remain free
and open source. A hosted analytics console (multi-node management, longer
retention, threat-intel feed) is planned as a paid add-on; it will never be
required to run the core firewall.

## Quick start

```sh
go build -o bin/rampart ./cmd/rampart
cp configs/rampart.example.yaml configs/rampart.yaml
# edit configs/rampart.yaml: set upstream to the app you're protecting
./bin/rampart -config configs/rampart.yaml
```

Rampart listens on `listen` (default `:8080`) and proxies allowed traffic to
`upstream`. Every block decision (IP filter, rate limit, or WAF) is written
as a JSON line to `logging.events_path`.

## Progress

- [x] **Phase 1** — network-layer core (reverse proxy, IP allow/deny, rate limiting, event log)
- [x] **Phase 2** — application WAF (Coraza + OWASP CRS, custom SecLang rules, verified live against OWASP Juice Shop). See [benchmarks/](benchmarks/) for GoTestWAF results.
- [ ] Phase 3 — API / mobile-backend abuse detection
- [ ] Phase 4 — attack analytics dashboard
- [ ] Phase 5 — cloud-native packaging
- [ ] Phase 6 — community release

Full detail in [docs/ROADMAP.md](docs/ROADMAP.md).
