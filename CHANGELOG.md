# Changelog

## v0.1.0 — initial release

First public release. All of the following is implemented, tested, and
verified against real running targets (OWASP Juice Shop, a real Keycloak
instance) — see [docs/FINDINGS.md](docs/FINDINGS.md) for the bugs found
and fixed along the way, and [benchmarks/RESULTS.md](benchmarks/RESULTS.md)
for independent WAF benchmark numbers.

- **Network layer**: reverse proxy, IP allow/deny, per-IP rate limiting
- **Application WAF**: Coraza + OWASP Core Rule Set, custom SecLang rule
  support, benchmarked with GoTestWAF
- **API abuse detection**: credential-stuffing/token-abuse blocking, JSON
  Schema request validation
- **Live analytics dashboard**: top attackers, block reasons, timeline,
  live event feed over SSE
- **Cloud-native packaging**: Docker (distroless, non-root), Helm chart,
  Terraform module for AWS ECS Fargate
- **OIDC integration**: dashboard login and API role/permission
  enforcement against an existing identity provider (Keycloak, Auth0,
  Okta, ...)

License: Apache 2.0.
