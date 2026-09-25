# Roadmap

| Phase | Scope |
|---|---|
| 0. Foundations | Repo scaffold, license, architecture doc |
| 1. Network-layer core | Reverse proxy, IP allow/deny, rate limiting, geo-blocking, connection-flood mitigation, YAML rule config |
| 2. Application WAF | Coraza + OWASP CRS integration, custom rule DSL, validated against OWASP Juice Shop |
| 3. API / mobile-backend protection | Credential-stuffing detection, token-abuse detection, REST/GraphQL schema validation |
| 4. Attack analytics dashboard | Event pipeline, local storage, web dashboard |
| 5. Cloud-native packaging | Docker image, Helm chart, ingress/sidecar mode, Terraform module |
| 6. Community release | Public launch, docs site, hosted Console (paid tier) |
