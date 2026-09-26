# Roadmap

| Phase | Scope |
|---|---|
| 0. Foundations | Repo scaffold, license, architecture doc |
| 1. Network-layer core | Reverse proxy, IP allow/deny, rate limiting, geo-blocking, connection-flood mitigation, YAML rule config |
| 2. Application WAF | Coraza + OWASP CRS integration, custom rule DSL, validated against OWASP Juice Shop |
| 3. API / mobile-backend protection | Credential-stuffing detection, token-abuse detection, REST/GraphQL schema validation |
| 4. Attack analytics dashboard | Event pipeline, local storage, web dashboard |
| 5. Cloud-native packaging | Docker image, Helm chart, ingress/sidecar mode, Terraform module |
| 5.5 OIDC integration | Dashboard login + API role/permission enforcement against an existing IdP (Keycloak, Auth0, Okta, ...); not an identity provider itself |
| 6. Community release | CI, security disclosure policy, contribution docs, issue/PR templates, launch materials — **done** |
| 7. Hosted Console (paid tier) | Separate SaaS build: multi-node fleet management, longer retention, threat-intel feed. Not started. |

## Known limitations (tracked, not yet implemented)

- **RP-initiated logout**: `/auth/logout` clears Rampart's own session but doesn't log the user out of the upstream IdP. If the IdP session is still active, the dashboard may silently re-authenticate on next visit.
- **Dashboard authentication has no rate limiting of its own** on the login/callback endpoints — relies on the IdP's own protections.
- **No live cluster verification for the Helm chart** — `helm lint`/`helm template` pass cleanly, but it hasn't been deployed to a real Kubernetes cluster in this project's testing so far.
- **Terraform module untested via `terraform validate`** — the CLI wasn't available in the environment this was built in; written carefully against the documented provider schema but not run.
