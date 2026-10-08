# Deployment

Three ways to run Rampart, roughly in order of how much infrastructure you
already have.

## Docker (single host)

```sh
docker build -t rampart .
docker run -d -p 8080:8080 -p 127.0.0.1:9090:9090 \
  -v $(pwd)/configs/rampart.yaml:/app/configs/rampart.yaml:ro \
  -v $(pwd)/configs/waf-custom-rules:/app/configs/waf-custom-rules:ro \
  -v $(pwd)/configs/schemas:/app/configs/schemas:ro \
  -v rampart-data:/data \
  rampart
```

The image is distroless and runs as non-root (UID 65532). `/app` is
read-only; `/data` is the only writable path (event log) — see finding #5
in [FINDINGS.md](FINDINGS.md) for why that split exists. Mounting a
host config file that doesn't exist yet silently creates an empty
directory instead — create `configs/rampart.yaml` from the example first.

For a zero-setup demo against OWASP Juice Shop: `docker compose up`.

**Troubleshooting:** if `docker compose up` starts both containers but
Rampart logs `dial tcp: lookup <service> on ...: no such host` and it
doesn't clear up within a few seconds, the demo target's network
attachment didn't register — `docker compose down && docker compose up`
resolves it. Seen as a one-off in local testing (Docker/OrbStack network
registration race at stack startup), not a compose file issue — a fresh
recreate reliably fixes it.

## Kubernetes (Helm)

```sh
helm install my-rampart ./deploy/helm/rampart --set upstream=http://myapp:8080
```

Supports three deployment patterns (standalone, sidecar, ingress-exposed)
— see [deploy/helm/rampart/README.md](../deploy/helm/rampart/README.md)
for the detail on each. Pod runs non-root with `readOnlyRootFilesystem:
true` and all capabilities dropped, matching the Docker image's security
posture.

Verification status: `helm lint` and `helm template` both pass cleanly
across every optional feature (custom WAF rules, API-abuse rules, schema
validation, ingress) — see the chart's `values-full-example.yaml`. Not
deployed against a live cluster in this environment (would have required
starting a local cluster, judged not worth the resource cost for a chart
whose templates already render correctly); do a `helm install --dry-run`
against a real cluster before trusting it in production.

## AWS (Terraform, ECS Fargate)

```hcl
module "rampart" {
  source = "./deploy/terraform/aws-ecs-fargate"
  # see deploy/terraform/aws-ecs-fargate/README.md
}
```

ECS Fargate service behind an ALB, with the dashboard on a separately
security-group-restricted listener (never put it on `0.0.0.0/0` — it has
no auth of its own). Put this behind AWS Shield if you need volumetric
DDoS protection ahead of it — see [NETWORK_HARDENING.md](NETWORK_HARDENING.md).

Verification status: written carefully against the documented
`hashicorp/aws` provider schema, but not run through `terraform validate`
— the CLI wasn't available in this environment. Run `terraform validate`
yourself before applying.

## Common to all three

- The dashboard (`dashboard.enabled` / Helm's `dashboard.enabled` / Terraform's
  `dashboard_port`) has no authentication yet. Every deployment path here
  defaults to keeping it off a public interface, or requires you to
  explicitly widen it — don't override that without putting an
  authenticating proxy in front of it.
- `configs/waf-custom-rules/` and `configs/schemas/` are how you extend
  detection without touching Go code — see their own READMEs.
- **Behind a load balancer, Ingress or CDN, set `trusted_proxies`**
  (Helm: `trustedProxies`) to that proxy's CIDR. Left empty, every user
  looks like the proxy: one attacker's login lockout hits everyone, and
  per-IP rate limiting becomes one shared limit. Only listed proxies get
  `X-Forwarded-For` honored, so the header can't be spoofed by direct
  clients. Details in [docs/FINDINGS.md #12](FINDINGS.md).
- **Set `allowed_hosts`** (Helm: `allowedHosts`) to the hostnames you
  serve. Any other `Host` or `X-Forwarded-Host` gets a 403, which stops the
  attack that puts an attacker's domain into password-reset links. Include
  every name your load balancer or Ingress forwards. Off by default.
  Kubernetes probes here are TCP checks, so they are unaffected; an HTTP
  probe would send the pod IP as `Host` and be rejected unless you add that
  or set the probe's host header.
- **TLS:** most deployments terminate TLS *in front of* Rampart (a cloud
  load balancer, an Ingress controller, Cloudflare) and leave `tls.enabled`
  off — that's the common case and needs nothing here. If you'd rather
  Rampart terminate TLS itself, set `tls.enabled: true` plus `cert_file` /
  `key_file` (PEM, your own cert — no ACME/auto-provisioning). Applies to
  both the main proxy and the dashboard listener. See the scope note in
  [docs/DETECTION.md](DETECTION.md#out-of-scope-on-purpose-networktransport-layer-attacks)
  for what this does and doesn't protect against.
