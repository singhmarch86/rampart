# Plain Kubernetes manifests

For `kubectl apply` directly, no Helm required. Equivalent to the Helm
chart's defaults (`deploy/helm/rampart`) — same security posture
(non-root, read-only rootfs, dropped capabilities), same ports, same
volumes — just as static YAML instead of a templated chart.

**Use this if:** you just want `kubectl apply -f deploy/k8s/` to work,
you don't use Helm, or you're hand-editing manifests as part of a
GitOps flow (Argo CD, Flux) that applies raw YAML.

**Use the Helm chart instead if:** you want `--set` overrides,
multiple releases with different values, or you're already using Helm
for everything else in the cluster. See
[deploy/helm/rampart/README.md](../helm/rampart/README.md).

## Usage

1. Edit `configmap.yaml` — set `upstream` to the application you're
   protecting (there's no sensible default, same as every other
   deployment path documented in
   [docs/DEPLOYMENT.md](../../docs/DEPLOYMENT.md)). For an in-cluster
   app: `http://<service-name>.<namespace>.svc.cluster.local:<port>`.
2. Build and push the image somewhere your cluster can pull it (or load
   it into a local cluster like kind/minikube), then update the
   `image:` field in `deployment.yaml` if it's not `rampart:latest` on
   the same node.
3. Apply:

```sh
kubectl apply -f deploy/k8s/
```

4. Check it's up:

```sh
kubectl get pods -l app.kubernetes.io/name=rampart
kubectl port-forward svc/rampart 8080:8080 9090:9090
```

## What's not here

- **Custom WAF rules / JSON schemas** (`configs/waf-custom-rules/`,
  `configs/schemas/` in the main repo) — not wired into these manifests.
  Add your own ConfigMap(s) and volume mounts following the pattern in
  `configmap.yaml`/`deployment.yaml` if you need them; the Helm chart's
  `customWafRules`/`schemas` values do this automatically if you'd
  rather use Helm for that.
- **Ingress** — point your cluster's existing ingress controller at the
  `rampart` Service (port 8080) the same way you would any other
  backend. No Ingress resource is included here since ingress-controller
  choice and annotations vary too much to have one sensible default.
- **TLS** — off by default, same as everywhere else (see the `tls.*`
  note in [docs/DEPLOYMENT.md](../../docs/DEPLOYMENT.md)). Most
  Kubernetes deployments terminate TLS at the Ingress instead.
