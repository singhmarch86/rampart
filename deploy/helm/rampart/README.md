# Rampart Helm chart

```sh
helm install my-rampart ./deploy/helm/rampart --set upstream=http://myapp:8080
```

See `values.yaml` for every option, and `values-full-example.yaml` for one
that exercises all of them together (API-abuse rules, schema validation,
custom WAF rules, ingress).

## Deployment patterns

### Standalone (what this chart does)

Rampart runs as its own Deployment + Service, in front of your app's
existing Service. Traffic flow: `client -> Ingress (optional) -> Rampart
Service -> Rampart Pod -> your app's Service -> your app`. Set `upstream` to
your app's in-cluster address
(`http://<service>.<namespace>.svc.cluster.local:<port>`). This is the
right choice when you want one Rampart deployment protecting one or more
backend services, scaled and upgraded independently of them.

### Sidecar

Run a Rampart container in the **same pod** as your app, with `upstream`
pointing at `http://localhost:<your-app-port>` — traffic reaches the pod,
hits Rampart first, and Rampart forwards to the app container over
loopback. This chart does not do this automatically (that would require a
mutating admission webhook to inject a container into pods it doesn't own,
which is out of scope here — see the note in `docs/ROADMAP.md` in the main
repo). Instead, copy the container spec this chart generates
(`helm template ... | yq '.spec.template.spec.containers[] | select(.name
== "rampart")'` is a quick way to extract it) into your own app's pod
template, and change `upstream` to `http://localhost:<port>`. Use this when
you want per-pod isolation and don't want a separate Rampart
Deployment/Service to manage.

### Ingress

Set `ingress.enabled: true` to put a standard Kubernetes `Ingress` resource
in front of Rampart's proxy Service, so Rampart sits behind your cluster's
existing ingress controller (nginx-ingress, etc.) like any other backend.
This chart creates the `Ingress` object; it does not implement an ingress
controller itself.

**Do not** enable `dashboardIngress` without adding authentication via your
ingress controller's annotations — the dashboard has no auth of its own yet
(tracked in `docs/ROADMAP.md`).

## Security defaults

The Pod runs as non-root (UID 65532, matching the Dockerfile's distroless
image) with `readOnlyRootFilesystem: true` and all capabilities dropped.
The only writable path is `/data` (an `emptyDir`), which is where the event
log lives — this is why the image's Dockerfile separates `/app`
(read-only) from `/data` (writable); see finding #5 in
`docs/FINDINGS.md` in the main repo for how that split came about.
