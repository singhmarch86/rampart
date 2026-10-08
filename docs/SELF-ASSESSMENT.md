# Self-assessment: scanning your own Rampart deployment

`scripts/security-assessment.sh` looks at a running Rampart the way a
scanner or attacker would first look at it, using standard tools (nmap,
openssl, curl). It checks the **deployment**; `scripts/test-attacks.sh` and
`scripts/test-crs-coverage.sh` check the **detection rules**.

```sh
./scripts/security-assessment.sh --i-own-this
HOST=203.0.113.7 HTTP_PORT=443 TLS=1 ./scripts/security-assessment.sh --i-own-this
```

**Only run it against systems you own or are authorized in writing to
test.** The `--i-own-this` flag exists so it can't be run by accident; it is
not a substitute for authorization. Settings (`HOST`, `HTTP_PORT`, `TLS`,
`DASH_PORT`, `ALLOWED_PORTS`, `SCAN_RANGE`, `SLOW`) are documented at the top
of the script.

## What it checks

| Area | Check | Verdict |
|---|---|---|
| Ports | nmap TCP scan of `SCAN_RANGE`: anything open outside `ALLOWED_PORTS` | FAIL |
| Ports | dashboard port reachable when it should not be (it has no auth unless OIDC is on) | FAIL |
| TLS | server accepts TLS 1.0 or 1.1 (nmap `ssl-enum-ciphers`) | FAIL |
| TLS | server accepts 1.2 / 1.3; no cipher graded D or worse; certificate subject/expiry | PASS / INFO |
| HTTP | `TRACE` or `CONNECT` returns 200 | FAIL |
| HTTP | a SQL-injection probe is blocked; the block page leaks no engine or rule details | PASS / FAIL |
| HTTP | 70 KB request header does not cause a 5xx | FAIL on 5xx |
| HTTP | banners (`Server`, `X-Powered-By`) and missing security headers | INFO only |
| Slow clients | `SLOW=1`: a client dripping a header is cut off (plain HTTP only) | PASS / FAIL |

Missing security headers (HSTS, CSP, X-Frame-Options...) are reported as
information, not failures: Rampart doesn't add them, they belong to the app
or the layer in front.

## Results, 2026-10-08

Run against a local build of the current code: Rampart with TLS (self-signed
certificate), the dashboard on loopback, WAF in block mode, in front of a
plain Python file server, `SCAN_RANGE=18000-19999` (scoped, because scanning
a whole laptop reports everything else running on it).

**Scanned via the machine's LAN address: 14 passed, 0 failed.** Only the
proxy port open; dashboard (bound to `127.0.0.1`) not reachable; TLS 1.0 and
1.1 refused, 1.2 and 1.3 accepted, no weak ciphers; `TRACE` and `CONNECT`
not honored (403); SQL-injection probe blocked; block page reveals nothing
about the engine; oversized header answered with 431.

**Scanned via loopback: 12 passed, 2 failed**, correctly: from the machine
itself the dashboard port and the upstream's port are reachable. This is the
intended behavior of the check, and a reminder that a result depends on
where you scan from.

**Negative controls** (a check that can't fail proves nothing):
- An `openssl s_server` restricted to TLS 1.0: the script reports
  `FAIL server accepts TLSv1.0`.
- The loopback run above shows the port checks do fail.

## Mistakes caught while building it

- The first oversized-header test used curl's default HTTP/2, where curl
  itself warned the stream might be rejected: it measured the client, not
  the server. Forced to HTTP/1.1, the server answers `431`.
- The TLS check uses nmap's protocol enumeration rather than only
  `openssl s_client -tls1`: a modern OpenSSL may refuse to offer TLS 1.0 at
  all, which would "pass" for the wrong reason.

## Not covered, and not run

- **The app behind Rampart.** A closed front door says nothing about the
  application. For a web-application scan, OWASP ZAP's baseline scan against
  a local Rampart + Juice Shop would be the next step; **it has not been run**
  (the container image is large and was not downloaded).
- The public demo VM was **not** scanned in this pass. It is the owner's
  resource and the script works against it, but it is a deliberate action
  for them to start (see `HOST=`).
- Vulnerability scanners (nikto, nuclei), UDP, and service-version probing
  (`nmap -sV`) are not included.
- Reachability from other networks (cloud firewall rules) can only be
  tested from those networks.
