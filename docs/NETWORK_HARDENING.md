# Network hardening beyond Rampart

Rampart's rate limiter and concurrency cap operate at the HTTP layer: a
request has already completed a TCP handshake and been parsed before Rampart
can act on it. That's sufficient for application-level abuse (scraping,
brute force, API flooding) but it is **not** a substitute for OS/kernel-level
protection against raw SYN floods or volumetric traffic, which arrive faster
than userspace can process them one request at a time.

For that, put one of these in front of (or alongside) Rampart:

## Linux: nftables SYN flood mitigation

```
table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;

        # Rate-limit new TCP connections per source IP.
        tcp flags syn tcp option maxseg size set 1-500 add @synflood { ip saddr limit rate 20/second burst 40 packets } accept
        tcp flags syn tcp option maxseg size set 1-500 drop
    }
}
```

## Cloud deployments

Prefer the provider's network-layer DDoS protection ahead of Rampart:
- AWS: Shield (+ Security Groups / NACLs for coarse IP filtering)
- GCP: Cloud Armor
- Any provider: put Rampart behind a CDN/edge proxy that already absorbs
  volumetric attacks, and use Rampart for the things edge providers don't
  do well — app-specific WAF rules, business-logic abuse detection,
  unified analytics across your own rule set.

This division of labor (kernel/cloud-edge for volumetric attacks, Rampart
for application-aware detection) is intentional and carries into Phase 5
(cloud-native packaging), where Rampart ships Terraform/Helm to wire itself
up correctly behind these layers rather than trying to replace them.
