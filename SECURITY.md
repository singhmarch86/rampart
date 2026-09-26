# Security Policy

Rampart is a security tool — if it has a vulnerability, that's a bigger deal
than a typical bug. Please report it responsibly rather than opening a
public issue.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, use [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
(Security tab → Report a vulnerability) on this repository, or email the
maintainer directly if that's not available yet.

Please include:
- What you found and why it's a vulnerability (not just "X seems off")
- Steps to reproduce, or a minimal PoC
- The affected version/commit
- Your assessment of severity/impact, if you have one

## What counts as a vulnerability here

Anything that lets an attacker:
- Bypass the WAF, rate limiter, API-abuse guard, or OIDC RBAC enforcement
  for a request that should have been blocked
- Forge or bypass a dashboard session
- Escalate privileges (e.g. reach a role-gated route without the role)
- Cause a crash/DoS in Rampart itself via crafted input
- Read or exfiltrate data Rampart shouldn't expose (e.g. another tenant's
  events, config secrets)

A WAF rule failing to catch a *novel* attack pattern isn't a security bug
in the traditional sense — it's a detection gap. Still worth reporting
(via a normal issue, with reproduction steps), just not through the
private channel unless you believe it's being actively exploited.

## Response

This is an early-stage open-source project maintained without a formal SLA.
Reports will be acknowledged as soon as reasonably possible and fixed with
priority proportional to severity. Credit will be given in the fix's
changelog entry unless you ask not to be named.

## Supported versions

Pre-1.0: only the latest commit on `main` is supported. There is no
long-term-support branch yet.
