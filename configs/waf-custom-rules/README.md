# Custom WAF rules

Files here are loaded (sorted by filename) after the OWASP Core Rule Set,
using the same SecLang syntax as ModSecurity/CRS. This is where
deployment-specific rules go — things CRS can't know about your application,
like blocking a path that should never be internet-facing, or a business-logic
check.

**Rule ID convention:** CRS reserves IDs below 1000000. Custom rules should
use IDs in the 1000000–1999999 range (this is the same convention
upstream CRS documents for local/custom rules) to avoid ever colliding with a
CRS rule ID as the rule set is updated.

See `01-example.conf` for a working example. Delete it once you've written
your own rules — it's a demonstration, not something worth keeping in a real
deployment.
