#!/bin/sh
# CRS coverage probe: one standard canary per OWASP Core Rule Set attack
# category, sent at a running Rampart instance, reporting which were blocked.
# Complements scripts/test-attacks.sh (the core regression suite) by mapping
# coverage across the CRS rule files at Rampart's default paranoia level (1).
#
#   ./scripts/test-crs-coverage.sh                       # localhost:8080
#   TARGET=http://localhost:18080 ./scripts/test-crs-coverage.sh
#
# Point this at a LOCAL instance (docker compose up). The canaries are the
# small, standard detection-test strings used in public CRS test material;
# any callback addresses point at localhost, nothing here phones home.
#
# Reading the result: a FAIL means "not blocked at the default anomaly
# threshold", not automatically "a bug". CRS adds points per rule hit and
# blocks at a threshold (5 by default), so a single low-severity hit may
# legitimately not block. Check the matching rule's severity and paranoia
# level before calling a FAIL a gap (see docs/FINDINGS.md #9 for how).
# Likewise a PASS (403) isn't proof the request was recognized: a block can
# be response-side (CRS flagging the app's error page), which happened with
# the XXE probe at paranoia levels 2-3 (FINDINGS #15). The block event's
# reason says "Inbound" or "Outbound".
#
# Exits non-zero if any probe was not blocked.
set -u

TARGET="${TARGET:-http://localhost:8080}"
PACE="${PACE:-0.4}"
CURL_TIMEOUT="${CURL_TIMEOUT:-10}"
SEARCH="$TARGET/rest/products/search"
PASS=0
FAIL=0

# probe NAME CRS_FILE EXPECT_CODE [curl args...]
probe() {
	name="$1"; file="$2"; expect="$3"; shift 3
	code=$(curl -sS -o /dev/null -m "$CURL_TIMEOUT" -w "%{http_code}" "$@")
	if [ "$code" = "$expect" ]; then
		printf "  PASS  %-38s %-10s -> %s\n" "$name" "$file" "$code"
		PASS=$((PASS + 1))
	else
		printf "  FAIL  %-38s %-10s -> %s (expected %s)\n" "$name" "$file" "$code" "$expect"
		FAIL=$((FAIL + 1))
	fi
	sleep "$PACE"
}

echo "CRS coverage probe against $TARGET (paranoia level 1 defaults)"
echo

echo "-- Request hygiene (911 method, 913 scanner, 920/921 protocol) --"
probe "Disallowed method (TRACE)"        911 403 -X TRACE "$TARGET/"
probe "Scanner user-agent (sqlmap)"      913 403 -A "sqlmap/1.7.2#stable" "$TARGET/"
# Real CR/LF bytes, encoded once by curl. Passing an already-encoded "%0d%0a"
# to --data-urlencode double-encodes it, and the WAF then sees literal text.
probe "HTTP response splitting (CRLF)"   921 403 -G "$SEARCH" --data-urlencode "q=$(printf 'a\r\nSet-Cookie: x=1')"

echo
echo "-- File inclusion (930 LFI, 931 RFI) --"
probe "LFI (/etc/passwd)"                930 403 -G "$SEARCH" --data-urlencode "q=/etc/passwd"
probe "LFI (/proc/self/environ)"         930 403 -G "$SEARCH" --data-urlencode "q=/proc/self/environ"
probe "RFI (remote URL as file param)"   931 403 -G "$SEARCH" --data-urlencode "q=http://127.0.0.1:1/shell.txt"

echo
echo "-- Code execution (932 RCE, 933 PHP, 944 Java) --"
probe "Unix command (;id)"               932 403 -G "$SEARCH" --data-urlencode "q=;id"
probe "Windows command (& whoami)"       932 403 -G "$SEARCH" --data-urlencode "q=a & whoami"
probe "Shellshock-style header"          932 403 -H 'User-Agent: () { :;}; /bin/true' "$TARGET/"
probe "PHP code injection"               933 403 -G "$SEARCH" --data-urlencode "q=<?php system(\$_GET['c']); ?>"
probe "Log4Shell JNDI lookup (param)"    944 403 -G "$SEARCH" --data-urlencode 'q=${jndi:ldap://127.0.0.1:1/a}'
probe "Log4Shell JNDI lookup (header)"   944 403 -H 'X-Api-Version: ${jndi:ldap://127.0.0.1:1/a}' "$SEARCH?q=a"
probe "Java class access (Runtime)"      944 403 -G "$SEARCH" --data-urlencode "q=java.lang.Runtime.getRuntime()"

echo
echo "-- Generic / injection (934, 942, 941) --"
probe "SSRF to cloud metadata address"   934 403 -G "$SEARCH" --data-urlencode "q=http://169.254.169.254/latest/meta-data/"
probe "Prototype pollution (__proto__)"  934 403 -G "$SEARCH" --data-urlencode "q=__proto__[admin]=1"
probe "XXE (external entity, XML body)"  "921/930" 403 -X POST -H "Content-Type: application/xml" \
	--data '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>&a;</x>' "$SEARCH"
probe "Time-based SQLi (SLEEP)"          942 403 -G "$SEARCH" --data-urlencode "q=' AND SLEEP(5)-- -"
probe "XSS via javascript: URI"          941 403 -G "$SEARCH" --data-urlencode "q=<a href=javascript:alert(1)>x</a>"

echo
echo "-- Template injection syntaxes beyond {{ }} (934, finding #9) --"
probe "Template: {% %} statement"        "934 PL2" 403 -G "$SEARCH" --data-urlencode "q={% print 7*7 %}"
probe "Template: <%= %> (ERB/JSP/EJS)"   "934 PL2" 403 -G "$SEARCH" --data-urlencode "q=<%= 7*7 %>"
probe "Template: \${ } (EL/Freemarker)"  "none"    403 -G "$SEARCH" --data-urlencode 'q=${7*7}'

echo
echo "-- Sanity: legitimate traffic must not be blocked --"
probe "Normal homepage"                  -   200 "$TARGET/"
probe "Normal search"                    -   200 -G "$SEARCH" --data-urlencode "q=apple juice"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
