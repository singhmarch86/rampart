#!/bin/sh
# One-shot attack test suite: sends a distinct payload per vulnerability
# class at a running Rampart instance and reports pass/fail (was it
# blocked?) for each. Complements scripts/demo-traffic.sh, which is a
# continuous background generator for keeping a public dashboard
# populated — this script is for verifying detection actually works,
# either against a local instance or the live public demo.
#
#   ./scripts/test-attacks.sh                                   # localhost:8080
#   TARGET=http://34.29.169.231:8080 ./scripts/test-attacks.sh  # a live demo
#
# Exits non-zero if any expected-blocked payload got through.
set -u

TARGET="${TARGET:-http://localhost:8080}"
PASS=0
FAIL=0

report() {
	name="$1"; code="$2"; expect="$3"
	matched=0
	for want in $expect; do
		[ "$code" = "$want" ] && matched=1
	done
	if [ "$matched" = "1" ]; then
		printf "  PASS  %-34s -> %s\n" "$name" "$code"
		PASS=$((PASS + 1))
	else
		printf "  FAIL  %-34s -> %s (expected one of: %s)\n" "$name" "$code" "$expect"
		FAIL=$((FAIL + 1))
	fi
}

# A small demo VM (e2-small) can queue up and time out under a burst of
# back-to-back requests with no relation to Rampart's own behavior -
# confirmed by hand: checks that "failed" under a tight burst passed
# individually once spaced out. Pace every check by a beat and use a
# generous timeout so a slow response isn't misread as a block/non-block
# verdict.
PACE="${PACE:-0.4}"
CURL_TIMEOUT="${CURL_TIMEOUT:-10}"

# check_query NAME PATH QUERY_VALUE EXPECT_CODES
# -G --data-urlencode: curl encodes the payload itself, no manual
# percent-encoding needed (and no risk of double-encoding bugs).
check_query() {
	name="$1"; path="$2"; value="$3"; expect="$4"
	code=$(curl -sS -o /dev/null -m "$CURL_TIMEOUT" -w "%{http_code}" -G "$TARGET$path" --data-urlencode "q=$value")
	report "$name" "$code" "$expect"
	sleep "$PACE"
}

# check_post NAME PATH JSON_BODY EXPECT_CODES
check_post() {
	name="$1"; path="$2"; body="$3"; expect="$4"
	code=$(curl -sS -o /dev/null -m "$CURL_TIMEOUT" -w "%{http_code}" -X POST "$TARGET$path" \
		-H "Content-Type: application/json" -d "$body")
	report "$name" "$code" "$expect"
	sleep "$PACE"
}

# check_get NAME PATH EXPECT_CODES
check_get() {
	name="$1"; path="$2"; expect="$3"
	code=$(curl -sS -o /dev/null -m "$CURL_TIMEOUT" -w "%{http_code}" "$TARGET$path")
	report "$name" "$code" "$expect"
	sleep "$PACE"
}

echo "Testing $TARGET"
echo

echo "-- WAF layer (expect 403) --"
check_query "SQL injection"                    "/rest/products/search" "1' OR '1'='1" "403"
check_query "SQL injection (UNION)"             "/rest/products/search" "' UNION SELECT * FROM users--" "403"
check_query "XSS (script tag)"                  "/rest/products/search" '<script>alert(1)</script>' "403"
check_query "XSS (event handler)"               "/rest/products/search" '<img src=x onerror=alert(1)>' "403"
check_query "Path traversal"                    "/rest/products/search" '../../../../etc/passwd' "403"
check_query "Command injection"                 "/rest/products/search" '; cat /etc/passwd' "403"
check_query "NoSQL injection"                   "/rest/products/search" '{"$gt":""}' "403"
check_query "LDAP injection"                    "/rest/products/search" '*)(uid=*))(|(uid=*' "403"
# Known gap, verified by hand (2026-09-28): a bare {{7*7}} isn't blocked at
# the demo's current paranoia level - the app doesn't evaluate it (Juice
# Shop has no template engine on this path) so it's not exploitable here,
# but the WAF layer itself doesn't recognize the pattern either. Left as an
# honest FAIL rather than adjusted to pass - see docs/FINDINGS.md.
check_query "Server-side template injection"    "/rest/products/search" '{{7*7}}' "403"
check_query "Base64-encoded SQLi (custom rule)" "/rest/products/search" "$(printf "' OR '1'='1" | base64)" "403"

echo
echo "-- Schema validation layer (expect 400) --"
check_post "Mass assignment (isAdmin)" "/rest/user/login" \
	'{"email":"admin@juice-sh.op","password":"x","isAdmin":true}' "400"

echo
echo "-- API-abuse layer (expect 429 after threshold) --"
i=1
while [ "$i" -le 5 ]; do
	curl -sS -o /dev/null -m "$CURL_TIMEOUT" -X POST "$TARGET/rest/user/login" \
		-H "Content-Type: application/json" \
		-d "{\"email\":\"admin@juice-sh.op\",\"password\":\"wrong$i\"}" >/dev/null
	i=$((i + 1))
	sleep "$PACE"
done
check_post "Brute-force lockout" "/rest/user/login" \
	'{"email":"admin@juice-sh.op","password":"wrong6"}' "429"

echo
echo "-- Sanity check: legitimate traffic should NOT be blocked --"
check_get "Normal homepage request"   "/" "200"
check_query "Normal search (no attack)" "/rest/products/search" "laptop" "200"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
