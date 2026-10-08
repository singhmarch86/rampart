#!/bin/sh
# Self-assessment of a running Rampart deployment from the outside, the way a
# scanner or an attacker would first look at it: what ports answer, which TLS
# versions it accepts, what HTTP methods and headers it exposes. Uses nmap,
# openssl and curl. Complements scripts/test-attacks.sh (WAF detection) and
# scripts/test-crs-coverage.sh; this one checks the *deployment*, not the rules.
#
#   ./scripts/security-assessment.sh --i-own-this                  # 127.0.0.1
#   HOST=203.0.113.7 ./scripts/security-assessment.sh --i-own-this
#
# Only point this at a system you own or are authorized in writing to test.
# Port scanning someone else's host can be illegal and will get you blocked.
# The --i-own-this flag exists so it can't be run by accident, not as a
# substitute for authorization.
#
# Environment (all optional):
#   HOST           target host                              (127.0.0.1)
#   HTTP_PORT      Rampart proxy port, plain or TLS         (8080)
#   TLS            "1" if HTTP_PORT serves TLS (tls.enabled)(0)
#   DASH_PORT      dashboard port                           (9090)
#   ALLOWED_PORTS  space-separated ports expected to be open ("$HTTP_PORT")
#                  Anything else open in SCAN_RANGE is a FAIL. If the
#                  dashboard should be reachable, add it here.
#   SCAN_RANGE     nmap -p value                            (1-10000)
#
# Exits non-zero if any check FAILs. INFO lines are observations, not verdicts.
set -u

if [ "${1:-}" != "--i-own-this" ]; then
	sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
	echo
	echo "Refusing to run without --i-own-this." >&2
	exit 2
fi

HOST="${HOST:-127.0.0.1}"
HTTP_PORT="${HTTP_PORT:-8080}"
TLS="${TLS:-0}"
DASH_PORT="${DASH_PORT:-9090}"
ALLOWED_PORTS="${ALLOWED_PORTS:-$HTTP_PORT}"
SCAN_RANGE="${SCAN_RANGE:-1-10000}"

if [ "$TLS" = "1" ]; then SCHEME=https; else SCHEME=http; fi
BASE="$SCHEME://$HOST:$HTTP_PORT"
CURL="curl -sk --max-time 10"

PASS=0
FAIL=0
pass() { printf "  PASS  %s\n" "$1"; PASS=$((PASS + 1)); }
fail() { printf "  FAIL  %s\n" "$1"; FAIL=$((FAIL + 1)); }
info() { printf "  INFO  %s\n" "$1"; }

need() {
	command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 2; }
}
need nmap
need openssl
need curl

echo "Target: $BASE  (scan range $SCAN_RANGE, expected open: $ALLOWED_PORTS)"

# ---------------------------------------------------------------- 1. ports
echo
echo "1. Port exposure (nmap TCP connect scan)"
# -sT needs no root; -Pn skips host discovery so a host that drops ping is
# still scanned; --open prints only open ports.
SCAN=$(nmap -sT -Pn --open -p "$SCAN_RANGE" -oG - "$HOST" 2>/dev/null | grep '^Host:.*Ports:')
OPEN=$(printf '%s\n' "$SCAN" | grep -o '[0-9]*/open/tcp' | cut -d/ -f1 | tr '\n' ' ')
info "open ports: ${OPEN:-none}"
UNEXPECTED=""
for p in $OPEN; do
	ok=0
	for a in $ALLOWED_PORTS; do [ "$p" = "$a" ] && ok=1; done
	[ "$ok" = 0 ] && UNEXPECTED="$UNEXPECTED $p"
done
if [ -z "$UNEXPECTED" ]; then
	pass "no open ports outside the expected set"
else
	fail "unexpected open ports:$UNEXPECTED (add to ALLOWED_PORTS if intended)"
fi
for a in $ALLOWED_PORTS; do
	case " $OPEN " in
	*" $a "*) ;;
	*) fail "expected port $a is not open" ;;
	esac
done

DASH_OPEN=0
case " $OPEN " in *" $DASH_PORT "*) DASH_OPEN=1 ;; esac
case " $ALLOWED_PORTS " in
*" $DASH_PORT "*) info "dashboard port $DASH_PORT is expected to be reachable" ;;
*)
	if [ "$DASH_OPEN" = 1 ]; then
		fail "dashboard port $DASH_PORT is reachable but not in ALLOWED_PORTS (no auth unless oidc.dashboard_auth is on)"
	else
		pass "dashboard port $DASH_PORT is not reachable from here"
	fi
	;;
esac

# ------------------------------------------------------------------ 2. TLS
echo
echo "2. TLS configuration"
if [ "$TLS" != "1" ]; then
	info "TLS=0: $HTTP_PORT serves plain HTTP, skipping (set TLS=1 if tls.enabled)"
else
	# nmap enumerates what the server accepts independently of this machine's
	# openssl build, which may refuse to even offer TLS 1.0/1.1 and so would
	# "pass" them for the wrong reason.
	ENUM=$(nmap -Pn -p "$HTTP_PORT" --script ssl-enum-ciphers "$HOST" 2>/dev/null)
	for v in "TLSv1.0" "TLSv1.1"; do
		if printf '%s\n' "$ENUM" | grep -q "^|   $v:"; then
			fail "server accepts $v"
		else
			pass "server does not accept $v"
		fi
	done
	for v in "TLSv1.2" "TLSv1.3"; do
		if printf '%s\n' "$ENUM" | grep -q "^|   $v:"; then
			pass "server accepts $v"
		else
			info "server does not offer $v"
		fi
	done
	if printf '%s\n' "$ENUM" | grep -q "^|   TLSv1.2:"; then
		if printf '%s\n' "$ENUM" | grep -qi 'least strength: [DEF]'; then
			fail "weakest offered cipher is graded D or worse by nmap"
		else
			pass "no cipher graded D or worse"
		fi
	fi
	for flag in -tls1_2 -tls1_3; do
		if echo | openssl s_client "$flag" -connect "$HOST:$HTTP_PORT" >/dev/null 2>&1; then
			pass "openssl handshake succeeds with $flag"
		else
			info "openssl handshake with $flag failed (server may not offer it)"
		fi
	done
	CERT=$(echo | openssl s_client -connect "$HOST:$HTTP_PORT" 2>/dev/null | openssl x509 -noout -subject -enddate -issuer 2>/dev/null)
	info "certificate: $(printf '%s' "$CERT" | tr '\n' ' ')"
fi

# ------------------------------------------------------------- 3. HTTP
echo
echo "3. HTTP behaviour"

# Dangerous / unneeded methods. Rampart itself has no method allow-list; what
# matters is that these don't reach something that honors them.
code=$($CURL -o /dev/null -w '%{http_code}' -X TRACE "$BASE/")
case "$code" in
200) fail "TRACE returned 200 (reflects the request; allows cross-site tracing)" ;;
*) pass "TRACE not honored (HTTP $code)" ;;
esac
code=$($CURL -o /dev/null -w '%{http_code}' -X CONNECT "$BASE/")
case "$code" in
200) fail "CONNECT returned 200 (open proxy?)" ;;
*) pass "CONNECT not honored (HTTP $code)" ;;
esac

# Does Rampart itself leak anything on a block page, and does the 404/500 page
# reveal a stack or framework? Use a request the WAF blocks.
BLOCK_HDRS=$($CURL -D - -o /dev/null "$BASE/?q=%27%20OR%20%271%27%3D%271")
BLOCK_BODY=$($CURL "$BASE/?q=%27%20OR%20%271%27%3D%271")
if printf '%s' "$BLOCK_HDRS" | grep -q ' 403'; then
	pass "SQL-injection probe is blocked (403)"
	if printf '%s' "$BLOCK_BODY" | grep -qiE 'coraza|owasp|crs|rule id|anomaly|go/|stack'; then
		fail "block page reveals internals: $(printf '%s' "$BLOCK_BODY" | head -c 120)"
	else
		pass "block page reveals no rule or engine details"
	fi
else
	info "SQL-injection probe was not blocked (waf disabled or mode: detect?)"
fi

# Version banners.
HDRS=$($CURL -D - -o /dev/null "$BASE/")
for h in Server X-Powered-By X-AspNet-Version; do
	v=$(printf '%s\n' "$HDRS" | grep -i "^$h:" | tr -d '\r')
	[ -n "$v" ] && info "banner from upstream or proxy: $v"
done

# Security headers. Rampart does not add these (a WAF/proxy could, but that is
# a product decision); this reports what the upstream sends through.
for h in Strict-Transport-Security X-Content-Type-Options X-Frame-Options Content-Security-Policy Referrer-Policy; do
	if printf '%s\n' "$HDRS" | grep -qi "^$h:"; then
		info "present: $h"
	else
		info "absent:  $h (set it in the app or the layer in front)"
	fi
done

# Robustness: oversized header and bare protocol oddities must not 5xx or hang.
BIG=$(head -c 70000 /dev/zero | tr '\0' 'A')
code=$($CURL --http1.1 -o /dev/null -w '%{http_code}' -H "X-Big: $BIG" "$BASE/")
case "$code" in
5??) fail "70 KB header caused HTTP $code" ;;
000) pass "70 KB header rejected at the connection level" ;;
*) pass "70 KB header handled (HTTP $code)" ;;
esac

# Slow-header resilience (optional: waits up to server.read_timeout).
if [ "${SLOW:-0}" = "1" ] && command -v nc >/dev/null 2>&1; then
	WAIT="${SLOW_WAIT:-75}"
	start=$(date +%s)
	( printf 'GET / HTTP/1.1\r\nHost: x\r\nX-Slow: '; sleep "$WAIT" ) | nc "$HOST" "$HTTP_PORT" >/dev/null 2>&1
	took=$(( $(date +%s) - start ))
	if [ "$took" -lt "$WAIT" ]; then
		pass "server cut off a client dripping headers after ${took}s"
	else
		fail "server held a half-sent request for the full ${WAIT}s"
	fi
else
	info "slow-header test skipped (SLOW=1 to run; waits up to SLOW_WAIT=75s; plain HTTP only)"
fi

echo
echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
