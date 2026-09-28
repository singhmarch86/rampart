#!/bin/sh
# Sends a rotating mix of attack and normal traffic at the public demo
# stack (Rampart in front of Juice Shop), so the public dashboard has
# something to show even with zero organic visitors. See
# docs/PUBLIC_DEMO.md. Meant to run continuously (e.g. via systemd or
# `nohup ... &`) on the demo host itself, targeting localhost:8080 — not
# meant to be pointed at anyone else's deployment.
set -eu

TARGET="${TARGET:-http://localhost:8080}"
SLEEP_BETWEEN_ROUNDS="${SLEEP_BETWEEN_ROUNDS:-120}"

sqli_payloads="
1' OR '1'='1
' UNION SELECT * FROM users--
1; DROP TABLE users--
admin'--
"

xss_payloads="
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"

send_search_attacks() {
	old_ifs="$IFS"
	IFS='
'
	for p in $sqli_payloads $xss_payloads; do
		[ -z "$p" ] && continue
		# -G --data-urlencode: curl encodes the payload itself, no extra
		# interpreter dependency needed on the host running this script.
		curl -sS -o /dev/null -m 5 -G "$TARGET/rest/products/search" --data-urlencode "q=$p" || true
		sleep 1
	done
	IFS="$old_ifs"
}

send_brute_force() {
	i=1
	while [ "$i" -le 7 ]; do
		curl -sS -o /dev/null -m 5 -X POST "$TARGET/rest/user/login" \
			-H "Content-Type: application/json" \
			-d "{\"email\":\"admin@juice-sh.op\",\"password\":\"wrongpass$i\"}" || true
		i=$((i + 1))
		sleep 1
	done
}

send_normal_traffic() {
	curl -sS -o /dev/null -m 5 "$TARGET/" || true
	curl -sS -o /dev/null -m 5 "$TARGET/rest/products/search?q=laptop" || true
}

while true; do
	send_normal_traffic
	send_search_attacks
	send_brute_force
	sleep "$SLEEP_BETWEEN_ROUNDS"
done
