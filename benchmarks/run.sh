#!/usr/bin/env bash
# Reproduces the GoTestWAF run documented in RESULTS.md.
#
# Requires: Docker, and something listening on localhost:3000 for Rampart to
# protect (the results in RESULTS.md were measured against a local OWASP
# Juice Shop: `docker run -d -p 3000:3000 bkimminich/juice-shop`).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Building rampart..."
go build -o bin/rampart ./cmd/rampart

echo "Starting rampart in benchmark mode (rate limiting disabled, WAF-only measurement) on :8081..."
pkill -f "bin/rampart -config configs/rampart.benchmark.yaml" 2>/dev/null || true
sleep 1
rm -f rampart-benchmark-events.jsonl
./bin/rampart -config configs/rampart.benchmark.yaml > rampart-benchmark.log 2>&1 &
RAMPART_PID=$!
trap 'kill $RAMPART_PID 2>/dev/null || true' EXIT
sleep 2

echo "Running GoTestWAF..."
mkdir -p benchmarks/reports
docker run --rm -v "$PWD/benchmarks/reports:/app/reports" \
  wallarm/gotestwaf --url=http://host.docker.internal:8081 --noEmailReport

echo "Done. Report in benchmarks/reports/. Summary in the command output above."
