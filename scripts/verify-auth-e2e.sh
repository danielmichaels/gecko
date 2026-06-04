#!/usr/bin/env bash
#
# verify-auth-e2e.sh — start the gecko server, wait for it to be healthy, run
# scripts/verify-auth.sh against it, then stop the server. Assumes Postgres is already
# up and migrated (the `verify:auth` Task target handles that). Port comes from
# API_SERVER_PORT (defaults to 7070).
#
# Lives in a real bash script rather than inline in the Taskfile because Task's
# embedded shell does not support background-job `$!` under `set -u`.

set -euo pipefail
cd "$(dirname "$0")/.."

BASE="http://localhost:${API_SERVER_PORT:-7070}"
LOG="$(mktemp -t gecko-verify-serve.XXXXXX)"
BIN="$(mktemp -t gecko-verify-bin.XXXXXX)"

# Build then run the binary directly. `go run` execs the compiled server as a child,
# so killing the `go run` PID would orphan the actual server (and leak the port);
# running the binary ourselves makes SERVER_PID the process we need to kill.
go build -o "$BIN" ./cmd/gecko/main.go
"$BIN" serve --disable-worker >"$LOG" 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true; rm -f "$BIN"' EXIT

echo "Waiting for $BASE/healthz ..."
up=0
for i in $(seq 1 60); do
  if [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/healthz" 2>/dev/null)" = "200" ]; then
    echo "server up after ${i}s"
    up=1
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "server exited early — log:"
    tail -n 20 "$LOG"
    exit 1
  fi
  sleep 1
done
if [ "$up" != 1 ]; then
  echo "server did not become healthy — log:"
  tail -n 20 "$LOG"
  exit 1
fi

BASE="$BASE" ./scripts/verify-auth.sh
