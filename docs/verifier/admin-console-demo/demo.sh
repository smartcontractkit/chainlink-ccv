#!/usr/bin/env bash
# One-command demo of the CCV admin console; see README.md for the walkthrough.
# start: disposable Postgres + seeded data + the console harness (127.0.0.1:8105);
# stop: stop the harness and remove the container; clean: also delete .runtime/.
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNTIME="$DEMO_DIR/.runtime"
ROOT="$(git -C "$DEMO_DIR" rev-parse --show-toplevel)"

CONTAINER=ccv-admin-demo
PG_PORT=5433
CONSOLE_PORT=8105
PG_USER=demo
PG_PASSWORD=demo
VERIFIER_DB=verifier_demo

# tool-versions.env pins the Go toolchain; a bare `go` with GOTOOLCHAIN=local may
# be older than go.mod requires.
export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.6}"

ATTESTED_ID=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mdemo:\033[0m %s\n' "$*" >&2; exit 1; }

port_free() { ! nc -z 127.0.0.1 "$1" 2>/dev/null; }

stop() {
    for pidfile in "$RUNTIME"/*.pid; do
        [ -e "$pidfile" ] || continue
        pid="$(cat "$pidfile")"
        # A stale PID file may name a recycled PID: signal it only while the
        # process still looks like this demo's console harness.
        if [ -n "$pid" ] && ps -p "$pid" -o command= 2>/dev/null | grep -q "console-demo"; then
            if kill "$pid" 2>/dev/null; then
                for _ in $(seq 1 50); do
                    ps -p "$pid" >/dev/null 2>&1 || break
                    sleep 0.1
                done
                say "stopped $(basename "$pidfile" .pid) (pid $pid)"
            fi
        fi
        rm -f "$pidfile"
    done
    if docker rm -f "$CONTAINER" >/dev/null 2>&1; then
        say "removed container $CONTAINER"
    fi
}

start() {
    command -v docker >/dev/null || die "docker is required"
    docker info >/dev/null 2>&1 || die "docker daemon is not running"
    command -v nc >/dev/null || die "nc is required (port checks)"
    command -v curl >/dev/null || die "curl is required (health checks)"

    # A failed init must not leak the container, the harness, or its ports: stop
    # on any non-zero exit during startup (a successful start keeps everything).
    trap '[ "$?" -ne 0 ] && stop >/dev/null 2>&1 || true' EXIT

    # A previous half-run must not leak processes, a stale container, or its ports.
    stop

    port_free "$PG_PORT" || die "port $PG_PORT is busy (stop whatever owns it, or change PG_PORT)"
    port_free "$CONSOLE_PORT" || die "port $CONSOLE_PORT is busy"

    say "starting disposable Postgres (database: $VERIFIER_DB)"
    docker run -d --name "$CONTAINER" \
        -e POSTGRES_USER="$PG_USER" -e POSTGRES_PASSWORD="$PG_PASSWORD" \
        -e POSTGRES_DB="$VERIFIER_DB" \
        -p 127.0.0.1:"$PG_PORT":5432 postgres:15-alpine >/dev/null

    say "waiting for Postgres to accept connections"
    for _ in $(seq 1 60); do
        docker exec "$CONTAINER" pg_isready -U "$PG_USER" -d "$VERIFIER_DB" >/dev/null 2>&1 && break
        sleep 1
    done
    docker exec "$CONTAINER" pg_isready -U "$PG_USER" -d "$VERIFIER_DB" >/dev/null 2>&1 \
        || die "Postgres did not become ready"

    mkdir -p "$RUNTIME"

    say "building the console harness (this checkout)"
    (cd "$ROOT" && go build -o "$RUNTIME/console-demo" ./docs/verifier/admin-console-demo)

    say "starting the admin console"
    DEMO_DATABASE_URL="postgres://$PG_USER:$PG_PASSWORD@127.0.0.1:$PG_PORT/$VERIFIER_DB?sslmode=disable" \
    CCV_ADMIN_CONFIG_PATH="$DEMO_DIR/demo-config.toml" \
        "$RUNTIME/console-demo" > "$RUNTIME/console.log" 2>&1 &
    echo $! > "$RUNTIME/console.pid"

    say "waiting for the console health endpoint"
    for _ in $(seq 1 30); do
        curl -sf "http://127.0.0.1:$CONSOLE_PORT/healthz" >/dev/null && break
        sleep 1
    done
    curl -sf "http://127.0.0.1:$CONSOLE_PORT/healthz" >/dev/null \
        || die "console did not start; see $RUNTIME/console.log"

    # The harness applies the verifier migrations at startup (the action-log table
    # included), so the schema is ready before seeding.
    say "seeding demo data"
    docker exec -i "$CONTAINER" psql -U "$PG_USER" -d "$VERIFIER_DB" -v ON_ERROR_STOP=1 \
        < "$DEMO_DIR/seed-verifier.sql" >/dev/null

    # Warm the search once so the first live click is fast.
    curl -sf "http://127.0.0.1:$CONSOLE_PORT/search" >/dev/null

    printf '\n'
    say "demo ready: http://127.0.0.1:$CONSOLE_PORT"
    printf '\n'
    cat <<EOF
Console process log : $RUNTIME/console.log
Message IDs to try  : 0x${ATTESTED_ID}
                      0xcafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe
                      0x0badf00d0badf00d0badf00d0badf00d0badf00d0badf00d0badf00d0badf00d
Recovery form       : owner CCTPVerifier, chain 1 (healthy) or 2 (finality-blocked)
Teardown            : $0 stop    (reset everything: $0 clean)
EOF
}

case "${1:-start}" in
    start) start ;;
    stop) stop ;;
    clean) stop; rm -rf "$RUNTIME"; say "removed $RUNTIME" ;;
    *) die "usage: $0 {start|stop|clean}" ;;
esac
