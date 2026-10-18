#!/usr/bin/env bash

# Runs formatting check, vet, optional staticcheck, and the test suite with a
# coverage summary. The coverage profile is written to build/coverage.out.
# Non-root runs are re-executed into an isolated, self-controlled network
# namespace (unshare --user --map-root-user --net), and Docker is required:
# a disposable PostgreSQL container serves the storage-driver conformance
# tests through a Unix socket (network namespace independent). CI
# environments start their own database and inject
# WGENROL_TEST_POSTGRES_DSN instead (no container then).
# Counterpart to build.sh.

set -euo pipefail
cd "$(dirname "$0")"

COVERAGE_FILE=build/coverage.out
# Coverage is measured across package boundaries (driver tests execute the
# shared internal/storage helpers). Exact package paths, so the test-support
# conformance package stays out.
COVERAGE_PKGS=./cmd/...,./internal/config/...,./internal/server/...,./internal/storage,./internal/storage/postgres,./internal/storage/sqlite,./internal/wireguard

# Step [0/5]: the vulnerability check. It needs network access (the
# vulnerability database is fetched from vuln.go.dev), so it runs BEFORE the
# re-exec into the network namespace and only in the outermost pass.
if [ "${WGENROL_TEST_NETNS:-}" != "1" ]; then
    echo "[0/5] govulncheck (optional: needs network access)"
    if command -v govulncheck >/dev/null 2>&1; then
        status=0
        govulncheck ./... || status=$?
        if [ "$status" = "3" ]; then
            # Vulnerabilities do not interrupt testing, but should be reported to the user.
            echo "WARNING: govulncheck reported reachable vulnerabilities."
        elif [ "$status" != "0" ]; then
            echo "WARNING: govulncheck failed with status $status (no network access?); continuing without its verdict."
        fi
    else
        echo "govulncheck not installed, skipping (install with: go install golang.org/x/vuln/cmd/govulncheck@latest)"
    fi
fi

# Isolate the test network stack: re-exec this script inside an unprivileged
# network namespace we fully control (mapped root has CAP_NET_ADMIN there,
# enabling e.g. test-only interfaces later). Docker's daemon keeps running in
# the host namespaces; the PostgreSQL container is reached via a Unix socket
# in a shared volume, which no network namespace can block.
if [ "$(id -u)" != "0" ]; then
    if ! command -v unshare >/dev/null 2>&1; then
        echo "ERROR: unshare is required to run the test suite outside the host network namespace. Install util-linux, or run the script as root."
        exit 1
    fi
    export WGENROL_TEST_NETNS=1
    exec unshare --user --map-root-user --net bash "$0" "$@"
fi
if ! command -v ip >/dev/null 2>&1; then
    echo "ERROR: ip (iproute2) is required to bring up loopback in the test network namespace."
    exit 1
fi
ip link set lo up

# Inside the namespace we can also cover the WireGuard device happy paths
# (interface create/delete, kernel module required). Enabled only when the
# kernel actually supports the device type, so hosts without the module keep
# passing with a note.
if [ "${WGENROL_TEST_NETNS:-}" = "1" ]; then
    if ! command -v wg >/dev/null 2>&1; then
        echo "Note: wg (wireguard-tools) not found; WireGuard device tests stay disabled."
    elif ip link add wgenrol-wgprobe type wireguard 2>/dev/null; then
        ip link del wgenrol-wgprobe
        export WGENROL_TEST_WIREGUARD_DEVICE_CONTROL=1
        echo "WireGuard device tests: enabled (interfaces wgenrol-test, wgenrol-serve)"
    else
        echo "Note: the kernel does not support WireGuard interfaces; WireGuard device tests stay disabled."
    fi
fi

# Browser E2E tests (real headless Chromium driving the frontend). A browser
# is validated by actually launching it headless: binary-only checks would
# soft-enable unusable browsers (e.g. Snap shims, which cannot run in the
# namespace). The validated binary is exported so the tests use exactly what
# was probed. When the gate was set explicitly but no browser works, the run
# fails instead.
e2e_browser_bin=""
find_working_browser() {
    local candidate
    if [ -n "${WGENROL_TEST_E2E_CHROMIUM:-}" ]; then
        candidate="$WGENROL_TEST_E2E_CHROMIUM"
    else
        for name in chromium chromium-browser google-chrome google-chrome-stable; do
            candidate="$(command -v "$name" 2>/dev/null)" && break
        done
    fi
    [ -n "$candidate" ] || return 1
    if timeout 90 "$candidate" --headless --no-sandbox --disable-gpu --dump-dom "data:text/html,ok" 2>/dev/null | grep -q "ok"; then
        echo "$candidate"
        return 0
    fi
    return 1
}
if [ -n "${WGENROL_TEST_E2E_BROWSER:-}" ]; then
    if working="$(find_working_browser)"; then
        export WGENROL_TEST_E2E_CHROMIUM="$working"
        echo "Browser E2E tests: enabled (user-requested; browser: $working)"
    else
        echo "ERROR: WGENROL_TEST_E2E_BROWSER was set, but no Chromium-family browser could be launched (probed: chromium, chromium-browser, google-chrome, google-chrome-stable, or WGENROL_TEST_E2E_CHROMIUM). Note: Snap-packaged browsers cannot run in the test namespace; install a non-Snap build (e.g. Google Chrome's .deb, or a Chromium tarball)."
        exit 1
    fi
elif working="$(find_working_browser)"; then
    export WGENROL_TEST_E2E_CHROMIUM="$working"
    export WGENROL_TEST_E2E_BROWSER=1
    echo "Browser E2E tests: enabled (validated browser: $working)"
else
    echo "Note: no launchable Chromium-family browser found; browser E2E tests stay disabled (a Snap-packaged browser or none is installed; a non-Snap build enables them)."
fi

echo "[1/5] gofmt"
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
    echo "These files are not gofmt-clean:"
    echo "$unformatted"
    echo "Run: gofmt -w ."
    exit 1
fi

echo "[2/5] go vet"
go vet ./...

echo "[3/5] staticcheck (optional)"
if command -v staticcheck >/dev/null 2>&1; then
    staticcheck ./...
else
    echo "staticcheck not installed, skipping"
fi

echo "[4/5] go test"

# PostgreSQL: a pre-set DSN wins (CI path); otherwise docker and the container
# are mandatory. Any failure to run the database aborts the script. The
# container publishes its Unix socket through a shared volume, which is
# reachable from the isolated network namespace the script re-executed into
# (Unix sockets are filesystem-scoped, not network-scoped). The container
# keeps its default Docker networking: its network placement is irrelevant to
# the socket transport, but the entrypoint refuses to run in a network-less
# container.
PG_CONTAINER=""
PG_SOCKDIR=""
cleanup_pg() {
    [ -z "$PG_CONTAINER" ] || docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
    [ -z "$PG_SOCKDIR" ] || rm -rf "$PG_SOCKDIR"
}

if [ -n "${WGENROL_TEST_POSTGRES_DSN:-}" ]; then
    echo "PostgreSQL tests: using the DSN from WGENROL_TEST_POSTGRES_DSN (no container started)"
else
    if ! command -v docker >/dev/null 2>&1; then
        echo "ERROR: docker is required for the PostgreSQL conformance tests. Install Docker, or point WGENROL_TEST_POSTGRES_DSN at a pre-provisioned database."
        exit 1
    fi
    PG_CONTAINER="wgenrol-test-pg-$$"
    PG_SOCKDIR="$(mktemp -d /tmp/wgenrol-pgsock-XXXXXX)"
    chmod 0777 "$PG_SOCKDIR"
    trap cleanup_pg EXIT
    PG_IMAGE="${WGENROL_TEST_POSTGRES_IMAGE:-postgres:17-alpine}"
    if ! docker run -d --name "$PG_CONTAINER" --rm \
        -e POSTGRES_USER=wgenrol -e POSTGRES_PASSWORD=wgenrol-test -e POSTGRES_DB=wgenrol \
        -v "$PG_SOCKDIR:/pgsock" \
        "$PG_IMAGE" postgres -c "unix_socket_directories=/pgsock,/var/run/postgresql" >/dev/null 2>&1
    then
        echo "ERROR: the PostgreSQL test container failed to start (is the Docker engine running?). Tests cannot continue."
        exit 1
    fi
    ready=0
    for _ in $(seq 1 60); do
        if docker exec "$PG_CONTAINER" pg_isready -h /pgsock -U wgenrol -q >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 0.5
    done
    if [ "$ready" != 1 ]; then
        echo "ERROR: the PostgreSQL test container did not become ready in time. Recent logs:"
        docker logs --tail 20 "$PG_CONTAINER" 2>/dev/null || true
        exit 1
    fi
    # Keyword-form DSN with a Unix socket directory (works from any network
    # namespace; the alpine image's pg_hba trusts local connections).
    export WGENROL_TEST_POSTGRES_DSN="host=$PG_SOCKDIR user=wgenrol password=wgenrol-test dbname=wgenrol"
    echo "PostgreSQL tests: temporary container $PG_CONTAINER (image $PG_IMAGE), Unix socket in $PG_SOCKDIR"
fi

# Plain test run first: readable per-package output without the -coverpkg
# annotations (which append the full package list to every line). -count=1
# disables result caching: the gates below are environment variables, which
# Go's test cache does not track, so a cached run could hide the tests'
# enabled/disabled state.
if command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1; then
    CGO_ENABLED=1 go test -race -count=1 ./...
else
    echo "(no C compiler found: running tests without -race)"
    go test -count=1 ./...
fi

# The cross-package coverage profile is produced in a second, silenced pass:
# with -coverpkg every test binary reports against all packages, and go test
# would append that package list to each output line. Failures are still
# surfaced from the log.
coverage_log=build/coverage-test.log
if ! go test -coverpkg="$COVERAGE_PKGS" -coverprofile="$COVERAGE_FILE" ./... >"$coverage_log" 2>&1; then
    echo "Coverage run failed:"
    tail -n 40 "$coverage_log"
    exit 1
fi

if [ -s "$COVERAGE_FILE" ]; then
    module="$(go list -m)"
    # The merged profile concatenates one profile per test binary: identical
    # blocks appear once per binary, so dedup by block position and count a
    # block as covered when any run hit it (mode: set).
    report="$(awk -v mod="$module" '
        NF >= 3 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {
            if (!($1 in max)) {
                split($1, p, ":")
                n = split(p[1], seg, "/")
                pkg = ""
                for (i = 1; i < n; i++) pkg = pkg (i > 1 ? "/" : "") seg[i]
                sub(mod "/", "", pkg)
                pkgs[$1] = pkg
                stmts[$1] = $2
                max[$1] = 0
            }
            if ($3 + 0 > max[$1]) max[$1] = $3 + 0
        }
        END {
            for (tag in stmts) {
                total[pkgs[tag]] += stmts[tag]
                if (max[tag] > 0) covered[pkgs[tag]] += stmts[tag]
            }
            for (dir in total) {
                printf "  %-38s %5.1f%%\n", dir, 100 * covered[dir] / total[dir]
                gt += total[dir]; gc += covered[dir]
            }
            printf "overall %5.1f\n", 100 * gc / gt
        }' "$COVERAGE_FILE")"
    echo "Per-package test coverage:"
    echo "$report" | sed '$d' | sort
    echo "Overall test coverage: $(echo "$report" | sed -n '$s/overall *//p')%"
    echo "Per-function coverage report: go tool cover -html=$COVERAGE_FILE"
fi

echo "OK: all checks passed."