#!/usr/bin/env bash

# Runs formatting check, vet, optional staticcheck, and the test suite.
# Counterpart to build.sh.

set -euo pipefail
cd "$(dirname "$0")"

echo "[1/4] gofmt"
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
    echo "These files are not gofmt-clean:"
    echo "$unformatted"
    echo "Run: gofmt -w ."
    exit 1
fi

echo "[2/4] go vet"
go vet ./...

echo "[3/4] staticcheck (optional)"
if command -v staticcheck >/dev/null 2>&1; then
    staticcheck ./...
else
    echo "staticcheck not installed, skipping"
fi

echo "[4/4] go test"
# The race detector needs cgo + a C compiler; use it when one is available.
if command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1; then
    CGO_ENABLED=1 go test -race ./...
else
    echo "(no C compiler found: running tests without -race)"
    go test ./...
fi

echo "OK: all checks passed."
