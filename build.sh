#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname $0)"

GOOS=linux GOARCH=amd64 go build -o build/wgenrol_x86-64 ./cmd/wgenrol
GOOS=linux GOARCH=arm64 go build -o build/wgenrol_arm64 ./cmd/wgenrol

GOOS=windows GOARCH=amd64 go build -o build/wgenrol_x86-64.exe ./cmd/wgenrol
GOOS=windows GOARCH=arm64 go build -o build/wgenrol_arm64.exe ./cmd/wgenrol
