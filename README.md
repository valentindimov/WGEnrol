# WGEnrol
A simple Web-based application for enrolling and managing peers in a Wireguard network.
Rather than managing a Wireguard `.conf` file by hand, WGEnrol allows an administrator to easily view, edit, and remove peers from the Web UI, as well as send invite links to new peers who can also enrol using the Web frontend.
Peer private keys are generated in the browser at the time of enrolment and never shared with the backend.

WGEnrol's dependencies are intentionally minimal:
- The app is built based on simple HTML templating and sticks to the Go standard library where possible;
- In the backend, additional libraries are used for cryptography, YAML and INI format support, and Wireguard interface control;
- In the frontend, the [qrcode.js](https://github.com/davidshimjs/qrcodejs) library is included to generate QR codes for mobile Wireguard clients. See the [enrolment.html](./internal/server/templates/enrolment.html) template file.

A reasonably modern browser (one that supports the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)) is required to use the app.


## How to Build
You will need a reasonably recent Go version (tested with 1.27). The project is pure Go, so

```bash
go build -o build/wgenrol ./cmd/wgenrol
```

is sufficient to build it.

You can also run `build.sh` and `test.sh` (on Linux) to build and run the full test suite.

## Development tools
The test suite (`test.sh`) uses a few optional tools, installed with `go install`:
- [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) reports known vulnerabilities in the module's dependencies (it needs network access to fetch the vulnerability database);
- [`staticcheck`](https://staticcheck.dev/) runs additional static analysis beyond `go vet`.

Additionally, an installed `wg` tool and a Chromium-family browser enable the WireGuard device and browser end-to-end tests, which run inside the script's network namespace.

## How to Run

`test.sh` works inside an isolated network namespace and uses Docker for its PostgreSQL storage tests.
An installed `wg` tool and Chromium or Chrome browser enable additional test coverage when present, but are not required.


## How to Run
The application uses a YAML-formatted config file. Check [testdata/test_config.yaml](./testdata/test_config.yaml) for an example.
Create this file and store it somewhere convenient, e.g. in `/etc/`.

The application manages the peer list of the Wireguard interface referenced by `wireguard.ifname` in the config file.
It does NOT create the interface, nor does it configure interface parameters like private key, IP routes, etc.
It ONLY manages the Wireguard peer list, assuming that all the rest is configured in advance, or managed by another tool.
It supports both Windows and Linux.

Additionally, peers and pending enrollments are stored in a database, configured through the `storage` block of the YAML config.
By default this is a SQLite database file (`storage.file`), but a PostgreSQL server can be used instead  - `storage.dsn` is the URL to connect to the database.

For adopting existing Wireguard configurations, the `-import` flag loads peers from a wg-quick `.conf` file into the database (peers already present are skipped) before the server starts.


## Notice on AI usage 
AI coding tools (with open-source models) are used in the development of WGEnrol for writing code, static verification, writing tests, and security hardening.
All productive code changes are reviewed and verified by hand.
High-level documentation is also written manually.


## License
Copyright (c) 2026 Valentin Dimov.
WGEnrol is licensed under the MIT license - see [LICENSE](./LICENSE).
