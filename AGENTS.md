# AGENTS.md — WGEnrol

Guidance for AI coding agents. Living document — update as the code is refactored.

## Ground rules

- **Git policy: agents NEVER commit or push.** You are free to create, edit, and
  delete files as needed for the task. However, running `git commit`, `git push`,
  or any other state-changing git operation (commit, amend, merge, rebase, tag,
  branch manipulation) is strictly out of bounds — committing and pushing is
  ALWAYS the human user's responsibility. Leave your changes in the working
  tree; the user will review and commit them.
- **Testing policy:** Changes are generally tested, i.e. agents run the existing
  suite (`./test.sh`) to verify their work. The project's target is >90% unit/
  integration/e2e test coverage. However, agents must NOT write, build, expand,
  or adapt tests unless the user explicitly instructs them to. When your changes
  leave tests missing or stale, remind the user and wait for instruction — do
  not touch test files on your own initiative.
- **Documentation policy:** High-level documentation (README, AGENTS.md, design
  docs, user-facing docs) is ALWAYS written by the human user, never by the
  agent. Low-level documentation — code comments and docstrings — can and
  should be written by the model as part of normal code changes, following the
  comment discipline in the coding style section.

## Project overview

WGEnrol is a Go web application for enrolling and managing peers
in a WireGuard network. Admins manage peers via a web UI; new peers enrol via
invite links, and private keys are generated in the browser (Web Crypto) and are
NEVER sent to the backend. The app only manages the peer list of an existing
WireGuard interface — it does not create interfaces, addresses, or routes. Runs
on Linux and Windows. Build targets: linux/windows × amd64/arm64 (see build.sh).

## Architecture (current state)

Four internal packages plus a thin entry point:

- `cmd/wgenrol/main.go` — entry point: `-config` flag → `run(configPath, importPath)` →
  `config.ParseConfigFile` → opens the store (`openStore`, dispatching on the backend;
  assigns the driver) → `-import <legacy.conf>` imports peers from a wg-quick INI file
  (add-only and idempotent: existing public keys are skipped, conf-side removals are
  never applied) and *continues*; then `server.NewContext(cfg, store)` → applies the
  stored peer list to the device on every startup → `server.ListenAndServe` (which
  returns its error; `main` log.Fatal's it).
- `internal/config` — YAML config (`WgEnrolConfig`), validation, and `ParseConfigFile`
  (returns `*WgEnrolConfig`). Pointer fields (`*string`, `*int`) mean "required":
  nil ⇒ missing. `normalizeStorage` validates the mandatory `storage:` block
  (backend/file/dsn, defaulting to sqlite), so cmd can branch on `Storage.Backend`
  alone; `ParseIPNetList` is exported for the server's context constructor
  (admin IP allowlist). The package stays dependency-free of the rest of the module.
- `internal/wireguard` — the domain package: `Key [32]byte` (also used for enrollment-
  token digests), `WgPeer`, `PendingPeer`; IPC allocation (`AllocateAllowedIPs`,
  excludes peer+pending reservations), device interaction (`ApplyPeerConfig`,
  `GetDeviceNets`/`netsFromAddrs`, `GetDevicePubkey`), and the legacy INI importer
  (`ImportPeersFromINI` — the only remaining ini.v1 consumer). It knows nothing about
  persistence and never imports internal/storage.
- `internal/storage` — the storage contracts and the plumbing shared by the drivers:
  the `PeerStore`/`SessionStore` interfaces and `DeviceApplyFn` (store methods that
  change the peer set run it with the resulting peer list *before* committing, so
  device state and store stay consistent), and the generic SQL store
  (`sqlstore.go`: all statement semantics written once with `{n}` markers,
  rendered per dialect at store construction; schema DDL, placeholder
  syntax, and the unique-violation mapping come from the `Dialect` the
  driver supplies). Also: peer/pending row codecs (AllowedIPs CSV codec, key
  blobs), `database/sql` scanners, and the transaction wrapper (`InTx`).
- `internal/storage/sqlite` — SQLite driver (pure-Go `modernc.org/sqlite`): dialect
  (SQLite DDL for schema v0: `peers`, `pending_peers` (token_hash), `sessions`; no
  `schema_version`/migration machinery — no deployments on older schemas exist),
  "?" placeholders, single connection, WAL + busy-timeout pragmas, and no
  unique-violation mapping (a single connection cannot race the in-tx pre-checks).
  Default backend. Driver `Store` type wraps the generic store and exposes `db`
  for the tests' raw-SQL corruption tests.
- `internal/storage/postgres` — PostgreSQL driver (pure-Go `jackc/pgx/v5` stdlib): dialect
  (BYTEA/BIGINT DDL, `$n` placeholders), pooled connections, and SQLSTATE 23505 mapped
  to the same "already exists" errors (the DB constraint arbitrates cross-instance
  duplicate races that the in-tx pre-checks cannot). Same schema v0 shape in the
  PostgreSQL dialect. Selected via
  `storage: {backend: postgres, dsn: …}`. Driver types implement both the PeerStore and
  the SessionStore interface (`sessions` table: login tokens survive restarts, and a
  shared PostgreSQL database makes them valid across app instances).
- `internal/storage/conformance` — test-only: driver-agnostic `RunPeerStoreSuite`
  asserting the PeerStore and SessionStore contracts for every driver. It deliberately
  has no test files of its own (its suites run inside the driver packages' tests; the
  `[no test files]` note it draws from `go test` is expected).
- `internal/server` — HTTP layer, and owner of `ServerContext` (parsed config + peer
  store + per-connection admin state + sessions + the mail hook; assembled by
  `NewContext`, constructed in cmd when launching). `server.go`: templates via
  `go:embed templates/*.html`, compiled at init; `wrapHandler` is the central
  middleware — it holds `ctx.StateMutex` for the whole request, sets security headers,
  applies IP filter + session auth, masks errors on unauthenticated routes, caps
  request bodies at 1 MB, and logs with enrollment-token path masking. Routes use Go
  method+wildcard patterns (`GET /peer/{token}`) and are registered on a
  fresh mux by `newServeMux` (kept separate so integration tests can serve the exact
  production route table via httptest). `getCertificate` hot-reloads TLS certs by
  mtime (`certCache`: falls back to last-known-good cert during renewal windows).
  `auth.go`: session cookie tokens (`crypto/rand.Text()`, sliding 1 h expiry,
  persisted via the store's SessionStore) and admin IP allowlist;
  auth failures redirect to /login. `api.go`: handlers for the admin UI (GET /: peers +
  pending invites tables), peer edit/delete, pending-invite CRUD (POST/PUT/DELETE
  `/pending[/{tokenHash}]`), enrollment page + enrollment (GET/PUT `/peer/{token}`),
  login/logout, SMTP invite email (async goroutine — must stay lock-free), and
  client-config AllowedIPs computation.
- `templates/*.html` (under `internal/server`) — server templates; inline JS does key
  generation (enrollment token + its SHA-256 digest), invite creation, enrollment requests, and QR
  codes (vendored qrcode.js in enrolment.html).

Import direction is strictly one-way: cmd → {server, config, wireguard, storage/*};
server → {config, wireguard, storage}; `config` depends on nothing else in the module;
storage → wireguard, storage drivers → {storage, wireguard}, and `wireguard` never
imports storage or server; no cycles.

### Security model — do not weaken

- Enrollment: an enrollment token (invite link) is the capability to register a real
  pubkey (PUT /peer/{token}); the store knows only its SHA-256 digest, so a database
  leak cannot forge links. The peers table never contains pseudo-keys, and pending
  enrollments are never applied to the WireGuard device.
- Handlers mutate state only under `ctx.StateMutex` (held by `wrapHandler`).
- Store writes are transactional; for mutations of the peer set the device is updated
  before the transaction commits (failure ⇒ rollback, no device/store divergence).
- Unauthenticated endpoints get masked errors (`handlerError.visible` + `maskErrors`).
- Login: bcrypt compare against a dummy hash for unknown users (timing defense);
  no rate limiting yet (TODO).

## Toolchain & commands

- Go per `go.mod` (currently 1.27; newer stdlib APIs like `rand.Text`, `strings.SplitSeq` are fine).
- Build: `./build.sh` → cross-compiles linux/windows × amd64/arm64 into `build/` (gitignored, never commit).
- Verification: `./test.sh` — step [0/5] `govulncheck ./...` (optional: needs network access, runs before the namespace re-exec; reachable vulnerabilities are reported as a warning and do not stop the run), gofmt check, `go vet ./...`, `staticcheck ./...` (optional, config in `staticcheck.conf`), `go test -race -count=1 ./...` (race detector needs a C compiler; `-count=1` because the result cache does not track the gates' environment variables). Non-root runs re-execute themselves into an isolated network namespace (`unshare --user --map-root-user --net`; `ip` from iproute2 required to bring loopback up), so tests never touch the host network stack. Inside the namespace, kernel-WireGuard device tests are enabled when `wg` (wireguard-tools) and the kernel device type are available (probed; env `WGENROL_TEST_WIREGUARD_DEVICE_CONTROL`). Docker is required: the script starts a disposable PostgreSQL container with no published ports, reached through a Unix socket on a shared volume (filesystem-scoped, hence network-namespace independent; the entrypoint needs a dual `unix_socket_directories` list because its init scripts hard-reset `PGHOST`), and fails hard when Docker is missing or the container cannot start (overridable `WGENROL_TEST_POSTGRES_IMAGE`, default postgres:17-alpine); a pre-set `WGENROL_TEST_POSTGRES_DSN` takes precedence (the CI path — CI provisions its own database). The suite also writes a cross-package coverage profile (`-coverpkg`, conformance package excluded as test support) to `build/coverage.out` (gitignored) and prints per-package + overall figures; per-function report: `go tool cover -html=build/coverage.out`.
- ALWAYS run `./test.sh` (or `gofmt -w . && go vet ./... && go test ./...`) after changes.

## Coding style & conventions (match existing code)

- Standard library first. Current deps: golang.org/x/crypto (bcrypt),
  golang.zx2c4.com/wireguard/wgctrl, modernc.org/sqlite (pure-Go SQLite peer store),
  github.com/jackc/pgx/v5 (pure-Go PostgreSQL peer store), gopkg.in/ini.v1 (legacy INI
  importer only), gopkg.in/yaml.v3; github.com/chromedp/chromedp (browser E2E only). No frameworks; no new dependencies without
  explicit discussion.
- Packages: `cmd/wgenrol` + `internal/{config,wireguard,server}`, imported by full
  module path (`thebasstoon.com/wgenrol/internal/…`). Keep the import direction
  strictly one-way (cmd → server → config; `config` imports no internal packages) —
  no cycles.
- Handler signature everywhere:
  `func(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *handlerError)`.
- Export surface is deliberately minimal — only what crosses a package boundary:
  `server.ListenAndServe`, `server.ServerContext`, `server.NewContext`; `config.ParseConfigFile`,
  `config.WgEnrolConfig`, `config.ParseIPNetList`;
  the `wireguard` domain/device API (`Key`, `WgPeer`, `PendingPeer`,
  `DecodeWireguardKey`, `KeyFromBytes`, `AllocateAllowedIPs`, `ApplyPeerConfig`,
  `GetDeviceNets`, `GetDevicePubkey`, `ImportPeersFromINI`); and
  `storage.PeerStore`, `storage.SessionStore`, `storage.DeviceApplyFn`,
  `storage/sqlite.Open`, `storage/postgres.Open`. Everything in `internal/server` beyond
  `ListenAndServe`/`ServerContext`/`NewContext`
  is unexported (`wrapHandler`, `handlerError`, `wrapError`, `getCertificate`,
  `certCache`, …) — keep it that way.
- Error strings are full sentences (capitalized, often with a period): ST1005 is
  intentionally disabled in staticcheck.conf — do not re-enable or rewrite them.
- Wrap handler errors with `wrapError(err, status, visible)`; `visible=true` only when
  the message should reach the client.
- JSON API bodies use Go field-name casing (`Pubkey`, `RegistrationLink`).
- Prefer `net/netip` for IPs/prefixes; convert to `net.IPNet` only at the wgctrl boundary.
- go:embed for templates; route patterns on DefaultServeMux.
- Comments are sparse and functional: security reasoning, gotchas, intentional
  limitations — never narration. Keep that discipline.
- LF endings everywhere (.gitattributes). Windows batch scripts were removed
  (Linux-only CI); if one is ever re-added it must keep CRLF (.gitattributes
  still carries the rule).

## Testing approach

- Tests live in each package: `internal/{config,server,wireguard}`, `internal/storage`
  (codec unit tests), `internal/storage/{sqlite,postgres}`,
  and `cmd/wgenrol` (import/conf-error paths, the postgres-unreachable startup error, and
  — gated on the device-control flag — serve-tail tests that pre-reserve `run`'s listener
  port so it terminates deterministically), plain `go test` with `*_test.go` alongside sources.
- The storage drivers share a conformance suite: `internal/storage/conformance.RunPeerStoreSuite`
  runs the full PeerStore and SessionStore contracts per driver (`TestSQLiteConformance`,
  incl. session lifecycle: touch/sliding expiry, pruning, keyed-visibility limits).
  `test.sh` starts a
  disposable PostgreSQL container (no published ports; reached via a shared-volume Unix
  socket, independent of the network namespaces) for local runs and aborts when it cannot
  start; CI sets `WGENROL_TEST_POSTGRES_DSN` to a pre-provisioned database instead.
- Per-package `helpers_test.go`: `internal/config` writes YAML fixtures per test;
  `internal/wireguard` has `makeKey`/`writeConf`; `internal/server` has
  `newLoginCtx`/`newStoreCtx`/`tempCertPair`/`genSelfSigned`, plus
  `newIntegrationServer`/`clientWithoutRedirects` for real-HTTP cookie-jar flows;
  `prefixes` is deliberately duplicated between the tests-helpers locations (no shared
  test-only package) — extend rather than duplicating further.
- There are NO WireGuard device seams in production: handlers call the real device
  functions. Device-dependent handler/integration tests (invite allocation, enrollment,
  full flow; interfaces `wgenrol-test`, `wgenrol-serve`, `wgenrol-apitest` — package-local
  names so parallel test binaries don't collide) are gated on
  `WGENROL_TEST_WIREGUARD_DEVICE_CONTROL` and run against real interfaces created in
  `test.sh`'s network namespace; without the flag they skip and coverage settles lower.
  `SendMailFn` on the context is the only remaining seam (nil in production): there is
  no test SMTP relay, so invite delivery is captured through it — inject fakes through
  it rather than mocking net/smtp.
- Browser end-to-end tests (`e2e_test.go`): a real headless Chromium
  (chromedp; pure-Go CDP, no Node toolchain) drives the frontend over the production
  route table — login, invite-dialog token generation, and the full Web Crypto
  enrollment incl. QR. Gated on `WGENROL_TEST_E2E_BROWSER` (test.sh soft-enables when a
  Chromium-family browser is found; explicitly requesting it without a browser fails
  hard; binary override `WGENROL_TEST_E2E_CHROMIUM`). They add no Go coverage; they
  verify template/JS/API contract behavior. Chromium's sandbox must be disabled
  (`--no-sandbox`) because the tests run as mapped root inside the namespace; the
  browser must be a Linux build reachable from the namespace (in WSL: apt, not Snap).
  Environment quirks (chromedp v0.21 + headless Chrome in the netns, documented in the
  harness helpers): chromedp's input-event `Click` and `Evaluate…` actions wedge the
  target's call queue, so all JS interaction goes through custom `cdp.Call`-evaluate
  actions (`jsClick`/`evalString`/`evalBool`) with evaluate-based waiter polls, and
  clicks carry a ~1 s settle; timeouts only on contexts derived from ones that have
  already run (a timeout on a first-Run context kills the whole browser).
- Table-driven tests for pure functions; httptest for handlers/middleware; real
  temporary-database tests for the SQLite store (open on `t.TempDir()`); store
  tests also corrupt rows via raw SQL (`insertRawPeer`) to cover the decode-failure
  branches, sweep every `PeerStore` method against a closed store (begin-failure
  branches), and verify rollback via deliberately failing `DeviceApplyFn` callbacks
  (promote/delete must not commit on apply error). Corrupt key/hash rows are reachable
  only through the list path: keyed lookups can never match a mismatched-length blob
  (documented by `TestCorruptPendingHashRow`).
- Integration tests (`integration_test.go`) drive the real mux end-to-end: login →
  invite → anonymous enrollment via the public link → admin edits/deletes → logout,
  plus the masking and IP-filter behavior.
- Documented non-goals (accepted uncovered): `main`'s thin flag wrapper (process-level
  e2e would be needed for it), `run`'s `ListPeers`-error branch (the store it opens
  cannot be made to fail through `run`), `getCertificate`'s nil-cache `log.Fatal`,
  template-Execute error branches, and — in the storage layer — the `row`/`rows.Scan`
  and mid-transaction `Exec`/`RowsAffected`/`QueryRow` failure branches (driver
  malfunction territory), the `isDuplicate` constraint-race arms (probabilistic only:
  the in-tx pre-checks catch duplicates in every deterministic interleaving), the
  corrupt-key decode branches in *keyed* scans (`GetPeer`/`GetPendingPeer` can never
  select a row whose key column is a mismatched-length blob; the list path reports
  such rows as corrupt — documented by `TestCorruptPendingHashRow`), and the drivers'
  `sql.Open` error return (DSNs are always well-formed). The serve tail of `run` (both
  TLS modes), the real-device happy paths of
  `ApplyPeerConfig`/`GetDevicePubkey`/`GetDeviceNets`, and the device-dependent server
  happy paths are covered by the env-gated device tests
  (`WGENROL_TEST_WIREGUARD_DEVICE_CONTROL`, enabled by `test.sh` in its network
  namespace; interface names are package-local constants so parallel test binaries do
  not collide) — coverage figures assume a full-namespace run; without the flag the
  gated tests skip and numbers settle lower. This gating structure is provisional:
  a further test rework is planned as part of a major refactor.
- Tests document deliberate limitations (e.g. `TestImportINIInSectionCommentNotRead`) — keep that.
- Root `testdata/` holds test config, certs, and a sample wg-quick conf used as an
  importer fixture (server tests read the certs via `../../testdata/…`); admin creds
  admin/"password" (precomputed bcrypt).
- Standing rule: run the test suite for your changes; only write/expand/adapt
  tests when the user explicitly asks. When instructed to work on tests, follow
  the practices above; when fixing bugs, write the failing test first.
  Coverage target: >90%.

## Known debt / open items (input for the refactor)

- No login rate limiting (TODO in api.go).
- `wrapHandler` serializes ALL requests under one mutex.
- Pending enrollments have no expiry/cleanup: `created_at` is recorded but never
  evaluated (stale invites stay forever until deleted by hand).
- The JSON error-code mapping in `api.go` matches store errors by substring
  (`strings.Contains(err.Error(), "does not exist")`) — brittle; typed errors or a
  sentinel-error mapping would be sturdier.
- `GetDeviceNets` returns prefixes whose address part is the interface's own
  (unmasked) address — `AllocateAllowedIPs` relies on that (scan starts one past
  the address); consumers elsewhere must not assume masked networks.
- With the PostgreSQL driver, store access is serialized per app instance only;
  cross-instance device-apply ordering is resolved by DB constraints (duplicates)
  but the WireGuard device state of a shared peer list is per-host.

## Collaboration note

Per the README: productive code is hand-written; AI is used for static verification,
tests, and security hardening. Keep changes small, reviewable, and verified.