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

Three internal packages plus a thin entry point:

- `cmd/wgenrol/main.go` — entry point: `-config` flag → `config.ParseConfigFile` →
  `ConfFile.ApplyDeviceConfig` → `server.ListenAndServe`.
- `internal/config` — YAML config (`WgEnrolConfig`), validation, and `ParseConfigFile`.
  Pointer fields (`*string`, `*int`) mean "required": nil ⇒ missing. `ServerContext` also
  lives here: it joins the parsed config, the peer store (`ConfFile *wireguard.WgConf`),
  the admin IP filter, and the session-token map; `StateMutex` is the global request lock.
- `internal/wireguard` — peer DB as wg-quick-compatible INI (`WgConf`, which carries the
  interface name internally), atomic save (temp file + fsync + rename), device apply
  (`Commit` = apply to device + save), free-IP allocation (`FindSuitableAllowedIPs`),
  device introspection (`GetDeviceNets`, `GetDevicePubkey`), key decoding
  (`DecodeWireguardKey`). Entry point: `LoadWgConf(path, ifname)`.
- `internal/server` — HTTP layer. `server.go`: templates via `go:embed templates/*.html`,
  compiled at init; `wrapHandler` is the central middleware — it holds `ctx.StateMutex`
  for the whole request, sets security headers, applies IP filter + session auth, masks
  errors on unauthenticated routes, caps request bodies at 1 MB, and logs with preimage
  path masking. Routes use Go method+wildcard patterns (`GET /peer/{pubkeyPreimage}`).
  `getCertificate` hot-reloads TLS certs by mtime (`certCache`: falls back to
  last-known-good cert during renewal windows). `auth.go`: session cookie tokens
  (`crypto/rand.Text()`, in-memory map, sliding 1 h expiry) and admin IP allowlist;
  auth failures redirect to /login. `api.go`: handlers for the admin UI (GET /), peer
  create/edit/delete, login/logout, enrollment page + enrollment, SMTP invite email
  (async goroutine — must stay lock-free), and client-config AllowedIPs computation.
- `templates/*.html` (under `internal/server`) — server templates; inline JS does key
  generation, enrolment requests, and QR codes (vendored qrcode.js in enrolment.html).

Import direction is strictly one-way: cmd → server → config → wireguard; no cycles.

### Security model — do not weaken

- Enrollment: pending peers store base64(SHA-256(preimage)) as their pubkey; the
  preimage link is the capability to register a real pubkey (PUT /peer/{preimage}).
- Handlers mutate state only under `ctx.StateMutex` (held by `wrapHandler`).
- Unauthenticated endpoints get masked errors (`handlerError.visible` + `maskErrors`).
- Login: bcrypt compare against a dummy hash for unknown users (timing defense);
  no rate limiting yet (TODO).

## Toolchain & commands

- Go per `go.mod` (currently 1.26; newer stdlib APIs like `rand.Text`, `strings.SplitSeq` are fine). README's "tested with 1.24" note is stale.
- Build: `./build.sh` → cross-compiles linux/windows × amd64/arm64 into `build/` (gitignored, never commit).
- Verification: `./test.sh` — gofmt check, `go vet ./...`, `staticcheck ./...` (optional, config in `staticcheck.conf`), `go test -race ./...` (race detector needs a C compiler).
- ALWAYS run `./test.sh` (or `gofmt -w . && go vet ./... && go test ./...`) after changes.

## Coding style & conventions (match existing code)

- Standard library first. Current deps: golang.org/x/crypto (bcrypt),
  golang.zx2c4.com/wireguard/wgctrl, gopkg.in/ini.v1, gopkg.in/yaml.v3.
  No frameworks; no new dependencies without explicit discussion.
- Packages: `cmd/wgenrol` + `internal/{config,wireguard,server}`, imported by full
  module path (`thebasstoon.com/wgenrol/internal/…`). Keep the import direction
  strictly one-way (cmd → server → config → wireguard) — no cycles.
- Handler signature everywhere:
  `func(ctx *config.ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *handlerError)`.
- Export surface is deliberately minimal — only what crosses a package boundary:
  `server.ListenAndServe`; `config.ParseConfigFile`, `config.ServerContext`, `config.WgEnrolConfig`;
  and the `wireguard` store/device API (`WgConf`, `WgPeer`, `LoadWgConf`, `DecodeWireguardKey`,
  the peer/device methods, `WgConf.Peers`). Everything in `internal/server` beyond
  `ListenAndServe` is unexported (`wrapHandler`, `handlerError`, `wrapError`,
  `getCertificate`, `certCache`, …) — keep it that way.
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

- Tests live in each package: `internal/{server,wireguard}`, plain `go test` with
  `*_test.go` alongside sources.
- Per-package `helpers_test.go`: `internal/wireguard` has `writeConf`/`validKey`,
  `internal/server` has `newLoginCtx`/`tempCertPair`/`genSelfSigned`;
  `validKey` + `prefixes` are deliberately duplicated between the two (no shared
  test-only package) — extend rather than duplicating further.
- Table-driven tests for pure functions; httptest for handlers/middleware.
- Tests document deliberate limitations (e.g. `TestImportInSectionCommentNotRead`) — keep that.
- Root `testdata/` holds test config, certs, sample conf (server tests read it via
  `../../testdata/…`); admin creds admin/"password" (precomputed bcrypt).
- Standing rule: run the test suite for your changes; only write/expand/adapt
  tests when the user explicitly asks. When instructed to work on tests, follow
  the practices above; when fixing bugs, write the failing test first.
  Coverage target: >90%.

## Known debt / open items (input for the refactor)

- WireGuard keys passed/stored as base64 strings (`DecodeWireguardKey` FIXME: should be byte arrays).
- `Commit()` has no transaction semantics between device-apply and INI-save (FIXME).
- No login rate limiting (TODO in api.go).
- Sessions in-memory only (lost on restart; single process by design).
- `wrapHandler` serializes ALL requests under one mutex.

## Collaboration note

Per the README: productive code is hand-written; AI is used for static verification,
tests, and security hardening. Keep changes small, reviewable, and verified.