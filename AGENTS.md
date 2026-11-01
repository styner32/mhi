# AGENTS.md — Working conventions for agents on mhi

Read `implementation-checklist-go-cli-v0.3.md` and
`mobile-http-inspector-go-cli-spec-v0.3.md` before changing anything.
The spec is the single source of truth; the checklist is the task tracker.

## Project in one line

Go single-binary CLI (`mhi`) that monitors CONNECT destinations of approved
iPhones with no CA, and later MITMs only exact user-listed hosts with a
locally generated CA — never importing external CAs or falling back to any
built-in one.

## Hard rules (violations = rejected work)

1. **Never fake success.** Unimplemented sub-commands must return an explicit
   "not yet implemented" error mapped to exit code 2. Do not stub a call path
   to return `nil`/plausible output.
2. **Never add a goproxy built-in CA path.** `GoproxyCa`, `MitmConnect`,
   `OkConnect`'s TLSConfig, and any internal-CA fallback must stay unused.
   `internal/proxy/helpers.go` documents which tunnel action M0 wires
   (`ConnectAccept` with nil TLSConfig) — keep that boundary.
3. **Never auto-discover config.** Only files explicitly named with
   `--config`/`--env-file` may be read from disk. No CWD, parent-dir, or `$HOME`
   search for `.env`/YAML.
4. **Never trust the environment for dialing.** `HTTP_PROXY`/`HTTPS_PROXY`/
   `ALL_PROXY` are ignored on every dial path. Upstream TLS verification stays
   ON (`InsecureSkipVerify=false`); there is no `--insecure` flag in P0.
5. **Never block network forwarding on output.** stdout/disk writes are
   fire-and-forget with a bounded queue; dropping observations is OK, stalling
   the proxy is not.
6. **Never let library types escape `internal/proxy`.** goproxy types are
   confined to the adapter; CA/redact/output layers see only `internal/model`.
7. **Never put secrets in output.** Proxy-Authorization, Authorization, Cookie,
   Set-Cookie, and any `*token*`/`*key*`/`*password*` header or JSON field name
   are always redacted, in every output format. `mhi` passwords come only from
   /dev/tty or a 0600 file — never argv, never `.env`, never a plain env var.
8. **Never claim device-verified results.** Automated tests + real-device
   checks are separately recorded. Marking something "pass" that was never run
   on real hardware violates the project's verification contract.
9. **Never modify the Mac keychain or macOS system proxy** anywhere in the code.

## Commands

```bash
go build ./...     # must be green before commit
go vet ./...       # must be clean
go test ./...      # before pushing
go test -race ./...
```

`make build|test|race|vet|tidy` wrap the same. `gofmt` everything; Go 1.25
toolchain (see `go.mod`, pinned deliberately — bump only with a note in the
commit message).

## Layout and ownership

| Path | Scope | Do not |
|---|---|---|
| `internal/cli` | cobra commands, exit codes 0/2/3/4/130 | put business logic here |
| `internal/config` | strict YAML decode, `.env` parser, precedence, limits | read files not explicitly named by the user |
| `internal/policy` | client gate, proxy auth, destination rules | weaken: client gate and destination checks run BEFORE dial |
| `internal/proxy` | goproxy adapter, dialer, tunnel lifecycle | expose goproxy types outside this package |
| `internal/model` | SafeEvent/SafeConnection/sanitized DTOs | put raw http.Request/Response, keys, or error texts here |
| `internal/output` | stdout/stderr sinks, terminal escaping | emit a byte to stdout that isn't a sanitized event |
| `internal/lifecycle` | connection registry, shutdown drain | use only `http.Server.Shutdown` — hijacked conns must be tracked and closed explicitly |
| `internal/ca` (M1) | local CA gen/load/path/delete, state-dir locks | import/download/.anything |

Spec sections worth re-reading before touching each area: §2.1 (library
default overrides), §4.4 (precedence + start-condition table), §4.6 (reload
semantics), §5 (CA policy), §6 (CONNECT monitoring rules), §7 (streaming
limits), §8 (JSONL contract), §9 (errors + shutdown).

## Naming and style

- Exported identifiers: `Listen`, `SSLProxy`, `SafeEvent` — match spec's
  English YAML field names exactly.
- Comments reference spec sections (`§4.4`) and checklist IDs (`T-005`,
  `AC-27`) so the paperwork stays traceable back to code.
- Exit codes are the contract (0/2/3/4/130); do not introduce new ones without
  documenting in the spec.
- Every network-bound decision must fail closed when in doubt.

## What changes require doc updates

- Any new command/flag/sub-command → `README.md` + spec §4.1 table.
- Any event-type change → spec §8 + `internal/model` constants together.
- Any new dependency → justify against spec §2's chosen-stack rule; add to
  `docs/bootstrap-record.md`'s dependency section and record a license note.
- Any milestone-completing change → tick the matching line in
  `implementation-checklist-go-cli-v0.3.md` **only after the gate test exists**,
  and separately note which items are still unverified on real devices.
