# mhi — Mobile HTTP Inspector

A Go single-binary CLI for observing HTTP/HTTPS traffic of your own or explicitly
authorized apps, locally on a trusted LAN — no cloud, no keychain changes, no
system proxy mutation.

**Status: pre-release scaffold, M0 in progress.** Commands beyond `version`/`--help`
return explicit *not-implemented* errors (exit code 2). Nothing here yet reports
fake success; features are gated by the milestone plan below.

## Design principle

1. Start with **CA-less CONNECT monitoring**: the proxy shows *which hosts* the
   approved device connects to (destination addresses and ports), without
   decrypting anything and without a CA.
2. Later (M1): a locally generated CA enables **selective MITM** for exact
   hosts you put in `ssl_proxy.domains` — new connections only, never mid-tunnel.
3. Configuration lives in an explicit YAML file and/or explicit `.env` file you
   name on the command line (no CWD/parent/home auto-discovery).

Think of it as a scoped, privacy-conscious alternative for a specific niche —
*not* a replacement for Proxyman or mitmproxy:

- No CA import, external CA, or built-in CA fallback — only a CA `mhi` itself
  generates via `mhi ca init`.
- No download server, QR code, or install wizard for the CA — you AirDrop the
  `.cer` yourself.
- Never touches the Mac login/System keychain or macOS system proxy settings.
- Never modifies app requests (no request tampering, no replay), keeps upstream
  TLS verification ON, and never adds `InsecureSkipVerify`.

## What M0 will deliver (current work)

| Item | Status |
|---|---|
| CLI skeleton (`ca`/`serve`/`config`/`doctor`/`version`) | ✅ wired, sub-commands stub honest errors |
| Typed config loader — YAML strict + explicit `.env` | ✅ YAML strict path done, `.env` pending |
| Client IP allowlist + basic proxy auth | ✅ gate/auth implemented; auth password sourcing pending |
| Destination restrictions (loopback/private/link-local/multicast/metadata block) | ✅ pure-decision done |
| CONNECT authority parsing → `mode=tunnel` metadata events | ✅ via goproxy adapter |
| Connection registry + Ctrl+C/SIGTERM shutdown (3s drain) | ✅ registry done |
| Device (iPhone/Safari) verification on real hardware | ⬜ not yet performed — will be recorded separately from automated tests |

Automated test results and real-device-unverified status are **separately tracked**;
see `docs/verification-matrix.md` (to be created at M4).

## Layout

```
cmd/mhi/          entry point
internal/cli      cobra command tree, exit codes (0/2/3/4/130)
internal/config   typed config, strict YAML decode, .env parser, precedence
internal/policy   client gate, proxy auth, destination rules
internal/proxy    goproxy adapter (v1.9.2) — library types stay confined here
internal/lifecycle  connection registry, shutdown drain
internal/model    SafeEvent JSONL contract (schema_version 2)
internal/output   sanitized stdout/stderr sinks, terminal escaping
internal/capture  (M3) bounded body observation
internal/redact   (M3) sanitization rules, JSON pointers
```

`goproxy` is pinned at **v1.9.2** — a source-review baseline, not "auto-latest".
Its MITM default (`MitmConnect`) and built-in CA are deliberately never wired;
dependencies are pinned only after the M0 gate passes.

## Building & testing

```bash
make build    # → bin/mhi
make race     # go test with -race
go test ./...
```

Requirements: Go 1.25.x, macOS ARM64 or other Go-supported platform.
No runtime dependency on Python/Node/Homebrew — the final artifact is a single
static binary.

## CLI surface (contract per spec v0.3)

```
mhi ca init|path|status|delete     # local CA lifecycle (M1)
mhi serve --config ./mhi.yaml --watch
mhi config check|show             # validate/display effective config (M2)
mhi doctor                        # read-only local checks (M3)
mhi version
```

Global options: `--state-dir`, `--config`, `--env-file`, `--no-color`.
All file inputs **must be explicitly named** — there is intentionally no
auto-discovery in CWD, parent directories, or `$HOME`.

## Configuration example (M0 monitoring mode)

```yaml
schema_version: 1
listen: "192.168.0.10:9090"   # a specific LAN IPv4, never 0.0.0.0
client: "192.168.0.25"        # the approved device's IP

ssl_proxy:
  enabled: false              # normal monitoring state; no CA needed
  domains: []                 # only filled in when switching to MITM (M1)

http_capture:
  domains: []

capture:
  body: none
  details: false

output:
  format: text
  file: ""
  max_bytes: 104857600
```

`ssl_proxy.domains` is a **decrypt list**, not an access allowlist — approved
non-target HTTPS hosts still tunnel through with only metadata reported.

## Safety properties the code enforces (M0)

- Approved clients only: an unapproved peer is rejected before any monitoring
  or upstream dial (fail-closed, even with an empty allowlist).
- Proxy auth required once password sourcing lands (T-004); never via argv.
- Outbound `CONNECT` limited to port 443 (plus user-declared SSL ports later);
  loopback/private/link-local/multicast/metadata destinations always blocked.
- No env-proxy inheritance on any dial path (`HTTP_PROXY`/`HTTPS_PROXY` are
  ignored — never self-recursing or bypassing).
- Original `Accept-Encoding` preserved; no silent auto-compression handling.
- stderr carries status/warnings only; stdout carries sanitized events only;
  hostnames with ESC/OSC/control characters are escaped before printing.

## Roadmap

| Milestone | Gate | Status |
|---|---|---|
| M0 CA-less CONNECT monitoring | iPhone/Safari host reporting verified on device | in progress |
| M1 local CA + selective MITM  | exact-host decrypt via hand-delivered `.cer` | pending |
| M2 config/.env reload        | atomic policy swap, new connections only | pending |
| M3 sanitized bodies/output   | bounded capture, redaction, JSONL/file sinks | pending |
| M4 deployment & verification | arm64 binary + full AC table pass/fail/not-tested | pending |

**Disclaimer:** automated tests prove code correctness under fixture conditions;
real-device behavior (AirDrop delivery, iOS trust settings, app pinning, Wi-Fi
roaming, sleep/wake) must be separately recorded as verified or unverified.
Nothing is marked "pass" that was never actually executed against a device.

## License

To be decided at deployment (M4 T-402 records dependency licenses).
