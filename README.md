# mhi — Mobile HTTP Inspector

A Go single-binary CLI for observing HTTP/HTTPS traffic of your own or explicitly
authorized apps, locally on a trusted LAN — no cloud, no keychain changes, no
system proxy mutation.

## Building & testing

```bash
make build    # → bin/mhi
make race     # go test with -race
go test ./...
```

## CLI

```
mhi ca init|path|status|delete     # local CA lifecycle (M1)
mhi serve --config ./mhi.yml --watch
mhi config check|show             # validate/display effective config (M2)
mhi doctor                        # read-only local checks (M3)
mhi version
```

Global options: `--state-dir`, `--config`, `--env-file`, `--no-color`.
All file inputs **must be explicitly named** — there is intentionally no
auto-discovery in CWD, parent directories, or `$HOME`.

## Configuration example (M0 monitoring mode)

```yml
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


## Getting Started

```sh
cp examples/mhi.yml mhi.yml
cp examples/env.example .env
```

```sh
ipconfig getifaddr $(route -n get default | awk '/interface/ {print $2}')
```