# Bootstrap record (M0 not started)

Date: 2026-10-30 (KST). Basis: spec v0.3 + checklist v0.3.

## Done at bootstrap (T-001, T-002 partial)

- Go 1.25.0 (darwin/arm64), cobra v1.10.2; goproxy deliberately deferred until
  CONNECT passthrough lands (T-001 policy: pin after M0 passes, v1.9.2 is a
  source-review baseline, not auto-latest).
- Project tree per spec §10: cmd/mhi + internal/{cli,config,policy,ca,proxy,
  capture,redact,model,output,lifecycle} + testdata, tests/integration,
  docs, examples.
- CLI surface wired: ca (init/path/status/delete), serve, config (check/show),
  doctor, version. help/version are no-op safe by construction.
- M0+ sub-command bodies return explicit "not yet implemented" errors rather
  than pretending success; exit-code plumbing (0/2/3/4/130) exists.

## Not yet (open checklist items)

- T-002..T-008: everything M0 — config loader, listener, auth, destination
  policy, CONNECT parsing, registry, shutdown, AC-27 verification.
- M1..M4 entirely.

## Verification gateway reminder

Checklist §게이트: ca-free CONNECT monitoring on a real iPhone/Safari must be
demonstrated; absent device hardware, automatic test results and unverified
status must be separately recorded (AC table pass/fail/not-tested).
