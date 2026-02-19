# Rusty Pinch

![Rusty Pinch Banner](assets/banner-rusty-pinch.png)

Rusty Pinch is a clean, standalone Rust runtime package for the assistant stack.  

![Rusty Pinch Logo](assets/logo-rusty-pinch.png)

## What You Get

- Rust CLI runtime: `rusty-pinch`
- Env-first configuration with strict `.env` support
- Provider modes: `codex` (default), OpenAI-compatible (`openrouter`, `openai`, `groq`, `compatible`), and `local`
- Append-only session storage (`jsonl`)
- Deterministic local tool path (`/tool ...`) with safety guardrails
- Native channel listeners: Telegram long polling and WhatsApp bridge websocket
- Structured per-turn logs with `request_id`
- Persisted telemetry counters across CLI restarts
- Standalone packaging script and CI artifacts

## Source Availability and Contribution

- Rusty Pinch is distributed under a **personal-use source-available** license.
- This is **not** an OSI-approved open-source license.
- Contributions are welcome through pull requests under repository license terms.

See:

- `LICENSE`
- `CONTRIBUTING.md`
- `SECURITY.md`

## Quick Start

```bash
cd rusty-pinch
cp .env.example .env
cargo run -- doctor
```

Local smoke run (no remote API call):

```bash
RUSTY_PINCH_PROVIDER=local cargo run -- run --session demo --message "hello"
cargo run -- stats
```

Codex provider run (default):

```bash
cargo run -- run --session demo --message "say hi in one line"
```

## Usage Guide

Core commands:

- `cargo run -- doctor`: validate provider/env/path setup
- `cargo run -- run --session <id> --message "<text>"`: execute one turn
- `cargo run -- repl --session <id>`: interactive mode
- `cargo run -- session --session <id>`: print session history JSON
- `cargo run -- stats`: print bus, cache, telemetry, and latest turn
- `cargo run -- monitor`: live TUI monitor (app/process/host/storage)
- `cargo run -- monitor --once`: render one snapshot and exit
- `cargo run -- channels telegram`: start Telegram listener loop
- `cargo run -- channels whatsapp`: start WhatsApp bridge listener loop
- `cargo run -- channels telegram --max-messages 1`: one-message Telegram smoke test
- `cargo run -- channels whatsapp --max-messages 1`: one-message WhatsApp smoke test
- `cargo run -- skills list`: list Rhai skills in workspace
- `cargo run -- skills dry-run --name <skill>`: compile-check a skill
- `cargo run -- skills run --session <id> --name <skill> --args "<arg text>"`: execute a skill
- `cargo run -- codex status`: inspect Codex account pool and queue
- `cargo run -- codex healthcheck`: force Codex account health checks
- `cargo run -- codex generate --prompt "<text>" --purpose "<goal>"`: submit one Codex task
- `cargo run -- codex drain-one`: execute one queued Codex task if allowed
- `cargo run -- pulse status`: inspect scheduler, goals, pending approvals
- `cargo run -- pulse job list`: list scheduler jobs
- `cargo run -- pulse job add-http-healthcheck --id api-health --interval-secs 60 --url "https://example.com/health" --expected-status 200 --timeout-secs 20`: register external health probe
- `cargo run -- pulse job enable --id <job-id>`: enable a scheduler job
- `cargo run -- pulse job disable --id <job-id>`: disable a scheduler job
- `cargo run -- pulse job remove --id <job-id>`: remove a scheduler job
- `cargo run -- pulse tick`: run due scheduler jobs once
- `cargo run -- pulse ooda --action "<action>" --observations '[{"source":"monitor","key":"cpu","value":"95","severity":"warn"}]'`: run one OODA cycle
- `cargo run -- pulse goal add --id <goal-id> --description "<text>"`: add tracked goal
- `cargo run -- pulse approve --token <token>`: approve pending risky action
- `cargo run -- evolution generate-skill --name <skill> --goal "<goal>"`: Codex -> dry-run -> staged promote flow
- `cargo run -- evolution stage-update --artifact <path-to-binary> --artifact-sha256 <sha256>`: stage blue/green update artifact with explicit checksum
- `cargo run -- evolution stage-update --artifact <path-to-binary> [--current-version <x.y.z> --artifact-version <x.y.z>] --artifact-sha256-sums-file <SHA256SUMS> [--artifact-sha256-sums-signature-file <SHA256SUMS.sig>] [--artifact-sha256-entry <name>]`: stage update using checksum manifest entry (optional detached signature verification + non-rollback version metadata)
- `cargo run -- evolution apply-staged-update --confirm --healthcheck-args "doctor" --healthcheck-timeout-secs 30`: apply staged update with checksum verification, staged-manifest freshness guard, key-id-aware signature verification, timeout, auto-rollback on failed health check, and resumable/idempotent apply checkpoints
- `cargo run -- evolution audit-verify`: validate evolution audit log hash chain integrity
- `cargo run -- evolution lock-status`: inspect evolution lock holder/stale status diagnostics
- `cargo run -- evolution recovery-status`: inspect staged apply checkpoint/recovery diagnostics (partial apply state, drift, staged-manifest age/expiry, operator recommendation)
- `cargo run -- evolution active-slot-status`: inspect active-slot marker signature/integrity diagnostics
- `cargo run -- evolution failure-circuit-status`: inspect apply-failure circuit breaker status
- `cargo run -- evolution failure-circuit-reset --confirm`: reset apply-failure circuit breaker after remediation
- `cargo run -- evolution force-unlock --confirm`: force-remove evolution lock file
- Evolution stage/apply operations hold an exclusive lock at `${RUSTY_PINCH_WORKSPACE}/updates/evolution.lock` to prevent concurrent rollout mutations.

Skill bootstrap behavior:

- Tracked starter skills under `assets/skills/*.rhai` are copied to `${RUSTY_PINCH_WORKSPACE}/skills` on app startup when the destination skill file is missing.
- Workspace skills are never overwritten by asset sync.
- Included starter skill: `weather` (`assets/skills/weather.rhai`).

Weather skill args:

- `Hanoi` -> current weather summary
- `forecast|Hanoi` -> forecast output
- `rain|Hanoi` -> precipitation-focused line
- `detail|Hanoi` -> detailed current conditions

Tool commands:

- `cargo run -- tools list`
- `cargo run -- tools run --session <id> --name model_info`
- `cargo run -- run --session <id> --message "/tool session_tail 5"`

Built-in tools:

- `/tool model_info`
- `/tool time_now`
- `/tool session_tail [count]`

Tool safety policy:

- Accept exact `/tool` prefix only (for example `/toolbox` is ignored as tool command)
- Tool names allow `[a-z0-9_-]`, max 64 chars
- Tool args max 512 chars, control characters rejected

Monitor flags:

- `--pid <n>`: monitor a fixed process id
- `--process-match <text>`: auto-discover PID from `/proc/*/cmdline` (default `rusty-pinch`)
- `--interval-ms <n>`: refresh interval in milliseconds (default `1000`)
- `--storage-refresh-ticks <n>`: refresh storage directory scan every N ticks (default `10`)
- `--once`: one-shot snapshot mode

## Environment

Primary variables:

- `RUSTY_PINCH_PROVIDER`
- `RUSTY_PINCH_MODEL`
- `RUSTY_PINCH_REQUEST_TIMEOUT_SECS`
- `RUSTY_PINCH_REQUEST_RETRIES`
- `RUSTY_PINCH_RETRY_BACKOFF_MS`
- `RUSTY_PINCH_RETRY_MAX_BACKOFF_MS`
- `RUSTY_PINCH_DATA_DIR`
- `RUSTY_PINCH_WORKSPACE`
- `RUSTY_PINCH_TELEMETRY_FILE` (default `${RUSTY_PINCH_DATA_DIR}/telemetry/latest.json`)
- `RUSTY_PINCH_ENV_FILE` (optional explicit `.env` file path)
- `RUSTY_PINCH_CODEX_ENABLED`
- `RUSTY_PINCH_CODEX_CLI_BIN`
- `RUSTY_PINCH_CODEX_CLI_ARGS` (default `exec --skip-git-repo-check` to support non-git container runtimes)
- `RUSTY_PINCH_CODEX_PROMPT_FLAG` (default empty/positional prompt)
- `RUSTY_PINCH_CODEX_MODEL_FLAG` (default `--model`)
- `RUSTY_PINCH_CODEX_MODEL` (optional explicit Codex model; defaults to Codex CLI default when unset)
- `RUSTY_PINCH_CODEX_ACCOUNTS` (format: `id|api_key_env|max_requests|model;...`)
- `RUSTY_PINCH_CODEX_AUTO_LOGIN` (container entrypoint Codex login bootstrap, default `true`)
- `RUSTY_PINCH_CODEX_AUTO_LOGIN_MODE` (`chatgpt`, `api-key`, or `off`)
- `RUSTY_PINCH_CODEX_CHATGPT_DEVICE_AUTH` (run `codex login --device-auth` when ChatGPT session missing)
- `RUSTY_PINCH_CODEX_LOGIN_TIMEOUT_SECS` (timeout for login bootstrap commands)
- `RUSTY_PINCH_CODEX_CHATGPT_AUTH_FILE` / `RUSTY_PINCH_CODEX_CHATGPT_AUTH_JSON_B64` (optional pre-seeded ChatGPT auth material)
- `RUSTY_PINCH_CODEX_AUTO_LOGIN_API_KEY_ENV` (API key source env name for `api-key` mode)
- `RUSTY_PINCH_CODEX_RATE_LIMIT_THRESHOLD_PERCENT`
- `RUSTY_PINCH_CODEX_RATE_WINDOW_SECS`
- `RUSTY_PINCH_CODEX_HEALTHCHECK_INTERVAL_SECS`
- `RUSTY_PINCH_PULSE_AUTO_ALLOW_ACTIONS` (CSV keywords; `*` to auto-allow all risky actions)
- `RUSTY_PINCH_EVOLUTION_REQUIRE_APPLY_CONFIRM` (default `true`; requires `--confirm` for apply-staged-update)
- `RUSTY_PINCH_EVOLUTION_REQUIRE_STAGE_ARTIFACT_SHA256` (default `false`; requires `--artifact-sha256` for stage-update)
- `RUSTY_PINCH_EVOLUTION_REQUIRE_NON_ROLLBACK_VERSION` (default `false`; requires `--current-version` and `--artifact-version`, and blocks downgrade/rollback versions)
- `RUSTY_PINCH_EVOLUTION_TRUSTED_SHA256SUMS_SHA256` (optional trusted SHA-256 hash pin for checksum manifest files used by `--artifact-sha256-sums-file`)
- `RUSTY_PINCH_EVOLUTION_TRUSTED_SHA256SUMS_ED25519_PUBLIC_KEY` (optional trusted Ed25519 public key for checksum-manifest detached signatures; accepts 64-char hex or base64)
- `RUSTY_PINCH_EVOLUTION_REQUIRE_SHA256SUMS_SIGNATURE` (default `false`; requires `--artifact-sha256-sums-signature-file` when using checksum-manifest stage flow)
- `RUSTY_PINCH_EVOLUTION_REQUIRE_SIGNED_CHECKSUM_MANIFEST_PROVENANCE` (default `false`; requires apply-time checksum provenance anchored to signed checksum manifests)
- `RUSTY_PINCH_EVOLUTION_REQUIRE_VERIFIED_STAGE_ARTIFACT_SHA256` (default `false`; requires apply-time manifest provenance from checksum-verified stage)
- `RUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEY` (optional HMAC key for staged manifest signing/verification)
- `RUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEY_ID` (optional signing key id for staged manifests; defaults to `default` when key is set)
- `RUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEYS` (optional rotation keyring for verification, format: `id|key;id|key`)
- `RUSTY_PINCH_EVOLUTION_REQUIRE_MANIFEST_SIGNATURE` (default `false`; enforce signature verification before apply)
- `RUSTY_PINCH_EVOLUTION_ACTIVE_SLOT_SIGNING_KEY` (optional HMAC key to sign/verify `${RUSTY_PINCH_WORKSPACE}/updates/active-slot`)
- `RUSTY_PINCH_EVOLUTION_ACTIVE_SLOT_SIGNING_KEY_ID` (optional key id for active-slot signatures; defaults to manifest key id or `default`)
- `RUSTY_PINCH_EVOLUTION_REQUIRE_SIGNED_ACTIVE_SLOT` (default `false`; enforce signed active-slot verification during stage/apply)
- `RUSTY_PINCH_EVOLUTION_MAX_STAGED_MANIFEST_AGE_SECS` (default `86400`; blocks apply when staged manifest age reaches/exceeds threshold, `0` disables)
- `RUSTY_PINCH_EVOLUTION_MAX_CONSECUTIVE_APPLY_FAILURES` (default `3`; opens apply-failure circuit after N consecutive apply failures, `0` disables)
- `RUSTY_PINCH_EVOLUTION_LOCK_STALE_AFTER_SECS` (default `900`; stale lock detection threshold, `0` disables)
- `RUSTY_PINCH_EVOLUTION_AUTO_RECOVER_STALE_LOCK` (default `true`; auto-removes stale evolution lock before stage/apply)
- `RUSTY_PINCH_CHANNELS_TELEGRAM_ENABLED`
- `RUSTY_PINCH_CHANNELS_TELEGRAM_TOKEN`
- `RUSTY_PINCH_CHANNELS_TELEGRAM_ALLOW_FROM`
- `RUSTY_PINCH_CHANNELS_WHATSAPP_ENABLED`
- `RUSTY_PINCH_CHANNELS_WHATSAPP_BRIDGE_URL`
- `RUSTY_PINCH_CHANNELS_WHATSAPP_ALLOW_FROM`

Common key/base overrides:

- `RUSTY_PINCH_OPENROUTER_API_KEY`, `OPENROUTER_API_KEY`
- `RUSTY_PINCH_OPENAI_API_KEY`, `OPENAI_API_KEY`
- `RUSTY_PINCH_OPENROUTER_API_BASE`, `RUSTY_PINCH_OPENAI_API_BASE`, `RUSTY_PINCH_API_BASE`

## Channel Connectivity

Telegram listener (Bot API long polling):

```bash
cargo run -- channels telegram
```

Bounded smoke run:

```bash
cargo run -- channels telegram --max-messages 1
```

Required env:

- `RUSTY_PINCH_CHANNELS_TELEGRAM_ENABLED=true`
- `RUSTY_PINCH_CHANNELS_TELEGRAM_TOKEN=<bot-token>`

Optional:

- `RUSTY_PINCH_CHANNELS_TELEGRAM_ALLOW_FROM=12345678,87654321` (user/chat allowlist)

WhatsApp listener (websocket bridge):

```bash
cargo run -- channels whatsapp
```

Bounded smoke run:

```bash
cargo run -- channels whatsapp --max-messages 1
```

Required env:

- `RUSTY_PINCH_CHANNELS_WHATSAPP_ENABLED=true`
- `RUSTY_PINCH_CHANNELS_WHATSAPP_BRIDGE_URL=ws://localhost:3001`

Shutdown behavior:

- Press `Ctrl+C` to request graceful stop (`event=channel_signal`, then `event=channel_stop`).

## Observability

- Every turn emits one JSON line to stderr (`event=turn`) with:
- `request_id`, `session_id`, `path`, `status`
- `attempts`, `latency_ms` (provider path)
- `tool_name` (tool path)
- `stats` returns persisted telemetry:
- `total_turns`, `ok_turns`, `error_turns`, `provider_turns`, `tool_turns`
- `last_turn` persists across process restarts
- `evolution` telemetry includes latest active-slot integrity state (`active_slot_integrity_status`, signature verify flags, signed-policy flag) and apply-failure circuit status (`apply_failure_consecutive`, `apply_failure_threshold`, `apply_failure_circuit_open`)
- `monitor` adds live process/host/storage metrics:
- `cpu%`, `rss`, `vms`, `read_bytes`, `write_bytes`, `fd_count`
- host `loadavg`, memory + swap, and filesystem/directory footprint
- evolution monitor panel raises `evolution_alert` when active-slot integrity drifts/signature policy fails or when apply-failure circuit is open
- evolution rollout events append to `${RUSTY_PINCH_WORKSPACE}/updates/evolution-audit.jsonl` with hash-chained records (`prev_hash` -> `hash`) for forensic review

## Packaging and Release

Build standalone package locally:

```bash
# from repository root
./scripts/release/build_rusty_pinch_package.sh
# or
make rusty-pinch-package
# verify package
make rusty-pinch-verify-package
# full readiness flow
make rusty-pinch-readiness
```

GitHub Actions automation:

- `.github/workflows/ci.yml` runs on `main` pushes, pull requests, and manual dispatch:
  - `cargo fmt --check`
  - `cargo build --locked`
  - `cargo test --locked`
- `.github/workflows/release.yml` runs on tags matching `v*` (and manual dispatch):
  - release gate (`fmt` + tests)
  - matrix release builds for Linux/macOS/Windows
  - `SHA256SUMS.txt` generation for all release archives
  - automatic GitHub Release asset publish on tag pushes

Tag a release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Deployment profile artifacts:

- systemd templates: `rusty-pinch/deploy/systemd/`
- container profile: `rusty-pinch/deploy/container/`
- Raspberry Pi compose profile: `rusty-pinch/deploy/container/docker-compose.rpi.yml`
- production health checklist: `rusty-pinch/docs/production-healthcheck.md`

Raspberry Pi compose monitor commands:

```bash
cd rusty-pinch/deploy/container
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch monitor --once
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch monitor --pid 1 --interval-ms 1000
```

Optional Codex CLI build for Pi container (no host Rust install needed):

```bash
cd rusty-pinch/deploy/container
export RUSTY_PINCH_INSTALL_CODEX_CLI=true
docker-compose -f docker-compose.rpi.yml build rusty-pinch-telegram
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram codex --version
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram codex login status
```

For container runtimes, set `RUSTY_PINCH_CODEX_CLI_ARGS="exec --skip-git-repo-check"` to avoid Codex git-trust checks on non-repo workdirs.
If Codex session is lost after worker restart/recreate, run:
`docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram codex login --device-auth`.

If turn logs show `Failed to authenticate request with Clerk`, review key envs in
`rusty-pinch.rpi.env` and recreate the worker:

```bash
docker-compose -f docker-compose.rpi.yml up -d --force-recreate rusty-pinch-telegram
```

Artifacts:

- `rusty-pinch-<version>-<os>-<arch>.tar.gz`
- `rusty-pinch-<version>-<os>-<arch>.tar.gz.sha256`

Push only `rusty-pinch/` to a standalone public repository:

```bash
# run from monorepo root
git subtree split --prefix=rusty-pinch -b rusty-pinch-publish
git remote add rusty-pinch-origin <NEW_GITHUB_REPO_URL>
git push rusty-pinch-origin rusty-pinch-publish:main
```

Pre-push safety checklist:

- `rusty-pinch/docs/open-source-publish-checklist.md`

## Media Assets

`assets/` already includes product media for docs and release notes.

![Rusty Pinch Product Media](assets/media-rusty-pinch.png)

- `assets/banner-rusty-pinch.png`
- `assets/logo-rusty-pinch.png`
- `assets/media-rusty-pinch.png`
- `assets/favicon_rusty-pinch/`

## Documentation Index

- Architecture: `rusty-pinch/docs/architecture.md`
- Product Specification: `rusty-pinch/docs/product-specification.md`
- Testing: `rusty-pinch/docs/testing.md`
- Operations: `rusty-pinch/docs/runbook.md`
- Raspberry Pi Deploy Runbook: `rusty-pinch/docs/runbook-raspberry-pi.md`
- Release: `rusty-pinch/docs/release.md`
- Promotion: `rusty-pinch/docs/promotion.md`
- Production Health: `rusty-pinch/docs/production-healthcheck.md`
- Open Source Publish Checklist: `rusty-pinch/docs/open-source-publish-checklist.md`
- Public Docs Manifest: `rusty-pinch/docs/public-docs-manifest.md`
- Security Policy: `rusty-pinch/SECURITY.md`
- Contribution Guide: `rusty-pinch/CONTRIBUTING.md`

## Project Layout

- `src/main.rs`: CLI commands
- `src/config.rs`: env loading and doctor report
- `src/provider.rs`: provider transport + retry policy
- `src/session.rs`: append-only session store
- `src/tools.rs`: deterministic tool registry + guardrails
- `src/telemetry.rs`: persisted runtime telemetry snapshot
- `src/monitor.rs`: terminal monitor for CPU/RAM/storage/process telemetry
- `src/app.rs`: runtime orchestration
- `assets/`: media package
- `docs/`: architecture, testing, operations, release guides
- `deploy/`: systemd and container deployment profiles
