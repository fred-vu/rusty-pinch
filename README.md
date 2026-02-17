# Rusty Pinch

![Rusty Pinch Banner](assets/banner-rusty-pinch.png)

Rusty Pinch is a clean, standalone Rust runtime package for the assistant stack.  

![Rusty Pinch Logo](assets/logo-rusty-pinch.png)

## What You Get

- Rust CLI runtime: `rusty-pinch`
- Env-first configuration with strict `.env` support
- OpenAI-compatible provider calls (`openrouter`, `openai`, `groq`, `compatible`) and `local` mode
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

Remote provider run (OpenRouter example):

```bash
# set key in .env first
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
- `monitor` adds live process/host/storage metrics:
- `cpu%`, `rss`, `vms`, `read_bytes`, `write_bytes`, `fd_count`
- host `loadavg`, memory + swap, and filesystem/directory footprint

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

Deployment profile artifacts:

- systemd templates: `rusty-pinch/deploy/systemd/`
- container profile: `rusty-pinch/deploy/container/`
- Raspberry Pi compose profile: `rusty-pinch/deploy/container/docker-compose.rpi.yml`
- production health checklist: `rusty-pinch/docs/production-healthcheck.md`

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
