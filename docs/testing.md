# Rusty Pinch Testing

Run all commands from `rusty-pinch/`.

## Build and Check

```bash
cargo fmt --all
cargo check
cargo test
```

## Manual Runtime Checks

1. Doctor check

```bash
cargo run -- doctor
```

2. One-turn run

```bash
cargo run -- run --session smoke --message "say hello in one sentence"
```

3. Local tool-path check (deterministic, no provider call)

```bash
cargo run -- tools list
cargo run -- tools run --session smoke --name model_info
cargo run -- run --session smoke --message "/tool session_tail 5"
```

4. Verify session persistence

```bash
cargo run -- session --session smoke
```

5. Inspect runtime stats

```bash
cargo run -- stats
```

5.1 Inspect resource monitor snapshot

```bash
cargo run -- monitor --once
```

Optional live monitor:

```bash
cargo run -- monitor --process-match rusty-pinch --interval-ms 1000
```

6. Validate observability contract

```bash
cargo test --test observability
```

7. Validate tool safety guardrails

```bash
cargo test --test tools
```

8. Validate telemetry persistence across process restart

```bash
cargo test --test observability telemetry_persists_across_app_instances
```

9. Build standalone package

```bash
../scripts/release/build_rusty_pinch_package.sh /tmp/rusty-pinch-package
```

9.1 Verify package integrity and packaged binary runtime

```bash
../scripts/release/verify_rusty_pinch_package.sh /tmp/rusty-pinch-package
```

9.2 One-command readiness flow

```bash
make rusty-pinch-readiness
```

9.3 Validate deploy profile artifacts

```bash
make rusty-pinch-deploy-check
```

9.4 (Optional) Validate Raspberry Pi compose manifest syntax

```bash
cd deploy/container
cp rusty-pinch.rpi.env.example rusty-pinch.rpi.env
docker-compose -f docker-compose.rpi.yml config >/dev/null
```

9.5 (Optional) Validate monitor command in compose runtime

```bash
cd deploy/container
docker-compose -f docker-compose.rpi.yml up -d rusty-pinch-telegram
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch monitor --once
```

10. Validate channel env contract and parser coverage

```bash
cargo test --test channels
```

11. Start Telegram listener (manual integration check)

```bash
cargo run -- channels telegram
```

Telegram bounded smoke:

```bash
cargo run -- channels telegram --max-messages 1
```

12. Start WhatsApp bridge listener (manual integration check)

```bash
cargo run -- channels whatsapp
```

WhatsApp bounded smoke:

```bash
cargo run -- channels whatsapp --max-messages 1
```

## Env Verification

Use one of these approaches:

- default `.env` in `rusty-pinch/`
- explicit file:

```bash
RUSTY_PINCH_ENV_FILE=/path/to/.env cargo run -- doctor
```

Recommended `.env` for default Codex provider call:

```dotenv
RUSTY_PINCH_PROVIDER=codex
RUSTY_PINCH_MODEL=gpt-5-codex
RUSTY_PINCH_CODEX_ENABLED=true
RUSTY_PINCH_CODEX_CLI_BIN=codex
RUSTY_PINCH_CODEX_CLI_ARGS="exec --skip-git-repo-check"
RUSTY_PINCH_REQUEST_RETRIES=2
```

## Expected Signals

- `doctor` reports `codex_enabled: true` when running with `RUSTY_PINCH_PROVIDER=codex`.
- `doctor` reports `api_key_loaded: true` for OpenAI-compatible providers.
- `doctor` reports non-empty `api_base` for OpenAI-compatible providers.
- `doctor` reports resolved `telemetry_file` path.
- transient provider failures (`429`/`5xx`) are retried based on retry env settings.
- `tools list` output order is stable across runs.
- `/toolbox ...` is not parsed as a tool command.
- tool guardrails reject invalid tool names and control-character args.
- channel listeners fail fast when required env is missing (token/bridge URL).
- channel listeners support bounded runs via `--max-messages` for acceptance testing.
- `Ctrl+C` emits graceful shutdown signals (`channel_signal` then `channel_stop`).
- Telegram/WhatsApp channel message parsing tests pass (`cargo test --test channels`).
- session command returns JSON history with both `user` and `assistant` entries.
- each `run`/`tools run` turn prints one JSON log event with `event=turn` and `request_id`.
- `stats` includes persisted `telemetry.total_turns` and `last_turn` after process restart.
- `monitor --once` prints app/process/host/storage blocks without error.
- compose monitor command works against running container (`exec ... rusty-pinch monitor --once`).
- package build command emits `.tar.gz` and `.sha256` artifact pair.
- package verification command validates checksum + extracted contents + packaged binary smoke.
- deploy profile check validates systemd/container artifacts and healthcheck docs.
- tests pass with no panic/failure.
