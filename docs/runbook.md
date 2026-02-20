# Rusty Pinch Runbook

## Runtime prerequisites

- Rust toolchain (`cargo`) for source runs, or packaged binary for release.
- `.env` file with provider/model/api key settings.
- Writable runtime paths:
  - `RUSTY_PINCH_DATA_DIR`
  - `RUSTY_PINCH_WORKSPACE`
  - `RUSTY_PINCH_TELEMETRY_FILE` (optional override)

For a full Raspberry Pi Docker Compose deployment walkthrough, use:

- `rusty-pinch/docs/runbook-raspberry-pi.md`

## Startup sequence

1. Validate env and paths:

```bash
cargo run -- doctor
```

2. Smoke one turn:

```bash
cargo run -- run --session smoke --message "health check"
```

3. Check telemetry snapshot:

```bash
cargo run -- stats
```

4. Check live resource monitor:

```bash
cargo run -- monitor
```

One-shot monitor snapshot (recommended for quick health checks):

```bash
cargo run -- monitor --once
```

5. Start channel listener when required:

```bash
cargo run -- channels telegram
# or
cargo run -- channels whatsapp
```

Bounded acceptance mode (recommended for first WhatsApp test):

```bash
cargo run -- channels whatsapp --max-messages 1
```

6. Run standalone readiness pipeline before release/canary:

```bash
make rusty-pinch-readiness
```

7. Choose deployment profile:
- systemd: `rusty-pinch/deploy/systemd/README.md`
- container: `rusty-pinch/deploy/container/README.md`

Raspberry Pi container profile quick start:

```bash
cd rusty-pinch/deploy/container
cp rusty-pinch.rpi.env.example rusty-pinch.rpi.env
mkdir -p ./data ./workspace ./skills ./codex-home
docker-compose -f docker-compose.rpi.yml pull
docker-compose -f docker-compose.rpi.yml up -d rusty-pinch-telegram watchtower
```

Raspberry Pi monitor via compose:

```bash
cd rusty-pinch/deploy/container
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch monitor --once
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch monitor --pid 1 --interval-ms 1000
```

## Health signals

- `doctor` must show `status: ok` for remote providers.
- `stats.telemetry.total_turns` should increase over time.
- `monitor` should show target process metrics (`pid`, `cpu`, `rss`) and host metrics.
- Every turn emits one JSON log line with `event=turn` and `request_id`.
- `session` output should include both user and assistant messages.
- channel startup logs should emit `event=channel_start`.
- graceful stop logs should emit `event=channel_signal` and `event=channel_stop`.

## Failure triage

1. API/auth failures:
   - verify `.env` key vars and `doctor` output (`api_key_loaded`, `api_base`).
2. Provider/network timeouts:
   - tune retry vars (`RUSTY_PINCH_REQUEST_RETRIES`, backoff settings).
3. Tool call rejection:
   - validate guardrails (`/tool` prefix, tool name chars, args control chars).
4. Telemetry write errors:
   - verify parent dir permissions for `RUSTY_PINCH_TELEMETRY_FILE`.
5. Telegram listener fails to start:
   - verify `RUSTY_PINCH_CHANNELS_TELEGRAM_ENABLED=true`
   - verify `RUSTY_PINCH_CHANNELS_TELEGRAM_TOKEN` is set.
6. WhatsApp listener reconnect loop:
   - verify `RUSTY_PINCH_CHANNELS_WHATSAPP_BRIDGE_URL`
   - verify bridge service is reachable from runtime host.
7. Need controlled first-run validation:
   - use `--max-messages 1` to validate one inbound/outbound cycle and auto-exit.
8. OpenRouter auth failure (`Failed to authenticate request with Clerk`):
   - verify key source in env (`RUSTY_PINCH_OPENROUTER_API_KEY` preferred; avoid stale `RUSTY_PINCH_API_KEY` override).
   - verify `RUSTY_PINCH_PROVIDER=openrouter` and `api_base=https://openrouter.ai/api/v1` in `doctor`.
   - recreate compose worker after key changes: `docker-compose -f docker-compose.rpi.yml up -d --force-recreate rusty-pinch-telegram`.
9. GHCR pull denied or manifest not found:
   - verify login with PAT classic `read:packages`: `printf '%s' "$GHCR_CLASSIC_PAT" | docker login ghcr.io -u fred-vu --password-stdin`.
   - verify image existence: `docker pull ghcr.io/fred-vu/rusty-pinch:latest`.
10. Raspberry Pi crash while pulling image:
   - inspect kernel log for undervoltage: `sudo journalctl -k -b -1 | egrep -i "Under-voltage|Voltage normalised"`.
   - apply swap + low Docker download concurrency before retry.

## Backup and cleanup

- Session history: `${RUSTY_PINCH_DATA_DIR}/sessions/*.jsonl`
- Telemetry snapshot: `${RUSTY_PINCH_TELEMETRY_FILE}`
- Remove runtime data only when safe:

```bash
rm -rf <data-dir> <workspace-dir>
```
