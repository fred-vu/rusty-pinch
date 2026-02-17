# Rusty Pinch Production Healthcheck

## Scope

Operational checklist for standalone `rusty-pinch` deployments (package, systemd, or container profile).

## Preflight (before enabling workers)

1. Runtime config:

```bash
rusty-pinch doctor
```

Expected:

- `status: ok`
- `api_key_loaded: true` for remote providers
- correct `data_dir`, `workspace`, `telemetry_file`

2. Local smoke:

```bash
rusty-pinch run --session health-smoke --message "health check"
rusty-pinch stats
```

Expected: one `event=turn` log and telemetry counters increment.

## Channel worker checks

Telegram worker:

- service/process is running
- startup log contains `event=channel_start` with channel `telegram`

WhatsApp bridge worker (community phase):

- service/process is running when enabled
- startup log contains `event=channel_start` with channel `whatsapp`
- optional bounded acceptance run succeeds:

```bash
rusty-pinch channels whatsapp --max-messages 1
```

## Ongoing signals

- No sustained `channel_connect_error` / `channel_poll_error` loops.
- `event=turn` logs continue for active traffic.
- `rusty-pinch stats` remains readable and telemetry file updates.
- Session files continue appending under `${RUSTY_PINCH_DATA_DIR}/sessions/`.

## First 24h Checklist (Raspberry Pi)

Every 2-4 hours:

- `docker compose -f docker-compose.rpi.yml ps`
- `docker compose -f docker-compose.rpi.yml logs --since 2h rusty-pinch-telegram`
- `docker stats --no-stream`
- `df -h`
- `free -h`

Expected:

- no repeated crash-restart loop
- no sustained `channel_*_error` loop
- telemetry counters continue increasing
- disk usage growth remains predictable

## Incident triage

1. Auth/provider issues:
- verify env keys and `doctor` output.

2. Worker stops/restarts frequently:
- inspect logs for `channel_send_error`, `channel_parse_error`, provider failures.

3. Storage/permission failures:
- verify write access for data/workspace/telemetry paths.

## Release gate recommendation

Run one command before production rollout:

```bash
make rusty-pinch-readiness
```

This runs format, check, tests, smoke, package build, and package verification.
