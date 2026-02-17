# Rusty Pinch container profile

## Files

- `Dockerfile`: builds and packages `rusty-pinch` runtime.
- `docker-compose.example.yml`: compose profile for Telegram and optional WhatsApp worker.
- `docker-compose.rpi.yml`: Raspberry Pi compose profile (ARM-focused, bind-mounted state).
- `rusty-pinch.env.example`: env template for compose runs.
- `rusty-pinch.rpi.env.example`: env template for Raspberry Pi compose runs.

## Quick start

Use `docker compose` (v2). If your host only has legacy `docker-compose` (v1), replace `docker compose` with `docker-compose` in all commands below.

```bash
cd rusty-pinch/deploy/container
cp rusty-pinch.env.example rusty-pinch.env
# fill API keys / tokens

docker compose -f docker-compose.example.yml up -d rusty-pinch-telegram
```

Enable WhatsApp worker (community test mode):

```bash
docker compose -f docker-compose.example.yml up -d rusty-pinch-whatsapp
```

## Raspberry Pi quick start (recommended)

Target: Raspberry Pi OS 64-bit (`aarch64` / `linux/arm64`).

Detailed runbook:

- `rusty-pinch/docs/runbook-raspberry-pi.md`

```bash
cd rusty-pinch/deploy/container
cp rusty-pinch.rpi.env.example rusty-pinch.rpi.env
# fill API key / Telegram token
mkdir -p ./state/data ./state/workspace

docker compose -f docker-compose.rpi.yml build
docker compose -f docker-compose.rpi.yml up -d rusty-pinch-telegram
```

Enable WhatsApp worker (community test mode):

```bash
docker compose -f docker-compose.rpi.yml up -d rusty-pinch-whatsapp
```

Optional overrides:

- `RUSTY_PINCH_DOCKER_PLATFORM=linux/arm64` (default)
- `RUSTY_PINCH_HOST_STATE_DIR=/opt/rusty-pinch/state` (host persistence root)
- `RUSTY_PINCH_IMAGE=rusty-pinch:pi-local`

If your Pi is 32-bit (`armv7`), set `RUSTY_PINCH_DOCKER_PLATFORM=linux/arm/v7` before running compose.

## Logs and health

```bash
docker compose -f docker-compose.example.yml logs -f rusty-pinch-telegram
```

Expected signals:

- startup log with `event=channel_start`
- per-turn log with `event=turn`
- graceful stop signal logs on shutdown

Raspberry Pi logs/health:

```bash
docker compose -f docker-compose.rpi.yml logs -f rusty-pinch-telegram
docker compose -f docker-compose.rpi.yml ps
```
