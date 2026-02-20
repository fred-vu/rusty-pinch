# Rusty Pinch Container Deployment

## Files

- `Dockerfile`: multi-stage runtime image.
- `docker-compose.example.yml`: local compose profile (build from source).
- `docker-compose.rpi.yml`: Raspberry Pi zero-build profile (pull from GHCR).
- `rusty-pinch.env.example`: local compose env template.
- `rusty-pinch.rpi.env.example`: Raspberry Pi env template.

## Local build profile

Use this for workstation development:

```bash
cd rusty-pinch/deploy/container
cp rusty-pinch.env.example rusty-pinch.env
# fill API keys / channel tokens
docker compose -f docker-compose.example.yml up -d rusty-pinch-telegram
```

## Raspberry Pi zero-build profile (recommended)

Target: Raspberry Pi 64-bit (`linux/arm64`).

This profile does not run `docker build` on Pi. It pulls prebuilt images from GHCR.

```bash
cd rusty-pinch/deploy/container
cp rusty-pinch.rpi.env.example rusty-pinch.rpi.env
# fill API keys / channel tokens
mkdir -p ./data ./workspace ./skills ./codex-home
docker compose -f docker-compose.rpi.yml pull
docker compose -f docker-compose.rpi.yml up -d rusty-pinch-telegram watchtower
```

Optional WhatsApp worker:

```bash
docker compose -f docker-compose.rpi.yml up -d rusty-pinch-whatsapp
```

Optional image override:

```bash
export RUSTY_PINCH_IMAGE=ghcr.io/fred-vu/rusty-pinch:v1.0.0
docker compose -f docker-compose.rpi.yml up -d rusty-pinch-telegram
```

## Watchtower auto-update

`watchtower` is included in `docker-compose.rpi.yml`.

- default poll interval: `300` seconds
- override interval:

```bash
export WATCHTOWER_POLL_INTERVAL_SECS=900
docker compose -f docker-compose.rpi.yml up -d watchtower
```

## GHCR auth (if package is private)

```bash
echo "$GITHUB_FINEGRAINED" | docker login ghcr.io -u <github-username> --password-stdin
```

## Codex runtime notes

Published GHCR image is built with Codex CLI included.

Recommended env settings in `rusty-pinch.rpi.env`:

- `RUSTY_PINCH_CODEX_ENABLED=true`
- `RUSTY_PINCH_CODEX_CLI_BIN=codex`
- `RUSTY_PINCH_CODEX_CLI_ARGS=exec --skip-git-repo-check`
- `RUSTY_PINCH_CODEX_PROMPT_FLAG=`
- `RUSTY_PINCH_CODEX_AUTO_LOGIN=true`

Manual login fallback:

```bash
docker compose -f docker-compose.rpi.yml exec rusty-pinch-telegram codex login --device-auth
docker compose -f docker-compose.rpi.yml exec rusty-pinch-telegram codex login status
```

## Logs and health

```bash
docker compose -f docker-compose.rpi.yml ps
docker compose -f docker-compose.rpi.yml logs -f rusty-pinch-telegram
docker compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch doctor
```

Expected signals:

- startup log with `event=channel_start`
- traffic log with `event=turn`

## Monitor

```bash
docker compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch monitor --once
```
