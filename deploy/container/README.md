# Rusty Pinch Container Deployment

Command style in this document uses `docker-compose` for compatibility with Raspberry Pi environments running compose v1.

## Files

- `Dockerfile`: multi-stage runtime image.
- `docker-compose.example.yml`: local compose profile (build from source).
- `docker-compose.rpi.yml`: Raspberry Pi zero-build profile (pull from GHCR).
- `rusty-pinch.env.example`: local compose env template.
- `rusty-pinch.rpi.env.example`: Raspberry Pi env template.
- `../config/config.alloy`: Grafana Alloy OTLP receiver/exporter config.

## Local build profile

Use this for workstation development:

```bash
cd rusty-pinch/deploy/container
cp rusty-pinch.env.example rusty-pinch.env
# fill API keys / channel tokens
docker-compose -f docker-compose.example.yml up -d rusty-pinch-telegram
```

Optional observability stack (Alloy + worker):

```bash
docker-compose -f docker-compose.example.yml up -d alloy rusty-pinch-telegram
```

## Raspberry Pi zero-build profile (recommended)

Target: Raspberry Pi 64-bit (`linux/arm64`).

This profile does not run `docker build` on Pi. It pulls prebuilt images from GHCR.

```bash
cd rusty-pinch/deploy/container
cp rusty-pinch.rpi.env.example rusty-pinch.rpi.env
# fill API keys / channel tokens
mkdir -p ./data ./workspace ./skills ./codex-home ./alloy-data
docker-compose -f docker-compose.rpi.yml pull
docker-compose -f docker-compose.rpi.yml up -d alloy rusty-pinch-telegram watchtower
```

For Grafana Cloud forwarding, set these in `rusty-pinch.rpi.env`:

- `RUSTY_PINCH_OTEL_EXPORTER_OTLP_ENDPOINT=http://alloy:4317` (worker -> alloy)
- `OTEL_EXPORTER_OTLP_ENDPOINT=http://alloy:4317` (legacy worker compatibility for older images)
- `GRAFANA_CLOUD_OTLP_ENDPOINT=https://otlp-gateway-<region>.grafana.net/otlp` (alloy -> Grafana Cloud)
- `GRAFANA_CLOUD_ACCOUNT_ID=<stack_account_id>`
- `GRAFANA_CLOUD_API_TOKEN=<cloud_api_token>`

Important:
- keep both worker endpoint variables pointed at `http://alloy:4317`
- do not set `OTEL_EXPORTER_OTLP_ENDPOINT` to Grafana Cloud in compose env files
- only `GRAFANA_CLOUD_OTLP_ENDPOINT` should point to the Grafana OTLP gateway

Optional WhatsApp worker:

```bash
docker-compose -f docker-compose.rpi.yml up -d rusty-pinch-whatsapp
```

Optional image override:

```bash
export RUSTY_PINCH_IMAGE=ghcr.io/fred-vu/rusty-pinch:v1.0.0
docker-compose -f docker-compose.rpi.yml up -d rusty-pinch-telegram
```

## Watchtower auto-update

`watchtower` is included in `docker-compose.rpi.yml`.

- default poll interval: `300` seconds
- override interval:

```bash
export WATCHTOWER_POLL_INTERVAL_SECS=900
docker-compose -f docker-compose.rpi.yml up -d watchtower
```

## GHCR auth (if package is private)

```bash
printf '%s' "$GHCR_CLASSIC_PAT" | docker login ghcr.io -u fred-vu --password-stdin
```

## Codex runtime notes

Published GHCR image is built with Codex CLI included.

Recommended env settings in `rusty-pinch.rpi.env`:

- `RUSTY_PINCH_CODEX_ENABLED=true`
- `CODEX_HOME=/var/lib/rusty-pinch/codex-home`
- `RUSTY_PINCH_CODEX_CLI_BIN=codex`
- `RUSTY_PINCH_CODEX_CLI_ARGS=exec --skip-git-repo-check`
- `RUSTY_PINCH_CODEX_PROMPT_FLAG=`
- `RUSTY_PINCH_CODEX_AUTO_LOGIN=true`

Persistence notes:

- `./codex-home` is the durable Codex auth state mount. Keep this directory across updates.
- avoid `docker-compose down -v` when you need to keep Codex login state.
- avoid `git clean -fdx` inside `deploy/container` unless you accept re-login.

Manual login fallback:

```bash
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram codex login --device-auth
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram codex login status
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram /bin/sh -lc 'printf "CODEX_HOME=%s\n" "$CODEX_HOME"'
```

## Logs and health

```bash
docker-compose -f docker-compose.rpi.yml ps
docker-compose -f docker-compose.rpi.yml logs -f rusty-pinch-telegram
docker-compose -f docker-compose.rpi.yml logs -f alloy
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch doctor
```

Expected signals:

- startup log with `event=channel_start`
- traffic log with `event=turn`

## Grafana OTLP quick-check

```bash
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram /bin/sh -lc 'printf "rp=%s\notel=%s\n" "$RUSTY_PINCH_OTEL_EXPORTER_OTLP_ENDPOINT" "$OTEL_EXPORTER_OTLP_ENDPOINT"'
docker-compose -f docker-compose.rpi.yml exec alloy /bin/sh -lc 'printf "cloud=%s\nacct=%s\ntoken_len=%s\n" "$GRAFANA_CLOUD_OTLP_ENDPOINT" "$GRAFANA_CLOUD_ACCOUNT_ID" "${#GRAFANA_CLOUD_API_TOKEN}"'
docker-compose -f docker-compose.rpi.yml logs --tail=300 alloy | egrep -i "Exporting failed|401|403|unauth|denied|retry"
```

## Monitor

```bash
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch monitor --once
```
