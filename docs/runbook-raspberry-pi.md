# Rusty Pinch Raspberry Pi Zero-Build Runbook

This runbook assumes Raspberry Pi 4 on Ubuntu 64-bit (`aarch64`) and uses `docker-compose` command style.

Goal: Pi only pulls prebuilt `linux/arm64` images from GHCR. No local Rust build.

## 1. Preflight

- Docker Engine installed
- `docker-compose` available (`docker-compose --version`)
- network access to `ghcr.io`
- stable 5V/3A power supply (under-voltage can crash pull/unpack)
- Telegram token and API key ready

## 2. Update repo and check commit

```bash
cd ~/rusty-pinch
git fetch origin --prune
git checkout main
git pull --ff-only origin main
git rev-parse --short HEAD
```

## 3. Prepare deployment directory

```bash
cd ~/rusty-pinch/deploy/container
cp rusty-pinch.rpi.env.example rusty-pinch.rpi.env
mkdir -p ./data ./workspace ./skills ./codex-home ./alloy-data
```

Edit `rusty-pinch.rpi.env` and set at minimum:

- `RUSTY_PINCH_CHANNELS_TELEGRAM_TOKEN`
- `RUSTY_PINCH_OPENAI_API_KEY` (if using Codex account auth)
- `CODEX_HOME=/var/lib/rusty-pinch/codex-home` (keep Codex login state on bind mount)
- `RUSTY_PINCH_OTEL_EXPORTER_OTLP_ENDPOINT=http://alloy:4317` (worker -> alloy)
- `OTEL_EXPORTER_OTLP_ENDPOINT=http://alloy:4317` (legacy worker compatibility for older images)
- `GRAFANA_CLOUD_OTLP_ENDPOINT=https://otlp-gateway-<region>.grafana.net/otlp` (alloy -> Grafana Cloud)
- `GRAFANA_CLOUD_ACCOUNT_ID=<stack_account_id>`
- `GRAFANA_CLOUD_API_TOKEN=<cloud_api_token>`

Rules to avoid self-loop/export issues:
- keep both worker endpoint vars (`RUSTY_PINCH_OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_ENDPOINT`) on `http://alloy:4317`
- only `GRAFANA_CLOUD_OTLP_ENDPOINT` points to Grafana Cloud OTLP gateway

## 4. Authenticate to GHCR (if package is private)

Use a PAT classic with `read:packages`:

```bash
printf '%s' "$GHCR_CLASSIC_PAT" | docker login ghcr.io -u fred-vu --password-stdin
```

Validate image visibility:

```bash
docker pull ghcr.io/fred-vu/rusty-pinch:latest
```

## 5. Pull and start services

```bash
cd ~/rusty-pinch/deploy/container
docker-compose -f docker-compose.rpi.yml pull
docker-compose -f docker-compose.rpi.yml up -d alloy rusty-pinch-telegram watchtower
```

Optional WhatsApp worker:

```bash
docker-compose -f docker-compose.rpi.yml up -d rusty-pinch-whatsapp
```

## 6. Verify runtime

```bash
docker-compose -f docker-compose.rpi.yml ps
docker-compose -f docker-compose.rpi.yml logs -f rusty-pinch-telegram
docker-compose -f docker-compose.rpi.yml logs -f alloy
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch doctor
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram codex --version
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram codex login status
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram /bin/sh -lc 'printf "CODEX_HOME=%s\n" "$CODEX_HOME"'
```

If ChatGPT auth is not active:

```bash
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram codex login --device-auth
```

Grafana OTLP quick-check:

```bash
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram /bin/sh -lc 'printf "rp=%s\notel=%s\n" "$RUSTY_PINCH_OTEL_EXPORTER_OTLP_ENDPOINT" "$OTEL_EXPORTER_OTLP_ENDPOINT"'
docker-compose -f docker-compose.rpi.yml exec alloy /bin/sh -lc 'printf "cloud=%s\nacct=%s\ntoken_len=%s\n" "$GRAFANA_CLOUD_OTLP_ENDPOINT" "$GRAFANA_CLOUD_ACCOUNT_ID" "${#GRAFANA_CLOUD_API_TOKEN}"'
docker-compose -f docker-compose.rpi.yml logs --tail=300 alloy | egrep -i "Exporting failed|401|403|unauth|denied|retry"
```

## 7. Auto-update behavior (Watchtower)

- `watchtower` polls every 300 seconds by default.
- Override poll interval:

```bash
export WATCHTOWER_POLL_INTERVAL_SECS=900
docker-compose -f docker-compose.rpi.yml up -d watchtower
```

When new `latest` image appears on GHCR, Watchtower pulls and restarts service with same volumes.

## 8. Upgrade and rollback

Upgrade now:

```bash
docker-compose -f docker-compose.rpi.yml pull rusty-pinch-telegram
docker-compose -f docker-compose.rpi.yml up -d rusty-pinch-telegram
```

Pin a known tag (rollback):

```bash
export RUSTY_PINCH_IMAGE=ghcr.io/fred-vu/rusty-pinch:v1.0.0
docker-compose -f docker-compose.rpi.yml up -d rusty-pinch-telegram
```

## 9. Stability hardening on low-power Pi

If previous pulls caused crashes:

```bash
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

```bash
printf '{\n  "max-concurrent-downloads": 1\n}\n' | sudo tee /etc/docker/daemon.json >/dev/null
sudo systemctl restart docker
```

Check undervoltage events:

```bash
sudo journalctl -k -b | egrep -i "Under-voltage|Voltage normalised"
```

## 10. Docker recovery quick fix

If `docker.service` enters restart loop:

```bash
sudo rm -f /etc/docker/daemon.json
sudo systemctl reset-failed docker.service
sudo systemctl restart containerd
sudo systemctl restart docker
systemctl status docker --no-pager
```

Collect logs if still failing:

```bash
sudo journalctl -u docker.service -n 200 --no-pager
sudo journalctl -xeu docker.service --no-pager | tail -n 120
```

## 11. Operations notes

- Keep only one long-poll consumer per Telegram bot token to avoid HTTP `409 Conflict`.
- State persistence paths:
  - `./data` -> session/telemetry data
  - `./workspace` -> pulse/evolution workspace state
  - `./skills` -> dynamic Rhai skills (hot-swappable)
  - `./codex-home` -> Codex login/session state
- Avoid commands that delete persistence paths unless intentional:
  - `docker-compose down -v`
  - `git clean -fdx` inside `deploy/container`
- If `sudo` warns `unable to resolve host ubuntu`, fix `/etc/hosts`:

```bash
echo "127.0.1.1 ubuntu" | sudo tee -a /etc/hosts
```

## 12. Grafana Cloud dashboards and alert baseline

Create these dashboard panels from OTLP metrics:

- Provider latency by provider (P50/P90/P99):
  - `histogram_quantile(0.50, sum by (le, provider) (rate(provider_latency_seconds_bucket[5m])))`
  - `histogram_quantile(0.90, sum by (le, provider) (rate(provider_latency_seconds_bucket[5m])))`
  - `histogram_quantile(0.99, sum by (le, provider) (rate(provider_latency_seconds_bucket[5m])))`
- Tool execution frequency:
  - `sum by (tool_name, source) (rate(tool_executions_total[5m]))`
- Provider error ratio:
  - `sum(rate(provider_latency_seconds_count{status="error"}[5m])) / clamp_min(sum(rate(provider_latency_seconds_count[5m])), 1)`

Recommended alert rule:

- Name: `rusty-pinch-provider-error-rate`
- Condition: provider error ratio `> 0.10` for `5m`
- Notification: route to Telegram contact point (new bot/token dedicated for alerts).
