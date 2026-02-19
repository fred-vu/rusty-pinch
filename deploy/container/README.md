# Rusty Pinch container profile

## Files

- `Dockerfile`: builds and packages `rusty-pinch` runtime.
- `docker-compose.example.yml`: compose profile for Telegram and optional WhatsApp worker.
- `docker-compose.rpi.yml`: Raspberry Pi compose profile (ARM-focused, bind-mounted state).
- `rusty-pinch.env.example`: env template for compose runs.
- `rusty-pinch.rpi.env.example`: env template for Raspberry Pi compose runs.

## Quick start

Use `docker-compose` (v1-compatible). If your host uses Docker Compose v2 plugin, the equivalent command is `docker compose`.

```bash
cd rusty-pinch/deploy/container
cp rusty-pinch.env.example rusty-pinch.env
# fill API keys / tokens

docker-compose -f docker-compose.example.yml up -d rusty-pinch-telegram
```

Enable WhatsApp worker (community test mode):

```bash
docker-compose -f docker-compose.example.yml up -d rusty-pinch-whatsapp
```

## Raspberry Pi quick start (recommended)

Target: Raspberry Pi OS 64-bit (`aarch64` / `linux/arm64`).

Detailed runbook:

- `rusty-pinch/docs/runbook-raspberry-pi.md`

```bash
cd rusty-pinch/deploy/container
cp rusty-pinch.rpi.env.example rusty-pinch.rpi.env
# fill API key / Telegram token
mkdir -p ./state/data ./state/workspace ./state/codex-home

docker-compose -f docker-compose.rpi.yml build
docker-compose -f docker-compose.rpi.yml up -d rusty-pinch-telegram
```

Enable WhatsApp worker (community test mode):

```bash
docker-compose -f docker-compose.rpi.yml up -d rusty-pinch-whatsapp
```

Optional overrides:

- `RUSTY_PINCH_HOST_STATE_DIR=/opt/rusty-pinch/state` (host persistence root)
- `RUSTY_PINCH_IMAGE=rusty-pinch:pi-local`

## Optional: Codex integration in container

Host Rust installation is not required. The image build compiles Rust in a builder stage.

To include Codex CLI in the runtime image, enable build arg `INSTALL_CODEX_CLI`:

```bash
cd rusty-pinch/deploy/container
export RUSTY_PINCH_INSTALL_CODEX_CLI=true
docker-compose -f docker-compose.rpi.yml build rusty-pinch-telegram
```

Then configure runtime env in `rusty-pinch.rpi.env`:

- `RUSTY_PINCH_CODEX_ENABLED=true`
- `RUSTY_PINCH_CODEX_CLI_BIN=codex`
- `RUSTY_PINCH_CODEX_CLI_ARGS="exec --skip-git-repo-check"`
- `RUSTY_PINCH_CODEX_PROMPT_FLAG=`
- `RUSTY_PINCH_CODEX_AUTO_LOGIN=true`
- `RUSTY_PINCH_CODEX_AUTO_LOGIN_MODE=chatgpt`
- `RUSTY_PINCH_CODEX_CHATGPT_DEVICE_AUTH=true`

`--skip-git-repo-check` is required because the runtime workdir in this image is not a git repository.

Optional account/env wiring:

- `RUSTY_PINCH_OPENAI_API_KEY=<key>`
- `RUSTY_PINCH_CODEX_ACCOUNTS=primary|RUSTY_PINCH_OPENAI_API_KEY|200|gpt-5-codex`

Auth bootstrap behavior:

- container entrypoint auto-checks `codex login status`
- login state is persisted in mounted `codex-home` volume
- when mode is `chatgpt`, entrypoint runs `codex login --device-auth` if session is missing
- when mode is `api-key`, entrypoint runs `codex login --with-api-key` using `RUSTY_PINCH_CODEX_AUTO_LOGIN_API_KEY_ENV` (default `RUSTY_PINCH_OPENAI_API_KEY`)
- in some Raspberry Pi deployments, recreate/restart may still lose active ChatGPT session and require manual login again

Manual fallback command:

```bash
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram codex login --device-auth
```

If session is lost after restart/recreate, rerun:

```bash
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram codex login --device-auth
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram codex login status
```

Smoke-check from running worker:

```bash
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram codex --version
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram codex login status
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch codex status
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch codex generate --prompt "ping" --purpose "smoke"
```

## Logs and health

```bash
docker-compose -f docker-compose.example.yml logs -f rusty-pinch-telegram
```

Expected signals:

- startup log with `event=channel_start`
- per-turn log with `event=turn`
- graceful stop signal logs on shutdown

Raspberry Pi logs/health:

```bash
docker-compose -f docker-compose.rpi.yml logs -f rusty-pinch-telegram
docker-compose -f docker-compose.rpi.yml ps
```

## Monitor from Compose

One-shot snapshot from the running Telegram worker:

```bash
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch monitor --once
```

Live monitor view (inside container, PID 1):

```bash
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch monitor --pid 1 --interval-ms 1000
```

## Common incident: OpenRouter auth failure

Symptom in logs:

- `provider_error=Failed to authenticate request with Clerk`

Triage:

1. Run `doctor` in the running container:

```bash
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch doctor
```

2. Verify key source (avoid ambiguous generic key overrides):

```bash
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram /bin/sh -lc 'env | grep -E "RUSTY_PINCH_(API_KEY|OPENROUTER_API_KEY|PROVIDER|MODEL|OPENROUTER_API_BASE)"'
```

3. After env/key update, recreate worker:

```bash
docker-compose -f docker-compose.rpi.yml up -d --force-recreate rusty-pinch-telegram
```
