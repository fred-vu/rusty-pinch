# Rusty Pinch Architecture (Clean Package)

## Objective

Provide a clean Rust-first runtime package in an isolated directory, while preserving the existing production migration track.

## Runtime Flow

1. Load `.env` (or `RUSTY_PINCH_ENV_FILE`) and process env.
2. Build `Settings` from env values.
3. Initialize `RustyPinchApp`:
   - `SessionStore` for append-only history
   - `MessageBus` for queue behavior and counters
   - `PromptBuilder` with static prompt cache
   - `provider` runtime for OpenAI-compatible chat completion with retry/backoff policy
   - deterministic `ToolRegistry` for local `/tool ...` command path
   - turn observability recorder (`request_id`, path, status, provider metrics)
   - persisted telemetry store (`RUSTY_PINCH_TELEMETRY_FILE`)
4. Execute command (`doctor`, `run`, `repl`, `session`, `stats`, `monitor`, `channels`).

## Storage

Session messages are stored as JSON lines at:

- `${RUSTY_PINCH_DATA_DIR}/sessions/<session>.jsonl`

Each entry contains `role`, `content`, and `timestamp`.

Telemetry snapshot is stored at:

- `${RUSTY_PINCH_TELEMETRY_FILE}` (default `${RUSTY_PINCH_DATA_DIR}/telemetry/latest.json`)

Telemetry stores aggregate counters and the latest turn record for cross-process diagnostics.

## Deterministic Tools

- Tools are stored in a sorted registry to guarantee stable list/order.
- Local tool command format: `/tool <name> [args]`.
- Guardrails are enforced before execution:
  - exact `/tool` prefix only
  - tool name allowlist chars `[a-z0-9_-]` with max length
  - arg length cap and control-character rejection
- Current built-ins:
  - `model_info`
  - `time_now`
  - `session_tail`

## Runtime Observability

- Each turn receives a generated `request_id` (for log and error correlation).
- Provider path captures:
  - `attempts`
  - `latency_ms` (end-to-end, including retry backoff)
- Tool path captures:
  - `tool_name`
  - command/response size counters
- One structured JSON log line is emitted per turn (`event=turn`).
- `stats` endpoint includes persisted telemetry counters and `last_turn`.
- `monitor` command reads Linux `/proc` + telemetry snapshot to render live TUI status:
  - process (`cpu%`, `rss`, `vms`, read/write bytes, fd count)
  - host (`loadavg`, memory, swap)
  - storage (`data_dir`, `workspace`, filesystem usage)

## Channel Adapters

- Telegram adapter:
  - long polling via Telegram Bot API (`getUpdates`)
  - send replies via `sendMessage`
  - supports bounded-run mode (`--max-messages N`) and graceful stop signal
  - env gating:
    - `RUSTY_PINCH_CHANNELS_TELEGRAM_ENABLED`
    - `RUSTY_PINCH_CHANNELS_TELEGRAM_TOKEN`
    - optional allowlist `RUSTY_PINCH_CHANNELS_TELEGRAM_ALLOW_FROM`
- WhatsApp adapter:
  - websocket bridge runtime (`ws://...`) compatible with bridge payload format from legacy stack
  - reconnect loop with bounded-run mode (`--max-messages N`) for safe acceptance checks
  - env gating:
    - `RUSTY_PINCH_CHANNELS_WHATSAPP_ENABLED`
    - `RUSTY_PINCH_CHANNELS_WHATSAPP_BRIDGE_URL`
    - optional allowlist `RUSTY_PINCH_CHANNELS_WHATSAPP_ALLOW_FROM`

## Non-Goals (Current Stage)

- No replacement of existing Go runtime in this milestone
- No deletion of hybrid migration codepaths
- No full multi-channel parity with legacy stack yet (current scope: Telegram + WhatsApp bridge)

## Promotion Criteria

Before promoting this package to mainline runtime role:

- parity tests against current behavior
- deterministic tool/message ordering checks
- KPI gate validation on Rusty Pinch execution path
- standalone package artifact can be produced and validated in CI

## Deployment Profiles

- systemd profile:
  - templates under `rusty-pinch/deploy/systemd/`
  - separate Telegram and WhatsApp worker units
- container profile:
  - Dockerfile and compose example under `rusty-pinch/deploy/container/`
  - optional WhatsApp worker via compose profile
