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

## Foundation Extensions (AI System)

- `codex` (Brain):
  - CLI wrapper with account pool, rate-window counters, queue activation when remaining quota reaches threshold (default 25%).
  - Periodic/forced account health checks and queue drain primitives.
- `skills` (Hands):
  - Rhai `SkillManager` loads scripts from `${RUSTY_PINCH_WORKSPACE}/skills`.
  - Sandbox defaults: bounded script size, operation limits, safe host functions only (`log_info`, `time_now`, `http_get`, `http_post`), local/private URL blocking.
- `pulse` (Scheduler + OODA):
  - Interval-based job scheduler with default runtime heartbeat and Codex maintenance jobs.
  - Supports custom external HTTP health-check jobs (`pulse job add-http-healthcheck`).
  - Job lifecycle controls via CLI (`pulse job enable|disable|remove`).
  - OODA cycle evaluator (observe/orient/decide/act) with risk classification.
  - Human-in-the-loop approvals for risky actions (tokenized pending approvals).
  - Auto-allow keyword policy via `RUSTY_PINCH_PULSE_AUTO_ALLOW_ACTIONS`.
  - Goal tracker for objective state.
  - Persistent state under `${RUSTY_PINCH_WORKSPACE}/pulse/state.json` (jobs, approvals, goals) with restart restore.
- `evolution` (Self-evolution + update scaffolding):
  - Codex-generated skill pipeline: generate -> stage -> dry-run validate -> promote.
  - Blue/Green binary update planning, staging manifest generation, apply + health-check + rollback executor.
  - Optional stage-time artifact checksum gate for release provenance (`--artifact-sha256`, `--artifact-sha256-sums-file`, `RUSTY_PINCH_EVOLUTION_REQUIRE_STAGE_ARTIFACT_SHA256`).
  - Optional anti-rollback version gate (`--current-version`, `--artifact-version`, `RUSTY_PINCH_EVOLUTION_REQUIRE_NON_ROLLBACK_VERSION`) to prevent downgrade applies.
  - Optional trusted checksum-manifest hash pin for stage checksum manifests (`RUSTY_PINCH_EVOLUTION_TRUSTED_SHA256SUMS_SHA256`).
  - Optional detached Ed25519 checksum-manifest signature verification (`--artifact-sha256-sums-signature-file`, `RUSTY_PINCH_EVOLUTION_TRUSTED_SHA256SUMS_ED25519_PUBLIC_KEY`, `RUSTY_PINCH_EVOLUTION_REQUIRE_SHA256SUMS_SIGNATURE`).
  - Optional apply-time signed checksum-manifest provenance enforcement (`RUSTY_PINCH_EVOLUTION_REQUIRE_SIGNED_CHECKSUM_MANIFEST_PROVENANCE`) with checksum/signature re-verification.
  - Optional apply-time provenance enforcement requiring checksum-verified stage manifests (`RUSTY_PINCH_EVOLUTION_REQUIRE_VERIFIED_STAGE_ARTIFACT_SHA256`).
  - Staged binary SHA-256 is captured at stage time and verified before slot switch.
  - Optional staged manifest HMAC signature verification with key rotation support (`RUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEY`, `RUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEY_ID`, `RUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEYS`, `RUSTY_PINCH_EVOLUTION_REQUIRE_MANIFEST_SIGNATURE`); signature payload covers artifact provenance fields for tamper evidence.
  - Optional active-slot marker signing policy (`RUSTY_PINCH_EVOLUTION_ACTIVE_SLOT_SIGNING_KEY`, `RUSTY_PINCH_EVOLUTION_ACTIVE_SLOT_SIGNING_KEY_ID`, `RUSTY_PINCH_EVOLUTION_REQUIRE_SIGNED_ACTIVE_SLOT`) with marker-sidecar integrity verification.
  - Optional staged-manifest freshness policy (`RUSTY_PINCH_EVOLUTION_MAX_STAGED_MANIFEST_AGE_SECS`) blocks apply when staged manifests exceed max age.
  - Optional apply-failure circuit breaker (`RUSTY_PINCH_EVOLUTION_MAX_CONSECUTIVE_APPLY_FAILURES`) blocks further apply attempts after repeated failures until operator reset (`evolution failure-circuit-status`, `evolution failure-circuit-reset --confirm`).
  - Stage/apply outcomes are written to append-only rollout audit log `${RUSTY_PINCH_WORKSPACE}/updates/evolution-audit.jsonl` with hash chaining (`prev_hash`, `hash`) for forensic continuity, including apply recovery context fields (resume count/notes/observed slot).
  - Forensics verifier command `evolution audit-verify` validates the full audit hash chain offline.
  - Stage/apply mutations are serialized via an exclusive lock file `${RUSTY_PINCH_WORKSPACE}/updates/evolution.lock`.
  - Lock diagnostics/operations are exposed via `evolution lock-status` and `evolution force-unlock --confirm`.
  - Apply recovery diagnostics are exposed via `evolution recovery-status` (manifest checkpoint + slot drift + manifest age/expiry recommendation).
  - Active-slot integrity diagnostics are exposed via `evolution active-slot-status`.
  - Stale lock policy is configurable (`RUSTY_PINCH_EVOLUTION_LOCK_STALE_AFTER_SECS`, `RUSTY_PINCH_EVOLUTION_AUTO_RECOVER_STALE_LOCK`).
  - Apply flow enforces health-check timeout with forced process kill before rollback.
  - Apply flow uses resumable checkpoints (`staged -> applying -> healthcheck_pending -> activated|rolled_back`) so interrupted runs can be safely resumed; terminal states are idempotent on re-run.
  - Apply flow is guarded by explicit operator confirmation policy (`RUSTY_PINCH_EVOLUTION_REQUIRE_APPLY_CONFIRM`, CLI `--confirm`).

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
- Telemetry snapshot also captures subsystem status:
  - `codex`: account health + queue depth/threshold
  - `pulse`: jobs/approvals/goals + last tick execution counts
  - `evolution`: latest skill promotion/apply outcome metadata + active-slot integrity/signature state + apply-failure circuit state
- `monitor` command reads Linux `/proc` + telemetry snapshot to render live TUI status:
  - process (`cpu%`, `rss`, `vms`, read/write bytes, fd count)
  - host (`loadavg`, memory, swap)
  - storage (`data_dir`, `workspace`, filesystem usage)
  - evolution warnings (`evolution_alert`) when active-slot signature/policy checks fail or apply-failure circuit is open

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
  - Raspberry Pi profile consumes prebuilt GHCR image with Watchtower auto-update
  - optional WhatsApp worker via compose profile

## CI/CD Automation

- `.github/workflows/ci.yml`:
  - gate checks for `fmt`, build, and tests on `main` + PR + manual dispatch.
- `.github/workflows/docker-publish.yml`:
  - buildx pipeline publishes `linux/arm64` runtime image to GHCR (`latest` + tag versions).
- `.github/workflows/release.yml`:
  - tag-triggered (`v*`) release pipeline with Linux/macOS/Windows build matrix.
  - uploads release archives and a consolidated `SHA256SUMS.txt`.
  - publishes GitHub Release assets automatically for tagged releases.
