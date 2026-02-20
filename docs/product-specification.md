# Rusty Pinch Product Specification

## 1. Purpose

This document defines the product baseline for `rusty-pinch` so external specialists can advise upgrades based on one core Git repository.

Intended audience:

- product/architecture reviewers
- systems and reliability specialists
- contributors preparing upgrade proposals

Canonical source:

- Core repository: `https://github.com/fred-vu/rusty-pinch.git`
- Primary branch: `main`
- Baseline snapshot for this specification: `0e7f95066ef3baf3eb7a8730e53f526f05203b66`

## 2. Product Summary

Rusty Pinch is a standalone Rust runtime for assistant workflows with:

- env-first configuration
- provider modes: `codex` (default), OpenAI-compatible (`openrouter`, `openai`, `groq`, `compatible`), and `local` mode
- append-only session persistence (`jsonl`)
- deterministic local tool execution (`/tool ...`)
- channel workers (Telegram long polling, WhatsApp bridge websocket)
- operational observability (`stats`, structured `event=turn` logs, `monitor` TUI)

The product is distributed under a personal-use source-available license (not OSI open source).

## 3. Product Goals

1. Deliver a reliable single-binary runtime for personal assistant operations.
2. Operate on low-cost ARM hosts (Raspberry Pi 4) with Docker Compose or systemd.
3. Keep runtime behavior deterministic and diagnosable.
4. Maintain clear upgrade path from current stable core without breaking operator workflows.

## 4. Current Scope and Non-Goals

In scope now:

- single-node deployment
- Telegram production usage
- WhatsApp bridge in community validation phase
- package build/verify/readiness pipeline in CI and local make targets

Out of scope now:

- multi-node/distributed scaling
- direct first-party WhatsApp vendor adapter parity
- replacement of legacy Go/hybrid runtime in one step

## 5. Users and Primary Use Cases

Primary users:

- operator running daily assistant flows on Pi or Linux host
- contributor extending runtime behavior safely

Primary use cases:

1. Receive inbound Telegram message and produce response with provider/tool path.
2. Persist conversation and telemetry across process restarts.
3. Inspect runtime health via logs, `doctor`, `stats`, and `monitor`.
4. Package and deploy reproducibly to target hosts.

## 6. Functional Requirements

FR-01 Configuration and startup

- Load `.env` (or `RUSTY_PINCH_ENV_FILE`) plus process env.
- `doctor` must validate provider, API base, key presence, channels, and paths.

FR-02 Session persistence

- Persist all turns append-only at `${RUSTY_PINCH_DATA_DIR}/sessions/<session>.jsonl`.
- Preserve message order and timestamps.

FR-03 Provider runtime

- Support `codex` provider runtime (default) and OpenAI-compatible chat completion APIs with retry/backoff policy.
- Emit one structured `event=turn` record per request with `request_id`, status, latency, and attempts.

FR-04 Deterministic local tools

- Parse only exact `/tool <name> [args]`.
- Enforce name and argument safety guardrails.
- Keep stable tool listing and execution behavior.

FR-05 Channels

- Telegram worker must support long polling, allowlist checks, and graceful shutdown.
- WhatsApp worker must support websocket bridge mode with reconnect and bounded run.

FR-06 Operations and monitoring

- `stats` must return persisted telemetry and latest turn status.
- `monitor` must provide process/host/storage view (`--once` and live mode).
- Compose deployment must support monitor commands through `docker-compose exec`.

## 7. Non-Functional Requirements

NFR-01 Reliability

- No sustained crash/restart loop in worker containers.
- Controlled behavior on transient upstream failures (retry, structured error output).

NFR-02 Observability

- Logs must be machine-readable JSON.
- Correlation via `request_id` must be present for every turn.

NFR-03 Security

- API keys must come from env/runtime files, never committed configs.
- Documentation must enforce secret hygiene and publish checklist.

NFR-04 Deployability

- Support Raspberry Pi 4 (`aarch64`) and general Linux hosts.
- Maintain compatibility with legacy `docker-compose` command style in docs.

NFR-05 Maintainability

- CI/readiness gates must stay reproducible from one repo.
- Architecture, testing, runbook, release, and health docs must stay synchronized.

## 8. Baseline Validation Commands

From `rusty-pinch/`:

```bash
cargo fmt --all
cargo check
cargo test
cargo run -- doctor
cargo run -- stats
```

From repository root:

```bash
make rusty-pinch-readiness
make rusty-pinch-deploy-check
```

Raspberry Pi compose operations:

```bash
cd rusty-pinch/deploy/container
docker compose -f docker-compose.rpi.yml pull
docker compose -f docker-compose.rpi.yml up -d rusty-pinch-telegram watchtower
docker compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch monitor --once
```

## 9. Known Risks and Gaps

1. WhatsApp bridge is implemented but community-validated, not fully production-validated.
2. Provider auth can fail due to ambiguous env key source; docs now recommend explicit provider key usage.
3. Compose feature usage is constrained by legacy environments; advanced compose-only features are avoided.
4. Product remains single-node with no built-in HA strategy.

## 10. Specialist Advisory Scope

Specialist review is requested for:

1. Runtime hardening priorities for single-node to small-scale growth.
2. Provider resilience design (error classes, backoff policy, circuit-breaker policy).
3. Channel worker reliability patterns (deduping, backpressure, reconnect strategies).
4. Secure key management model beyond `.env` while preserving simple operator UX.
5. Observability upgrades (structured metrics export, alert-ready signals).
6. Upgrade roadmap from current core to stronger production profile without destabilizing operator flow.

Expected advisor deliverables:

- prioritized upgrade backlog (P0/P1/P2)
- architecture delta proposal (minimal-risk path)
- risk matrix with rollback strategy
- measurable acceptance criteria for each proposed upgrade

## 11. Immediate Upgrade Backlog Candidates

1. Add provider credential source diagnostics in `doctor` (without secret leakage).
2. Add optional health endpoint/metric export for external monitoring.
3. Add explicit runbook flow for provider key rotation and hot reload/recreate.
4. Define WhatsApp bridge validation checklist with pass/fail evidence format.
5. Add CI check to keep documentation command style and deployment steps consistent.
