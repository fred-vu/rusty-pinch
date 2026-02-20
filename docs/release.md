# Rusty Pinch Release Guide

## Local packaging

Build standalone package from repo root:

```bash
./scripts/release/build_rusty_pinch_package.sh
```

Or via Make:

```bash
make rusty-pinch-package
```

Verify package integrity and runtime smoke:

```bash
make rusty-pinch-verify-package
# or
./scripts/release/verify_rusty_pinch_package.sh dist/rusty-pinch
```

Validate deployment profiles:

```bash
make rusty-pinch-deploy-check
```

Output (default `dist/rusty-pinch/`):

- `rusty-pinch-<version>-<os>-<arch>/` (expanded package)
- `rusty-pinch-<version>-<os>-<arch>.tar.gz`
- `rusty-pinch-<version>-<os>-<arch>.tar.gz.sha256`

## Package contents

- `rusty-pinch` binary
- `README.md`
- `LICENSE`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `.env.example`
- `docs/`
- `assets/`
- `deploy/`
- `VERSION.txt`

## Source policy

- Repository license is personal-use source-available (see `LICENSE`).
- This project is not OSI-open-source.
- Public publishing checklist: `docs/open-source-publish-checklist.md`

## Raspberry Pi deployment artifact

Container package includes Pi-focused compose assets:

- `deploy/container/docker-compose.rpi.yml`
- `deploy/container/rusty-pinch.rpi.env.example`

Suggested first-run on Pi host:

```bash
cd deploy/container
cp rusty-pinch.rpi.env.example rusty-pinch.rpi.env
mkdir -p ./data ./workspace ./skills ./codex-home
docker compose -f docker-compose.rpi.yml pull
docker compose -f docker-compose.rpi.yml up -d rusty-pinch-telegram watchtower
```

## CI release flow

- `ci.yml` (push to `main`, pull request, or manual dispatch):
  - `cargo fmt --check`
  - `cargo build --locked`
  - `cargo test --locked`
- `docker-publish.yml` (push to `main`, tag push `v*`, or manual dispatch):
  - buildx pipeline publishes `linux/arm64` image to GHCR
  - `latest` tag on default branch + version tags on `v*`
- `release.yml` (tag push `v*` or manual dispatch):
  - release gate (`fmt` + tests on Linux)
  - matrix release builds:
    - `x86_64-unknown-linux-gnu`
    - `x86_64-apple-darwin`
    - `x86_64-pc-windows-msvc`
  - archive artifact upload (`.tar.gz` on Unix, `.zip` on Windows)
  - consolidated `SHA256SUMS.txt` generation
  - automatic GitHub Release publication with all artifacts when triggered by tag push

For self-update staging, `rusty-pinch evolution stage-update` can resolve artifact checksums directly from `SHA256SUMS.txt` via `--artifact-sha256-sums-file` (and optional `--artifact-sha256-entry`). Trust can be pinned by checksum (`RUSTY_PINCH_EVOLUTION_TRUSTED_SHA256SUMS_SHA256`) and/or detached Ed25519 signature verification (`--artifact-sha256-sums-signature-file`, `RUSTY_PINCH_EVOLUTION_TRUSTED_SHA256SUMS_ED25519_PUBLIC_KEY`, optional policy `RUSTY_PINCH_EVOLUTION_REQUIRE_SHA256SUMS_SIGNATURE`). Optional apply-time signed provenance policy `RUSTY_PINCH_EVOLUTION_REQUIRE_SIGNED_CHECKSUM_MANIFEST_PROVENANCE` re-validates checksum-manifest checksum/signature at apply. Optional non-rollback policy `RUSTY_PINCH_EVOLUTION_REQUIRE_NON_ROLLBACK_VERSION` enforces `--current-version` and `--artifact-version` and blocks downgrade updates. Optional active-slot signing policy (`RUSTY_PINCH_EVOLUTION_ACTIVE_SLOT_SIGNING_KEY`, `RUSTY_PINCH_EVOLUTION_ACTIVE_SLOT_SIGNING_KEY_ID`, `RUSTY_PINCH_EVOLUTION_REQUIRE_SIGNED_ACTIVE_SLOT`) verifies active-slot marker integrity during stage/apply. Optional staged-manifest freshness policy (`RUSTY_PINCH_EVOLUTION_MAX_STAGED_MANIFEST_AGE_SECS`) blocks apply when staged manifests are older than the configured threshold. Optional apply-failure circuit breaker policy (`RUSTY_PINCH_EVOLUTION_MAX_CONSECUTIVE_APPLY_FAILURES`) blocks new apply attempts after repeated rollout failures until operator reset (`evolution failure-circuit-status`, `evolution failure-circuit-reset --confirm`). Rollout mutations are serialized through `${RUSTY_PINCH_WORKSPACE}/updates/evolution.lock`, and apply resumes safely from checkpointed states (`applying`, `healthcheck_pending`) after interruptions. Stale lock handling is policy-driven (`RUSTY_PINCH_EVOLUTION_LOCK_STALE_AFTER_SECS`, `RUSTY_PINCH_EVOLUTION_AUTO_RECOVER_STALE_LOCK`) with manual controls available via `evolution lock-status` and `evolution force-unlock --confirm`; partial apply diagnostics are available via `evolution recovery-status` (including manifest age/expiry details), and active-slot diagnostics via `evolution active-slot-status`.

## Release checklist

1. `cargo test --manifest-path rusty-pinch/Cargo.toml` passes.
2. Smoke run with target provider succeeds.
3. `cargo run -- stats` shows valid telemetry snapshot path and counters.
4. Package archive checksum validates.
5. Package verification script passes (checksum + extracted contents + packaged binary smoke).
6. Recommended: run full local readiness pipeline once before tagging.

```bash
make rusty-pinch-readiness
```
