# Rusty Pinch Promotion Plan

## Objective

Promote `rusty-pinch/` from isolated package track to an approved independent product path without disrupting the existing Go/hybrid runtime.

## Current status (2026-02-17)

- Telegram channel is operator-validated in a real run.
- WhatsApp bridge path is implemented and intentionally opened for community testing.
- Package build/test/smoke flows are automated and CI-backed.

## Hard gates before promotion

1. Build and test gates pass:

```bash
make rusty-pinch-fmt
make rusty-pinch-check
make rusty-pinch-test
```

2. Standalone smoke and package verification pass:

```bash
make rusty-pinch-smoke
make rusty-pinch-package
make rusty-pinch-verify-package
make rusty-pinch-deploy-check
```

3. Operator runbook validation is complete:
- `doctor` status is healthy for target provider.
- telemetry and session files persist correctly.
- channel startup/stop logs are observable.

## Soft gates during community phase

- WhatsApp bridge reports from community runs are collected.
- Any bridge payload incompatibility is documented in release notes.
- No critical regressions in telemetry, session persistence, or tool loop.

## Rollout sequence

1. Keep Telegram enabled for production operators.
2. Keep WhatsApp in bridge/community mode until evidence is sufficient.
3. Cut release artifacts with checksum and package verification.
4. Run a short canary rollout (single environment) before broader adoption.

## Promotion exit criteria

- All hard gates pass on `main` CI.
- At least one successful community WhatsApp bridge run is documented.
- Release package is reproducible and verified by `make rusty-pinch-readiness`.
