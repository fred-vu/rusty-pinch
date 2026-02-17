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
mkdir -p ./state/data ./state/workspace
docker-compose -f docker-compose.rpi.yml up -d rusty-pinch-telegram
```

## CI release flow

- PR/Main workflows run:
  - format/check/test
  - local provider smoke run
  - package build + artifact upload
- Manual release workflow (`Create Tag and Release`) now also:
  - builds Rusty Pinch package
  - uploads `.tar.gz` + `.sha256` to the GitHub release tag

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
