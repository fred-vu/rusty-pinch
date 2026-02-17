# Rusty Pinch Public Documentation Manifest

Use this manifest for first public release and future documentation reviews.

## Required public docs

- `README.md`
- `LICENSE`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `docs/architecture.md`
- `docs/testing.md`
- `docs/runbook.md`
- `docs/runbook-raspberry-pi.md`
- `docs/release.md`
- `docs/production-healthcheck.md`
- `docs/open-source-publish-checklist.md`

## Optional public docs

- `docs/promotion.md` (roadmap/promotion status context)

## Must NOT publish

- `.env`
- `data/`
- `workspace/`
- `target/`
- any runtime env override file with real values

## Review rule

Before every public push:

1. Compare docs in repository with this manifest.
2. Remove or redact any internal-only notes.
3. Run `docs/open-source-publish-checklist.md`.
