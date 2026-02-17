# Security Policy

## Supported scope

This policy applies to the `rusty-pinch/` standalone project and its deployment profiles.

## Report a vulnerability

Please do not open a public issue for security vulnerabilities.

Use private contact with:

- affected component/file
- impact summary
- reproduction steps
- proposed mitigation (if available)

## Secret handling rules

- Never commit `.env`, runtime state, or production logs containing sensitive data.
- Never commit real API keys, bot tokens, or bridge credentials.
- Use templates:
  - `.env.example`
  - `deploy/container/*.env.example`
  - `deploy/systemd/rusty-pinch.env.example`

## Hardening checklist

- Restrict Telegram/WhatsApp allowlists where possible.
- Use dedicated provider keys per environment.
- Rotate compromised keys immediately.
- Keep Docker host and base images patched.

## Operational checks

- Monitor logs for repeated `channel_*_error`, auth failures, and unexpected restarts.
- Verify telemetry and session directories have least-privilege access.
- Use `docs/production-healthcheck.md` and `docs/runbook-raspberry-pi.md` for operations.
