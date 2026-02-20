#!/bin/sh
set -eu

CODEX_STATUS_FILE="/tmp/rusty-pinch-codex-login-status.txt"

log() {
  printf '%s %s\n' "[rusty-pinch-entrypoint]" "$*"
}

lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

is_true() {
  case "$(lower "${1:-}")" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

codex_status_capture() {
  codex login status >"$CODEX_STATUS_FILE" 2>&1
}

ensure_codex_home() {
  if [ -z "${CODEX_HOME:-}" ]; then
    CODEX_HOME="${RUSTY_PINCH_CODEX_HOME:-/var/lib/rusty-pinch/codex-home}"
    export CODEX_HOME
  fi

  mkdir -p "$CODEX_HOME"
  chmod 700 "$CODEX_HOME" 2>/dev/null || true
}

restore_chatgpt_auth_material() {
  if [ -n "${RUSTY_PINCH_CODEX_CHATGPT_AUTH_FILE:-}" ] && [ -f "${RUSTY_PINCH_CODEX_CHATGPT_AUTH_FILE}" ]; then
    cp "${RUSTY_PINCH_CODEX_CHATGPT_AUTH_FILE}" "$CODEX_HOME/auth.json"
    chmod 600 "$CODEX_HOME/auth.json" 2>/dev/null || true
    log "codex auth restored from RUSTY_PINCH_CODEX_CHATGPT_AUTH_FILE"
    return 0
  fi

  if [ -n "${RUSTY_PINCH_CODEX_CHATGPT_AUTH_JSON_B64:-}" ]; then
    if printf '%s' "$RUSTY_PINCH_CODEX_CHATGPT_AUTH_JSON_B64" | base64 -d >"$CODEX_HOME/auth.json" 2>/dev/null; then
      chmod 600 "$CODEX_HOME/auth.json" 2>/dev/null || true
      log "codex auth restored from RUSTY_PINCH_CODEX_CHATGPT_AUTH_JSON_B64"
      return 0
    fi
    log "failed to decode RUSTY_PINCH_CODEX_CHATGPT_AUTH_JSON_B64"
  fi

  return 1
}

run_chatgpt_login() {
  restore_chatgpt_auth_material || true
  if codex_status_capture; then
    return 0
  fi

  if ! is_true "${RUSTY_PINCH_CODEX_CHATGPT_DEVICE_AUTH:-true}"; then
    log "chatgpt auto-login requires device auth; set RUSTY_PINCH_CODEX_CHATGPT_DEVICE_AUTH=true or provide auth material"
    return 1
  fi

  login_timeout_secs="${RUSTY_PINCH_CODEX_LOGIN_TIMEOUT_SECS:-300}"
  log "starting codex device-auth login (timeout ${login_timeout_secs}s)"
  if timeout "$login_timeout_secs" codex login --device-auth; then
    log "codex device-auth command completed"
  else
    log "codex device-auth did not complete before timeout or returned failure"
  fi

  codex_status_capture
}

run_api_key_login() {
  api_key_env="${RUSTY_PINCH_CODEX_AUTO_LOGIN_API_KEY_ENV:-RUSTY_PINCH_OPENAI_API_KEY}"
  api_key_value="$(printenv "$api_key_env" 2>/dev/null || true)"
  if [ -z "$api_key_value" ]; then
    log "api-key auto-login skipped: env '$api_key_env' is empty"
    return 1
  fi

  if printf '%s' "$api_key_value" | codex login --with-api-key; then
    log "codex login completed via api key env '$api_key_env'"
    return 0
  fi

  log "codex api-key login failed for env '$api_key_env'"
  return 1
}

bootstrap_codex_login() {
  if ! is_true "${RUSTY_PINCH_CODEX_ENABLED:-false}"; then
    return 0
  fi

  if ! command -v codex >/dev/null 2>&1; then
    log "codex integration enabled but codex CLI not found; use GHCR prebuilt image or rebuild with RUSTY_PINCH_INSTALL_CODEX_CLI=true"
    return 0
  fi

  ensure_codex_home

  if codex_status_capture; then
    log "codex auth ready: $(cat "$CODEX_STATUS_FILE")"
    return 0
  fi

  login_mode="$(lower "${RUSTY_PINCH_CODEX_AUTO_LOGIN_MODE:-chatgpt}")"
  if ! is_true "${RUSTY_PINCH_CODEX_AUTO_LOGIN:-true}"; then
    log "codex auth not ready and auto-login disabled; status: $(cat "$CODEX_STATUS_FILE")"
    return 0
  fi

  case "$login_mode" in
    chatgpt)
      run_chatgpt_login || true
      ;;
    api-key|api_key|apikey)
      run_api_key_login || true
      ;;
    off|none|disabled)
      log "codex auto-login mode is '$login_mode'; skipping login bootstrap"
      ;;
    *)
      log "unknown codex auto-login mode '$login_mode'; expected chatgpt|api-key|off"
      ;;
  esac

  if codex_status_capture; then
    log "codex auth ready after bootstrap: $(cat "$CODEX_STATUS_FILE")"
  else
    log "codex auth still not ready after bootstrap: $(cat "$CODEX_STATUS_FILE")"
  fi
}

bootstrap_codex_login

exec rusty-pinch "$@"
