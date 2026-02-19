use std::fs;
use std::sync::Mutex;

use rusty_pinch::app::RustyPinchApp;
use rusty_pinch::config::Settings;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn reset_rusty_env() {
    for key in [
        "RUSTY_PINCH_PROVIDER",
        "RUSTY_PINCH_MODEL",
        "RUSTY_PINCH_DATA_DIR",
        "RUSTY_PINCH_WORKSPACE",
        "RUSTY_PINCH_TELEMETRY_FILE",
        "RUSTY_PINCH_API_KEY",
        "RUSTY_PINCH_API_BASE",
        "RUSTY_PINCH_OPENAI_API_KEY",
        "RUSTY_PINCH_OPENROUTER_API_KEY",
        "RUSTY_PINCH_GROQ_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "GROQ_API_KEY",
        "RUSTY_PINCH_CHANNELS_TELEGRAM_ENABLED",
        "RUSTY_PINCH_CHANNELS_TELEGRAM_TOKEN",
        "RUSTY_PINCH_CHANNELS_TELEGRAM_ALLOW_FROM",
        "RUSTY_PINCH_CHANNELS_TELEGRAM_POLL_TIMEOUT_SECS",
        "RUSTY_PINCH_CHANNELS_TELEGRAM_POLL_INTERVAL_MS",
        "RUSTY_PINCH_CHANNELS_TELEGRAM_REQUEST_TIMEOUT_SECS",
        "RUSTY_PINCH_CHANNELS_WHATSAPP_ENABLED",
        "RUSTY_PINCH_CHANNELS_WHATSAPP_BRIDGE_URL",
        "RUSTY_PINCH_CHANNELS_WHATSAPP_ALLOW_FROM",
        "RUSTY_PINCH_CHANNELS_WHATSAPP_RECONNECT_MS",
        "RUSTY_PINCH_CODEX_ENABLED",
        "RUSTY_PINCH_CODEX_CLI_BIN",
        "RUSTY_PINCH_CODEX_CLI_ARGS",
        "RUSTY_PINCH_CODEX_PROMPT_FLAG",
        "RUSTY_PINCH_CODEX_MODEL_FLAG",
        "RUSTY_PINCH_CODEX_TIMEOUT_SECS",
        "RUSTY_PINCH_CODEX_QUEUE_CAPACITY",
        "RUSTY_PINCH_CODEX_RATE_LIMIT_THRESHOLD_PERCENT",
        "RUSTY_PINCH_CODEX_RATE_WINDOW_SECS",
        "RUSTY_PINCH_CODEX_HEALTHCHECK_INTERVAL_SECS",
        "RUSTY_PINCH_CODEX_HEALTHCHECK_ARGS",
        "RUSTY_PINCH_CODEX_MODEL",
        "RUSTY_PINCH_CODEX_ACCOUNTS",
        "RUSTY_PINCH_CODEX_ACCOUNT_MAX_REQUESTS",
        "RUSTY_PINCH_CODEX_ACCOUNT_API_KEY_ENV",
        "RUSTY_PINCH_CODEX_ACCOUNT_MODEL",
        "RUSTY_PINCH_PULSE_AUTO_ALLOW_ACTIONS",
        "RUSTY_PINCH_EVOLUTION_REQUIRE_APPLY_CONFIRM",
        "RUSTY_PINCH_EVOLUTION_REQUIRE_STAGE_ARTIFACT_SHA256",
        "RUSTY_PINCH_EVOLUTION_REQUIRE_VERIFIED_STAGE_ARTIFACT_SHA256",
        "RUSTY_PINCH_EVOLUTION_REQUIRE_SIGNED_CHECKSUM_MANIFEST_PROVENANCE",
        "RUSTY_PINCH_EVOLUTION_REQUIRE_NON_ROLLBACK_VERSION",
        "RUSTY_PINCH_EVOLUTION_TRUSTED_SHA256SUMS_SHA256",
        "RUSTY_PINCH_EVOLUTION_TRUSTED_SHA256SUMS_ED25519_PUBLIC_KEY",
        "RUSTY_PINCH_EVOLUTION_REQUIRE_SHA256SUMS_SIGNATURE",
        "RUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEY_ID",
        "RUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEY",
        "RUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEYS",
        "RUSTY_PINCH_EVOLUTION_REQUIRE_MANIFEST_SIGNATURE",
        "RUSTY_PINCH_EVOLUTION_ACTIVE_SLOT_SIGNING_KEY_ID",
        "RUSTY_PINCH_EVOLUTION_ACTIVE_SLOT_SIGNING_KEY",
        "RUSTY_PINCH_EVOLUTION_REQUIRE_SIGNED_ACTIVE_SLOT",
        "RUSTY_PINCH_EVOLUTION_MAX_STAGED_MANIFEST_AGE_SECS",
        "RUSTY_PINCH_EVOLUTION_MAX_CONSECUTIVE_APPLY_FAILURES",
        "RUSTY_PINCH_EVOLUTION_LOCK_STALE_AFTER_SECS",
        "RUSTY_PINCH_EVOLUTION_AUTO_RECOVER_STALE_LOCK",
        "RUSTY_PINCH_ENV_FILE",
    ] {
        std::env::remove_var(key);
    }
}

#[test]
fn app_process_turn_persists_history() {
    let _guard = ENV_LOCK.lock().expect("lock env");
    reset_rusty_env();
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");

    fs::write(
        temp.path().join(".env"),
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\n",
            data_dir.display()
        ),
    )
    .expect("write env");

    std::env::set_var(
        "RUSTY_PINCH_ENV_FILE",
        temp.path().join(".env").display().to_string(),
    );

    let settings = Settings::load().expect("load settings");
    let mut app = RustyPinchApp::new(settings).expect("new app");

    let response = app
        .process_turn("test-session", "hello")
        .expect("process turn");

    assert!(response.contains("Rusty Pinch"));

    let history = app
        .session_history_json("test-session")
        .expect("session history");
    assert!(history.contains("hello"));
}

#[test]
fn settings_default_provider_is_codex() {
    let _guard = ENV_LOCK.lock().expect("lock env");
    reset_rusty_env();
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace_dir = temp.path().join("workspace");

    fs::write(
        temp.path().join(".env"),
        format!(
            "RUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\n",
            data_dir.display(),
            workspace_dir.display()
        ),
    )
    .expect("write env");

    std::env::set_var(
        "RUSTY_PINCH_ENV_FILE",
        temp.path().join(".env").display().to_string(),
    );

    let settings = Settings::load().expect("load settings");
    assert_eq!(settings.provider, "codex");
    assert_eq!(settings.model, "gpt-5-codex");
    assert!(settings.codex.enabled);
}

#[test]
fn app_process_turn_supports_codex_provider_path() {
    let _guard = ENV_LOCK.lock().expect("lock env");
    reset_rusty_env();
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace_dir = temp.path().join("workspace");

    fs::write(
        temp.path().join(".env"),
        format!(
            "RUSTY_PINCH_PROVIDER=codex\nRUSTY_PINCH_MODEL=gpt-5-codex\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\nRUSTY_PINCH_CODEX_ENABLED=true\nRUSTY_PINCH_CODEX_CLI_BIN=echo\nRUSTY_PINCH_CODEX_CLI_ARGS=\"exec --skip-git-repo-check\"\nRUSTY_PINCH_CODEX_PROMPT_FLAG=\nRUSTY_PINCH_CODEX_MODEL_FLAG=--model\nRUSTY_PINCH_CODEX_MODEL=gpt-5-codex\nRUSTY_PINCH_CODEX_HEALTHCHECK_ARGS=--version\n",
            data_dir.display(),
            workspace_dir.display()
        ),
    )
    .expect("write env");

    std::env::set_var(
        "RUSTY_PINCH_ENV_FILE",
        temp.path().join(".env").display().to_string(),
    );

    let settings = Settings::load().expect("load settings");
    let mut app = RustyPinchApp::new(settings).expect("new app");

    let response = app
        .process_turn("codex-provider-session", "hello-codex-route")
        .expect("process turn");

    assert!(response.contains("hello-codex-route"));

    let history = app
        .session_history_json("codex-provider-session")
        .expect("session history");
    assert!(history.contains("hello-codex-route"));
}
