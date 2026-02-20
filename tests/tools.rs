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
fn tools_list_order_is_deterministic() {
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
    let app = RustyPinchApp::new(settings).expect("new app");
    let names = app
        .list_tools()
        .into_iter()
        .map(|spec| spec.name)
        .collect::<Vec<String>>();

    assert_eq!(
        names,
        vec![
            "model_info".to_string(),
            "session_tail".to_string(),
            "skill_list".to_string(),
            "skill_run".to_string(),
            "time_now".to_string()
        ]
    );
}

#[test]
fn tool_command_bypasses_provider_key_requirements() {
    let _guard = ENV_LOCK.lock().expect("lock env");
    reset_rusty_env();
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");

    fs::write(
        temp.path().join(".env"),
        format!(
            "RUSTY_PINCH_PROVIDER=openai\nRUSTY_PINCH_MODEL=gpt-4o-mini\nRUSTY_PINCH_DATA_DIR={}\n",
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
        .process_turn("tool-session", "/tool model_info")
        .expect("tool command should succeed without API key");
    assert!(response.contains("[tool:model_info]"));

    let history = app
        .session_history_json("tool-session")
        .expect("history should load");
    assert!(history.contains("/tool model_info"));
    assert!(history.contains("provider=openai"));
}

#[test]
fn tool_skill_run_surfaces_root_cause_error_details() {
    let _guard = ENV_LOCK.lock().expect("lock env");
    reset_rusty_env();
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace_dir = temp.path().join("workspace");

    fs::write(
        temp.path().join(".env"),
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\n",
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

    let err = app
        .process_turn("tool-session", "/tool skill_run unknown_skill")
        .expect_err("unknown skill should fail");
    let details = format!("{:#}", err);

    assert!(
        details.contains("unknown_skill"),
        "unexpected error: {}",
        details
    );
    assert!(
        details.contains("not found"),
        "unexpected error: {}",
        details
    );
}

#[test]
fn tool_guardrail_rejects_control_char_args() {
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

    let err = app
        .process_turn("tool-session", "/tool session_tail 5\n6")
        .expect_err("tool call with control char args must fail");
    let message = err.to_string();
    assert!(message.contains("request_id="));
    assert!(message.contains("control characters"));

    let history = app
        .session_history_json("tool-session")
        .expect("history should load");
    assert!(!history.contains("/tool session_tail 5"));
}
