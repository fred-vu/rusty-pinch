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
