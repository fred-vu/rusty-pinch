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
