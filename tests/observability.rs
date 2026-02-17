use std::fs;
use std::sync::Mutex;

use serde_json::Value;

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

fn new_app(provider: &str) -> (RustyPinchApp, tempfile::TempDir) {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");

    fs::write(
        temp.path().join(".env"),
        format!(
            "RUSTY_PINCH_PROVIDER={}\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\n",
            provider,
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
    (app, temp)
}

#[test]
fn stats_include_last_tool_turn_record() {
    let _guard = ENV_LOCK.lock().expect("lock env");
    reset_rusty_env();
    let (mut app, _temp) = new_app("local");

    app.process_turn("obs-tool", "/tool model_info")
        .expect("tool turn should succeed");

    let stats = app.stats_json().expect("stats");
    let data: Value = serde_json::from_str(&stats).expect("valid stats json");
    let last = data
        .get("last_turn")
        .expect("last_turn should exist")
        .as_object()
        .expect("last_turn should be object");

    assert_eq!(last.get("path").and_then(Value::as_str), Some("tool"));
    assert_eq!(last.get("status").and_then(Value::as_str), Some("ok"));
    assert_eq!(
        last.get("tool_name").and_then(Value::as_str),
        Some("model_info")
    );
    assert!(last
        .get("request_id")
        .and_then(Value::as_str)
        .is_some_and(|id| id.starts_with("rp-")));
    assert!(last.get("attempts").is_some_and(Value::is_null));
    assert!(last.get("latency_ms").is_some_and(Value::is_null));
}

#[test]
fn stats_include_provider_attempt_and_latency() {
    let _guard = ENV_LOCK.lock().expect("lock env");
    reset_rusty_env();
    let (mut app, _temp) = new_app("local");

    app.process_turn("obs-provider", "hello observability")
        .expect("provider turn should succeed");

    let stats = app.stats_json().expect("stats");
    let data: Value = serde_json::from_str(&stats).expect("valid stats json");
    let last = data
        .get("last_turn")
        .expect("last_turn should exist")
        .as_object()
        .expect("last_turn should be object");

    assert_eq!(last.get("path").and_then(Value::as_str), Some("provider"));
    assert_eq!(last.get("status").and_then(Value::as_str), Some("ok"));
    assert_eq!(last.get("attempts").and_then(Value::as_u64), Some(0));
    assert!(last.get("latency_ms").and_then(Value::as_u64).is_some());
}

#[test]
fn telemetry_persists_across_app_instances() {
    let _guard = ENV_LOCK.lock().expect("lock env");
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let telemetry_file = temp.path().join("telemetry").join("latest.json");
    let env_file = temp.path().join(".env");

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_TELEMETRY_FILE={}\n",
            data_dir.display(),
            telemetry_file.display()
        ),
    )
    .expect("write env");

    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    {
        let settings = Settings::load().expect("load settings");
        let mut app = RustyPinchApp::new(settings).expect("new app");
        app.process_turn("persist", "one turn")
            .expect("turn should succeed");
    }

    let settings = Settings::load().expect("load settings again");
    let app = RustyPinchApp::new(settings).expect("new app again");
    let stats = app.stats_json().expect("stats after restart");
    let data: Value = serde_json::from_str(&stats).expect("valid stats json");

    let telemetry = data
        .get("telemetry")
        .expect("telemetry should exist")
        .as_object()
        .expect("telemetry should be object");
    assert_eq!(
        telemetry.get("total_turns").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(telemetry.get("ok_turns").and_then(Value::as_u64), Some(1));

    let last = data
        .get("last_turn")
        .expect("last_turn should exist")
        .as_object()
        .expect("last_turn should be object");
    assert_eq!(last.get("path").and_then(Value::as_str), Some("provider"));
}
