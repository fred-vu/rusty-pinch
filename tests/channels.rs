use std::fs;
use std::sync::Mutex;

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
fn settings_load_channel_env_contract() {
    let _guard = ENV_LOCK.lock().expect("lock env");
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let env_file = temp.path().join(".env");
    fs::write(
        &env_file,
        "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_CHANNELS_TELEGRAM_ENABLED=true\nRUSTY_PINCH_CHANNELS_TELEGRAM_TOKEN=test-token\nRUSTY_PINCH_CHANNELS_TELEGRAM_ALLOW_FROM=12345,67890\nRUSTY_PINCH_CHANNELS_TELEGRAM_POLL_TIMEOUT_SECS=31\nRUSTY_PINCH_CHANNELS_TELEGRAM_POLL_INTERVAL_MS=800\nRUSTY_PINCH_CHANNELS_WHATSAPP_ENABLED=true\nRUSTY_PINCH_CHANNELS_WHATSAPP_BRIDGE_URL=ws://localhost:3001\nRUSTY_PINCH_CHANNELS_WHATSAPP_ALLOW_FROM=alice,bob\nRUSTY_PINCH_CHANNELS_WHATSAPP_RECONNECT_MS=4000\n",
    )
    .expect("write env");

    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let settings = Settings::load().expect("load settings");

    assert!(settings.channels.telegram.enabled);
    assert_eq!(
        settings.channels.telegram.token.as_deref(),
        Some("test-token")
    );
    assert_eq!(
        settings.channels.telegram.allow_from,
        vec!["12345", "67890"]
    );
    assert_eq!(settings.channels.telegram.poll_timeout_secs, 31);
    assert_eq!(settings.channels.telegram.poll_interval_ms, 800);

    assert!(settings.channels.whatsapp.enabled);
    assert_eq!(
        settings.channels.whatsapp.bridge_url.as_deref(),
        Some("ws://localhost:3001")
    );
    assert_eq!(settings.channels.whatsapp.allow_from, vec!["alice", "bob"]);
    assert_eq!(settings.channels.whatsapp.reconnect_ms, 4000);
}

#[test]
fn doctor_warns_on_enabled_channel_missing_credentials() {
    let _guard = ENV_LOCK.lock().expect("lock env");
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let env_file = temp.path().join(".env");
    fs::write(
        &env_file,
        "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_CHANNELS_TELEGRAM_ENABLED=true\nRUSTY_PINCH_CHANNELS_WHATSAPP_ENABLED=true\n",
    )
    .expect("write env");

    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let settings = Settings::load().expect("load settings");
    let report = settings.doctor_report();
    let warnings = report.warnings.join("\n");

    assert!(
        warnings.contains("RUSTY_PINCH_CHANNELS_TELEGRAM_TOKEN"),
        "warnings should mention missing telegram token"
    );
    assert!(
        warnings.contains("RUSTY_PINCH_CHANNELS_WHATSAPP_BRIDGE_URL"),
        "warnings should mention missing whatsapp bridge url"
    );
}
