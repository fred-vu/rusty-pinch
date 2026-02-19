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
fn pulse_goals_and_pending_approvals_persist_across_restarts() {
    let _guard = ENV_LOCK.lock().expect("lock env");
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\nRUSTY_PINCH_PULSE_AUTO_ALLOW_ACTIONS=manual_only\n",
            data_dir.display(),
            workspace.display()
        ),
    )
    .expect("write env");

    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    {
        let settings = Settings::load().expect("load settings");
        let mut app = RustyPinchApp::new(settings).expect("new app");
        app.pulse_add_goal_json("goal-1", "keep service healthy")
            .expect("add goal");
        app.pulse_ooda_json(
            r#"[{"source":"monitor","key":"status","value":"degraded","severity":"warn"}]"#,
            "deploy production",
            Some("goal-1"),
        )
        .expect("run ooda");
    }

    let settings = Settings::load().expect("load settings restart");
    let app = RustyPinchApp::new(settings).expect("new app restart");
    let status = app.pulse_status_json().expect("pulse status");
    let value: Value = serde_json::from_str(&status).expect("valid json");

    let goals = value
        .get("goals")
        .and_then(Value::as_array)
        .expect("goals array");
    let approvals = value
        .get("pending_approvals")
        .and_then(Value::as_array)
        .expect("pending approvals array");

    assert_eq!(goals.len(), 1);
    assert_eq!(approvals.len(), 1);
    assert_eq!(goals[0].get("id").and_then(Value::as_str), Some("goal-1"));
}

#[test]
fn pulse_custom_jobs_persist_and_lifecycle_controls_work_across_restarts() {
    let _guard = ENV_LOCK.lock().expect("lock env");
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\nRUSTY_PINCH_PULSE_AUTO_ALLOW_ACTIONS=manual_only\n",
            data_dir.display(),
            workspace.display()
        ),
    )
    .expect("write env");

    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    {
        let settings = Settings::load().expect("load settings");
        let mut app = RustyPinchApp::new(settings).expect("new app");
        app.pulse_add_http_healthcheck_job_json(
            "api-health",
            60,
            "https://example.com/health",
            200,
            10,
            true,
        )
        .expect("add custom healthcheck job");
        app.pulse_disable_job_json("api-health")
            .expect("disable custom job");
    }

    {
        let settings = Settings::load().expect("load settings restart");
        let mut app = RustyPinchApp::new(settings).expect("new app restart");
        let jobs_json = app.pulse_jobs_json().expect("pulse jobs");
        let jobs_value: Value = serde_json::from_str(&jobs_json).expect("valid jobs json");
        let jobs = jobs_value
            .get("jobs")
            .and_then(Value::as_array)
            .expect("jobs array");
        let custom = jobs
            .iter()
            .find(|job| job.get("id").and_then(Value::as_str) == Some("api-health"))
            .expect("custom job should persist");
        assert_eq!(custom.get("enabled").and_then(Value::as_bool), Some(false));

        app.pulse_enable_job_json("api-health")
            .expect("enable custom job");
        app.pulse_remove_job_json("api-health")
            .expect("remove custom job");
    }

    let settings = Settings::load().expect("load settings final restart");
    let app = RustyPinchApp::new(settings).expect("new app final restart");
    let jobs_json = app.pulse_jobs_json().expect("pulse jobs final");
    let jobs_value: Value = serde_json::from_str(&jobs_json).expect("valid jobs json");
    let jobs = jobs_value
        .get("jobs")
        .and_then(Value::as_array)
        .expect("jobs array");
    assert!(
        jobs.iter()
            .all(|job| job.get("id").and_then(Value::as_str) != Some("api-health")),
        "custom job should stay removed after restart"
    );
}
