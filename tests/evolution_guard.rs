use std::fs;
use std::sync::Mutex;

use ed25519_dalek::{Signer, SigningKey};
use rusty_pinch::app::RustyPinchApp;
use rusty_pinch::config::Settings;
use serde_json::Value;
use sha2::{Digest, Sha256};

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

fn to_lower_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>()
}

#[test]
fn evolution_apply_requires_confirmation_by_default() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\n",
            data_dir.display(),
            workspace.display()
        ),
    )
    .expect("write env");

    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let settings = Settings::load().expect("load settings");
    let mut app = RustyPinchApp::new(settings).expect("new app");
    let err = app
        .evolution_apply_staged_update_json("doctor", 5, false)
        .expect_err("apply should require confirmation");
    assert!(err.to_string().contains("--confirm"));
}

#[test]
fn evolution_apply_can_skip_confirmation_when_policy_disabled() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\nRUSTY_PINCH_EVOLUTION_REQUIRE_APPLY_CONFIRM=false\n",
            data_dir.display(),
            workspace.display()
        ),
    )
    .expect("write env");

    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let settings = Settings::load().expect("load settings");
    let mut app = RustyPinchApp::new(settings).expect("new app");
    let err = app
        .evolution_apply_staged_update_json("doctor", 5, false)
        .expect_err("apply should fail only because there is no staged update");
    let message = err.to_string();
    assert!(
        !message.contains("--confirm"),
        "confirmation guard should be bypassed when policy is disabled: {message}"
    );
    assert!(
        message.contains("blue-green-staged.json"),
        "expected staged manifest lookup failure, got: {message}"
    );
}

#[test]
fn evolution_apply_requires_active_slot_signing_key_when_policy_enabled() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\nRUSTY_PINCH_EVOLUTION_REQUIRE_APPLY_CONFIRM=false\nRUSTY_PINCH_EVOLUTION_REQUIRE_SIGNED_ACTIVE_SLOT=true\n",
            data_dir.display(),
            workspace.display()
        ),
    )
    .expect("write env");

    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let current = temp.path().join("current.sh");
    let artifact = temp.path().join("artifact.sh");
    fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");
    fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");

    let settings = Settings::load().expect("load settings");
    let mut app = RustyPinchApp::new(settings).expect("new app");
    app.evolution_stage_update_json(
        artifact.to_str().expect("artifact path str"),
        Some(current.to_str().expect("current path str")),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("stage update");

    let err = app
        .evolution_apply_staged_update_json("doctor", 5, true)
        .expect_err("apply should fail when signed active-slot policy lacks key");
    assert!(err
        .to_string()
        .contains("RUSTY_PINCH_EVOLUTION_ACTIVE_SLOT_SIGNING_KEY"));
}

#[cfg(unix)]
#[test]
fn evolution_failure_circuit_reset_requires_confirm_flag() {
    use std::os::unix::fs::PermissionsExt;

    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\nRUSTY_PINCH_EVOLUTION_REQUIRE_APPLY_CONFIRM=false\nRUSTY_PINCH_EVOLUTION_MAX_CONSECUTIVE_APPLY_FAILURES=1\n",
            data_dir.display(),
            workspace.display()
        ),
    )
    .expect("write env");

    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let current = temp.path().join("current.sh");
    let artifact = temp.path().join("artifact.sh");
    fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");
    fs::write(&artifact, "#!/bin/sh\nexit 1\n").expect("write artifact");
    let mut current_perm = fs::metadata(&current).expect("current meta").permissions();
    current_perm.set_mode(0o755);
    fs::set_permissions(&current, current_perm).expect("chmod current");
    let mut artifact_perm = fs::metadata(&artifact)
        .expect("artifact meta")
        .permissions();
    artifact_perm.set_mode(0o755);
    fs::set_permissions(&artifact, artifact_perm).expect("chmod artifact");

    let settings = Settings::load().expect("load settings");
    let mut app = RustyPinchApp::new(settings).expect("new app");
    app.evolution_stage_update_json(
        artifact.to_str().expect("artifact path str"),
        Some(current.to_str().expect("current path str")),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("stage update");
    let apply = app
        .evolution_apply_staged_update_json("doctor", 5, true)
        .expect("apply");
    assert!(apply.contains("\"status\": \"rolled_back\""));

    let status = app
        .evolution_failure_circuit_status_json()
        .expect("failure-circuit status");
    assert!(status.contains("\"circuit_open\": true"));

    let err = app
        .evolution_failure_circuit_reset_json(false)
        .expect_err("reset should require confirm");
    assert!(err.to_string().contains("--confirm"));

    let reset = app
        .evolution_failure_circuit_reset_json(true)
        .expect("reset with confirmation");
    assert!(reset.contains("\"circuit_open\": false"));
    assert!(reset.contains("\"consecutive_failures\": 0"));
}

#[test]
fn evolution_apply_rejects_stale_staged_manifest_when_policy_enabled() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\nRUSTY_PINCH_EVOLUTION_REQUIRE_APPLY_CONFIRM=false\nRUSTY_PINCH_EVOLUTION_MAX_STAGED_MANIFEST_AGE_SECS=60\n",
            data_dir.display(),
            workspace.display()
        ),
    )
    .expect("write env");

    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let current = temp.path().join("current.sh");
    let artifact = temp.path().join("artifact.sh");
    fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");
    fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");

    let settings = Settings::load().expect("load settings");
    let mut app = RustyPinchApp::new(settings).expect("new app");
    app.evolution_stage_update_json(
        artifact.to_str().expect("artifact path str"),
        Some(current.to_str().expect("current path str")),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("stage update");

    let manifest_path = workspace.join("updates").join("blue-green-staged.json");
    let mut manifest: Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("read staged manifest"))
            .expect("decode staged manifest");
    manifest["timestamp"] = Value::String("2000-01-01T00:00:00Z".to_string());
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("encode staged manifest"),
    )
    .expect("write staged manifest");

    let err = app
        .evolution_apply_staged_update_json("doctor", 5, true)
        .expect_err("apply should fail for stale staged manifest");
    assert!(err.to_string().contains("stale"));

    let recovery = app
        .evolution_recovery_status_json()
        .expect("recovery status after stale apply");
    assert!(recovery.contains("\"manifest_expired\": true"));
    assert!(recovery.contains("\"manifest_max_age_secs\": 60"));
}

#[test]
fn evolution_apply_requires_manifest_signature_policy_when_enabled() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\nRUSTY_PINCH_EVOLUTION_REQUIRE_MANIFEST_SIGNATURE=true\n",
            data_dir.display(),
            workspace.display()
        ),
    )
    .expect("write env");

    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let current = temp.path().join("current.sh");
    let artifact = temp.path().join("artifact.sh");
    fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");
    fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");

    let settings = Settings::load().expect("load settings");
    let mut app = RustyPinchApp::new(settings).expect("new app");
    app.evolution_stage_update_json(
        artifact.to_str().expect("artifact path str"),
        Some(current.to_str().expect("current path str")),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("stage update");

    let err = app
        .evolution_apply_staged_update_json("doctor", 5, true)
        .expect_err("apply should fail without signing key when signature required");
    assert!(err.to_string().contains("no signing key is configured"));
}

#[cfg(unix)]
#[test]
fn evolution_apply_supports_signature_key_rotation_policy() {
    use std::os::unix::fs::PermissionsExt;

    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\nRUSTY_PINCH_EVOLUTION_REQUIRE_MANIFEST_SIGNATURE=true\nRUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEY_ID=2026-q1\nRUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEY=new-signing-key\nRUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEYS=2025-q4|old-signing-key\n",
            data_dir.display(),
            workspace.display()
        ),
    )
    .expect("write env");

    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let current = temp.path().join("current.sh");
    let artifact = temp.path().join("artifact.sh");
    fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");
    fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");
    let mut current_perm = fs::metadata(&current).expect("current meta").permissions();
    current_perm.set_mode(0o755);
    fs::set_permissions(&current, current_perm).expect("chmod current");
    let mut artifact_perm = fs::metadata(&artifact)
        .expect("artifact meta")
        .permissions();
    artifact_perm.set_mode(0o755);
    fs::set_permissions(&artifact, artifact_perm).expect("chmod artifact");

    let settings = Settings::load().expect("load settings");
    let mut app = RustyPinchApp::new(settings).expect("new app");
    app.evolution_stage_update_json(
        artifact.to_str().expect("artifact path str"),
        Some(current.to_str().expect("current path str")),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("stage update");

    let result = app
        .evolution_apply_staged_update_json("doctor", 5, true)
        .expect("apply should pass with rotated keyring");
    assert!(result.contains("\"status\": \"activated\""));
}

#[test]
fn evolution_stage_update_requires_artifact_checksum_when_policy_enabled() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\nRUSTY_PINCH_EVOLUTION_REQUIRE_STAGE_ARTIFACT_SHA256=true\n",
            data_dir.display(),
            workspace.display()
        ),
    )
    .expect("write env");

    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let current = temp.path().join("current.sh");
    let artifact = temp.path().join("artifact.sh");
    fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");
    fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");

    let settings = Settings::load().expect("load settings");
    let app = RustyPinchApp::new(settings).expect("new app");

    let err = app
        .evolution_stage_update_json(
            artifact.to_str().expect("artifact path str"),
            Some(current.to_str().expect("current path str")),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect_err("stage should require artifact checksum under policy");
    assert!(err.to_string().contains("--artifact-sha256"));

    let artifact_bytes = fs::read(&artifact).expect("read artifact");
    let checksum = format!("{:x}", Sha256::digest(&artifact_bytes));
    let staged = app
        .evolution_stage_update_json(
            artifact.to_str().expect("artifact path str"),
            Some(current.to_str().expect("current path str")),
            None,
            None,
            Some(&checksum),
            None,
            None,
            None,
        )
        .expect("stage should succeed with checksum");
    assert!(staged.contains("\"status\": \"staged\""));
}

#[test]
fn evolution_apply_requires_verified_stage_artifact_provenance_when_policy_enabled() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\nRUSTY_PINCH_EVOLUTION_REQUIRE_STAGE_ARTIFACT_SHA256=false\nRUSTY_PINCH_EVOLUTION_REQUIRE_VERIFIED_STAGE_ARTIFACT_SHA256=true\n",
            data_dir.display(),
            workspace.display()
        ),
    )
    .expect("write env");

    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let current = temp.path().join("current.sh");
    let artifact = temp.path().join("artifact.sh");
    fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");
    fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");

    let settings = Settings::load().expect("load settings");
    let mut app = RustyPinchApp::new(settings).expect("new app");

    app.evolution_stage_update_json(
        artifact.to_str().expect("artifact path str"),
        Some(current.to_str().expect("current path str")),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("stage should succeed without checksum when stage policy is disabled");

    let err = app
        .evolution_apply_staged_update_json("doctor", 5, true)
        .expect_err("apply should fail due provenance policy");
    assert!(err.to_string().contains("artifact-checksum-verified"));
}

#[test]
fn evolution_apply_requires_signed_checksum_manifest_provenance_when_policy_enabled() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\nRUSTY_PINCH_EVOLUTION_REQUIRE_SIGNED_CHECKSUM_MANIFEST_PROVENANCE=true\n",
            data_dir.display(),
            workspace.display()
        ),
    )
    .expect("write env");

    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let current = temp.path().join("current.sh");
    let artifact = temp.path().join("artifact.sh");
    fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");
    fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");

    let settings = Settings::load().expect("load settings");
    let mut app = RustyPinchApp::new(settings).expect("new app");

    app.evolution_stage_update_json(
        artifact.to_str().expect("artifact path str"),
        Some(current.to_str().expect("current path str")),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("stage update");

    let err = app
        .evolution_apply_staged_update_json("doctor", 5, true)
        .expect_err("apply should fail due checksum-manifest provenance policy");
    assert!(err
        .to_string()
        .contains("checksum-manifest-signature-verified"));
}

#[test]
fn evolution_stage_update_requires_versions_when_non_rollback_policy_enabled() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\nRUSTY_PINCH_EVOLUTION_REQUIRE_NON_ROLLBACK_VERSION=true\n",
            data_dir.display(),
            workspace.display()
        ),
    )
    .expect("write env");

    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let current = temp.path().join("current.sh");
    let artifact = temp.path().join("artifact.sh");
    fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");
    fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");

    let settings = Settings::load().expect("load settings");
    let app = RustyPinchApp::new(settings).expect("new app");
    let err = app
        .evolution_stage_update_json(
            artifact.to_str().expect("artifact path str"),
            Some(current.to_str().expect("current path str")),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect_err("stage should require versions under non-rollback policy");
    assert!(err
        .to_string()
        .contains("RUSTY_PINCH_EVOLUTION_REQUIRE_NON_ROLLBACK_VERSION"));
}

#[test]
fn evolution_stage_update_rejects_rollback_version_when_policy_enabled() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\nRUSTY_PINCH_EVOLUTION_REQUIRE_NON_ROLLBACK_VERSION=true\n",
            data_dir.display(),
            workspace.display()
        ),
    )
    .expect("write env");

    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let current = temp.path().join("current.sh");
    let artifact = temp.path().join("artifact.sh");
    fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");
    fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");

    let settings = Settings::load().expect("load settings");
    let app = RustyPinchApp::new(settings).expect("new app");
    let err = app
        .evolution_stage_update_json(
            artifact.to_str().expect("artifact path str"),
            Some(current.to_str().expect("current path str")),
            Some("1.3.0"),
            Some("1.2.9"),
            None,
            None,
            None,
            None,
        )
        .expect_err("stage should reject rollback version");
    assert!(err
        .to_string()
        .contains("must be greater than current version"));
}

#[test]
fn evolution_stage_update_accepts_trusted_sha256sums_manifest() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    let current = temp.path().join("current.sh");
    let artifact = temp.path().join("artifact.sh");
    let sums = temp.path().join("SHA256SUMS.txt");
    fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");
    fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");

    let artifact_sha256 = format!(
        "{:x}",
        Sha256::digest(fs::read(&artifact).expect("artifact"))
    );
    fs::write(
        &sums,
        format!(
            "{artifact_sha256}  {}\n",
            artifact.to_str().expect("artifact str")
        ),
    )
    .expect("write sums");
    let sums_sha256 = format!("{:x}", Sha256::digest(fs::read(&sums).expect("sums")));

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\nRUSTY_PINCH_EVOLUTION_REQUIRE_STAGE_ARTIFACT_SHA256=true\nRUSTY_PINCH_EVOLUTION_TRUSTED_SHA256SUMS_SHA256={}\n",
            data_dir.display(),
            workspace.display(),
            sums_sha256,
        ),
    )
    .expect("write env");
    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let settings = Settings::load().expect("load settings");
    let app = RustyPinchApp::new(settings).expect("new app");
    let staged = app
        .evolution_stage_update_json(
            artifact.to_str().expect("artifact path str"),
            Some(current.to_str().expect("current path str")),
            None,
            None,
            None,
            Some(sums.to_str().expect("sums path str")),
            None,
            None,
        )
        .expect("stage should succeed with trusted sums manifest");
    assert!(staged.contains("\"status\": \"staged\""));
}

#[test]
fn evolution_stage_update_requires_sha256sums_signature_when_policy_enabled() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    let current = temp.path().join("current.sh");
    let artifact = temp.path().join("artifact.sh");
    let sums = temp.path().join("SHA256SUMS.txt");
    fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");
    fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");

    let artifact_sha256 = format!(
        "{:x}",
        Sha256::digest(fs::read(&artifact).expect("artifact"))
    );
    fs::write(
        &sums,
        format!(
            "{artifact_sha256}  {}\n",
            artifact.to_str().expect("artifact str")
        ),
    )
    .expect("write sums");

    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let public_key_hex = to_lower_hex(signing_key.verifying_key().as_bytes());
    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\nRUSTY_PINCH_EVOLUTION_REQUIRE_STAGE_ARTIFACT_SHA256=true\nRUSTY_PINCH_EVOLUTION_REQUIRE_SHA256SUMS_SIGNATURE=true\nRUSTY_PINCH_EVOLUTION_TRUSTED_SHA256SUMS_ED25519_PUBLIC_KEY={}\n",
            data_dir.display(),
            workspace.display(),
            public_key_hex,
        ),
    )
    .expect("write env");
    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let settings = Settings::load().expect("load settings");
    let app = RustyPinchApp::new(settings).expect("new app");
    let err = app
        .evolution_stage_update_json(
            artifact.to_str().expect("artifact path str"),
            Some(current.to_str().expect("current path str")),
            None,
            None,
            None,
            Some(sums.to_str().expect("sums path str")),
            None,
            None,
        )
        .expect_err("stage should fail when checksum manifest signature is required");
    assert!(err
        .to_string()
        .contains("checksum manifest signature is required by policy"));
}

#[test]
fn evolution_stage_update_accepts_signed_sha256sums_manifest() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    let current = temp.path().join("current.sh");
    let artifact = temp.path().join("artifact.sh");
    let sums = temp.path().join("SHA256SUMS.txt");
    let sums_sig = temp.path().join("SHA256SUMS.sig");
    fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");
    fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");

    let artifact_sha256 = format!(
        "{:x}",
        Sha256::digest(fs::read(&artifact).expect("artifact"))
    );
    fs::write(
        &sums,
        format!(
            "{artifact_sha256}  {}\n",
            artifact.to_str().expect("artifact str")
        ),
    )
    .expect("write sums");

    let signing_key = SigningKey::from_bytes(&[12u8; 32]);
    let sums_raw = fs::read(&sums).expect("read sums");
    let signature = signing_key.sign(&sums_raw);
    fs::write(&sums_sig, to_lower_hex(&signature.to_bytes())).expect("write sums sig");
    let public_key_hex = to_lower_hex(signing_key.verifying_key().as_bytes());

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\nRUSTY_PINCH_EVOLUTION_REQUIRE_STAGE_ARTIFACT_SHA256=true\nRUSTY_PINCH_EVOLUTION_REQUIRE_SHA256SUMS_SIGNATURE=true\nRUSTY_PINCH_EVOLUTION_TRUSTED_SHA256SUMS_ED25519_PUBLIC_KEY={}\n",
            data_dir.display(),
            workspace.display(),
            public_key_hex,
        ),
    )
    .expect("write env");
    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let settings = Settings::load().expect("load settings");
    let app = RustyPinchApp::new(settings).expect("new app");
    let staged = app
        .evolution_stage_update_json(
            artifact.to_str().expect("artifact path str"),
            Some(current.to_str().expect("current path str")),
            None,
            None,
            None,
            Some(sums.to_str().expect("sums path str")),
            Some(sums_sig.to_str().expect("sums sig path str")),
            None,
        )
        .expect("stage should succeed with signed sums manifest");
    assert!(staged.contains("\"status\": \"staged\""));
}

#[test]
fn evolution_stage_update_rejects_untrusted_sha256sums_manifest() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    let current = temp.path().join("current.sh");
    let artifact = temp.path().join("artifact.sh");
    let sums = temp.path().join("SHA256SUMS.txt");
    fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");
    fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");

    let artifact_sha256 = format!(
        "{:x}",
        Sha256::digest(fs::read(&artifact).expect("artifact"))
    );
    fs::write(
        &sums,
        format!(
            "{artifact_sha256}  {}\n",
            artifact.to_str().expect("artifact str")
        ),
    )
    .expect("write sums");

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\nRUSTY_PINCH_EVOLUTION_REQUIRE_STAGE_ARTIFACT_SHA256=true\nRUSTY_PINCH_EVOLUTION_TRUSTED_SHA256SUMS_SHA256=0000000000000000000000000000000000000000000000000000000000000000\n",
            data_dir.display(),
            workspace.display(),
        ),
    )
    .expect("write env");
    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let settings = Settings::load().expect("load settings");
    let app = RustyPinchApp::new(settings).expect("new app");
    let err = app
        .evolution_stage_update_json(
            artifact.to_str().expect("artifact path str"),
            Some(current.to_str().expect("current path str")),
            None,
            None,
            None,
            Some(sums.to_str().expect("sums path str")),
            None,
            None,
        )
        .expect_err("stage should fail for untrusted sums manifest");
    assert!(err
        .to_string()
        .contains("checksum manifest SHA-256 mismatch"));
}

#[test]
fn evolution_force_unlock_requires_confirm_flag() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\n",
            data_dir.display(),
            workspace.display()
        ),
    )
    .expect("write env");
    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    fs::create_dir_all(workspace.join("updates")).expect("updates dir");
    fs::write(
        workspace.join("updates").join("evolution.lock"),
        "operation=apply-staged-update pid=123 started_at=2000-01-01T00:00:00Z",
    )
    .expect("write lock");

    let settings = Settings::load().expect("load settings");
    let app = RustyPinchApp::new(settings).expect("new app");

    let err = app
        .evolution_force_unlock_json(false)
        .expect_err("force unlock should require --confirm");
    assert!(err.to_string().contains("--confirm"));

    let unlocked = app
        .evolution_force_unlock_json(true)
        .expect("force unlock with confirmation");
    assert!(unlocked.contains("\"force_unlocked\": true"));
}

#[test]
fn evolution_stage_update_recovers_stale_lock_when_policy_enabled() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\nRUSTY_PINCH_EVOLUTION_LOCK_STALE_AFTER_SECS=60\nRUSTY_PINCH_EVOLUTION_AUTO_RECOVER_STALE_LOCK=true\n",
            data_dir.display(),
            workspace.display()
        ),
    )
    .expect("write env");
    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let current = temp.path().join("current.sh");
    let artifact = temp.path().join("artifact.sh");
    fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");
    fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");

    fs::create_dir_all(workspace.join("updates")).expect("updates dir");
    let lock_path = workspace.join("updates").join("evolution.lock");
    fs::write(
        &lock_path,
        "operation=apply-staged-update pid=321 started_at=2000-01-01T00:00:00Z",
    )
    .expect("write stale lock");

    let settings = Settings::load().expect("load settings");
    let app = RustyPinchApp::new(settings).expect("new app");
    let staged = app
        .evolution_stage_update_json(
            artifact.to_str().expect("artifact path str"),
            Some(current.to_str().expect("current path str")),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("stage should recover stale lock");
    assert!(staged.contains("\"status\": \"staged\""));
    assert!(!lock_path.exists());
}

#[test]
fn evolution_recovery_status_reports_partial_apply_diagnostics() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    reset_rusty_env();

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("data");
    let workspace = temp.path().join("workspace");
    let env_file = temp.path().join(".env");

    fs::write(
        &env_file,
        format!(
            "RUSTY_PINCH_PROVIDER=local\nRUSTY_PINCH_MODEL=test-model\nRUSTY_PINCH_DATA_DIR={}\nRUSTY_PINCH_WORKSPACE={}\n",
            data_dir.display(),
            workspace.display()
        ),
    )
    .expect("write env");
    std::env::set_var("RUSTY_PINCH_ENV_FILE", env_file.display().to_string());

    let current = temp.path().join("current.sh");
    let artifact = temp.path().join("artifact.sh");
    fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");
    fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");

    let settings = Settings::load().expect("load settings");
    let app = RustyPinchApp::new(settings).expect("new app");
    app.evolution_stage_update_json(
        artifact.to_str().expect("artifact path str"),
        Some(current.to_str().expect("current path str")),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("stage update");

    let manifest_path = workspace.join("updates").join("blue-green-staged.json");
    let manifest_raw = fs::read_to_string(&manifest_path).expect("manifest");
    let mut manifest: Value = serde_json::from_str(&manifest_raw).expect("manifest json");
    manifest["status"] = Value::String("healthcheck_pending".to_string());
    manifest["apply_started_at"] = Value::String("2026-01-01T00:00:00Z".to_string());
    manifest["apply_from_slot"] = Value::String("blue".to_string());
    manifest["apply_to_slot"] = Value::String("green".to_string());
    manifest["apply_resume_count"] = Value::from(3u64);
    manifest["last_recovery_note"] = Value::String(
        "resumed apply and continued from pending healthcheck checkpoint".to_string(),
    );
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("encode manifest"),
    )
    .expect("write manifest");
    fs::write(workspace.join("updates").join("active-slot"), "green\n").expect("write active slot");

    let raw = app
        .evolution_recovery_status_json()
        .expect("recovery status");
    let payload: Value = serde_json::from_str(&raw).expect("status json");
    let report = payload.get("report").expect("report");
    assert_eq!(
        report.get("manifest_status").and_then(Value::as_str),
        Some("healthcheck_pending")
    );
    assert_eq!(
        report.get("apply_resume_count").and_then(Value::as_u64),
        Some(3)
    );
    assert_eq!(
        report.get("drift_detected").and_then(Value::as_bool),
        Some(false)
    );
    assert!(report
        .get("recommendation")
        .and_then(Value::as_str)
        .is_some_and(|value| value.contains("re-run evolution apply-staged-update")));
}
