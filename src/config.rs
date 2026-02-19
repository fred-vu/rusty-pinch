use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

const ENV_FILE_ENV: &str = "RUSTY_PINCH_ENV_FILE";

#[derive(Debug, Clone)]
pub struct Settings {
    pub provider: String,
    pub model: String,
    pub api_key: Option<String>,
    pub api_base: Option<String>,
    pub request_timeout_secs: u64,
    pub request_retries: u32,
    pub retry_backoff_ms: u64,
    pub retry_max_backoff_ms: u64,
    pub data_dir: PathBuf,
    pub workspace: PathBuf,
    pub telemetry_file: PathBuf,
    pub channels: ChannelsSettings,
    pub codex: CodexSettings,
    pub pulse: PulseSettings,
    pub evolution: EvolutionSettings,
}

#[derive(Debug, Clone)]
pub struct ChannelsSettings {
    pub telegram: TelegramChannelSettings,
    pub whatsapp: WhatsAppChannelSettings,
}

#[derive(Debug, Clone)]
pub struct TelegramChannelSettings {
    pub enabled: bool,
    pub token: Option<String>,
    pub allow_from: Vec<String>,
    pub poll_timeout_secs: u64,
    pub poll_interval_ms: u64,
    pub request_timeout_secs: u64,
}

#[derive(Debug, Clone)]
pub struct WhatsAppChannelSettings {
    pub enabled: bool,
    pub bridge_url: Option<String>,
    pub allow_from: Vec<String>,
    pub reconnect_ms: u64,
}

#[derive(Debug, Clone)]
pub struct CodexSettings {
    pub enabled: bool,
    pub cli_bin: String,
    pub cli_args: Vec<String>,
    pub prompt_flag: String,
    pub model_flag: String,
    pub timeout_secs: u64,
    pub queue_capacity: usize,
    pub rate_limit_threshold_percent: u8,
    pub rate_window_secs: u64,
    pub healthcheck_interval_secs: u64,
    pub healthcheck_args: Vec<String>,
    pub default_model: Option<String>,
    pub accounts: Vec<CodexAccountSettings>,
}

#[derive(Debug, Clone)]
pub struct CodexAccountSettings {
    pub id: String,
    pub api_key_env: Option<String>,
    pub max_requests: u32,
    pub model: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PulseSettings {
    pub auto_allow_actions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct EvolutionSettings {
    pub require_apply_confirm: bool,
    pub require_stage_artifact_sha256: bool,
    pub require_verified_stage_artifact_sha256: bool,
    pub require_signed_checksum_manifest_provenance: bool,
    pub require_non_rollback_version: bool,
    pub trusted_sha256sums_sha256: Option<String>,
    pub trusted_sha256sums_ed25519_public_key: Option<String>,
    pub require_sha256sums_signature: bool,
    pub manifest_signing_key_id: Option<String>,
    pub manifest_signing_key: Option<String>,
    pub manifest_signing_keys: Vec<(String, String)>,
    pub require_manifest_signature: bool,
    pub active_slot_signing_key_id: Option<String>,
    pub active_slot_signing_key: Option<String>,
    pub require_signed_active_slot: bool,
    pub max_staged_manifest_age_secs: Option<u64>,
    pub max_consecutive_apply_failures: Option<u64>,
    pub lock_stale_after_secs: Option<u64>,
    pub auto_recover_stale_lock: bool,
}

impl Settings {
    pub fn load() -> Result<Self> {
        load_dotenv()?;

        let provider = env::var("RUSTY_PINCH_PROVIDER")
            .unwrap_or_else(|_| "openrouter".to_string())
            .trim()
            .to_lowercase();

        let model = env::var("RUSTY_PINCH_MODEL")
            .unwrap_or_else(|_| default_model(&provider).to_string())
            .trim()
            .to_string();

        let api_key = resolve_api_key(&provider);
        let api_base = resolve_api_base(&provider);
        let request_timeout_secs = env::var("RUSTY_PINCH_REQUEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60);
        let request_retries = env::var("RUSTY_PINCH_REQUEST_RETRIES")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(2);
        let retry_backoff_ms = env::var("RUSTY_PINCH_RETRY_BACKOFF_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(600);
        let retry_max_backoff_ms = env::var("RUSTY_PINCH_RETRY_MAX_BACKOFF_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(4000);

        let data_dir = env::var("RUSTY_PINCH_DATA_DIR")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./data"));

        let workspace = env::var("RUSTY_PINCH_WORKSPACE")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./workspace"));

        let telemetry_file = env::var("RUSTY_PINCH_TELEMETRY_FILE")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("telemetry/latest.json"));

        let channels = ChannelsSettings {
            telegram: TelegramChannelSettings {
                enabled: read_bool_env("RUSTY_PINCH_CHANNELS_TELEGRAM_ENABLED", false),
                token: read_non_empty_env("RUSTY_PINCH_CHANNELS_TELEGRAM_TOKEN"),
                allow_from: read_csv_env("RUSTY_PINCH_CHANNELS_TELEGRAM_ALLOW_FROM"),
                poll_timeout_secs: read_u64_env(
                    "RUSTY_PINCH_CHANNELS_TELEGRAM_POLL_TIMEOUT_SECS",
                    30,
                ),
                poll_interval_ms: read_u64_env(
                    "RUSTY_PINCH_CHANNELS_TELEGRAM_POLL_INTERVAL_MS",
                    350,
                ),
                request_timeout_secs: read_u64_env(
                    "RUSTY_PINCH_CHANNELS_TELEGRAM_REQUEST_TIMEOUT_SECS",
                    60,
                ),
            },
            whatsapp: WhatsAppChannelSettings {
                enabled: read_bool_env("RUSTY_PINCH_CHANNELS_WHATSAPP_ENABLED", false),
                bridge_url: read_non_empty_env("RUSTY_PINCH_CHANNELS_WHATSAPP_BRIDGE_URL"),
                allow_from: read_csv_env("RUSTY_PINCH_CHANNELS_WHATSAPP_ALLOW_FROM"),
                reconnect_ms: read_u64_env("RUSTY_PINCH_CHANNELS_WHATSAPP_RECONNECT_MS", 2000),
            },
        };

        let codex = load_codex_settings(&model);
        let pulse = load_pulse_settings();
        let evolution = load_evolution_settings();

        Ok(Self {
            provider,
            model,
            api_key,
            api_base,
            request_timeout_secs,
            request_retries,
            retry_backoff_ms,
            retry_max_backoff_ms,
            data_dir,
            workspace,
            telemetry_file,
            channels,
            codex,
            pulse,
            evolution,
        })
    }

    pub fn doctor_report(&self) -> DoctorReport {
        let provider_requires_key = !matches!(self.provider.as_str(), "local" | "offline");
        let provider_requires_base = matches!(
            self.provider.as_str(),
            "openrouter" | "openai" | "groq" | "vllm" | "compatible"
        );
        let key_present = self
            .api_key
            .as_ref()
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        let base_present = self
            .api_base
            .as_ref()
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);

        let mut warnings = Vec::new();
        if self.model.trim().is_empty() {
            warnings.push("RUSTY_PINCH_MODEL is empty".to_string());
        }
        if provider_requires_key && !key_present {
            warnings.push(format!(
                "Provider '{}' requires API key but none was found",
                self.provider
            ));
        }
        if provider_requires_base && !base_present {
            warnings.push(format!(
                "Provider '{}' requires API base but none was found",
                self.provider
            ));
        }
        if self.request_timeout_secs == 0 {
            warnings.push("RUSTY_PINCH_REQUEST_TIMEOUT_SECS should be > 0".to_string());
        }
        if self.retry_max_backoff_ms < self.retry_backoff_ms {
            warnings.push(
                "RUSTY_PINCH_RETRY_MAX_BACKOFF_MS should be >= RUSTY_PINCH_RETRY_BACKOFF_MS"
                    .to_string(),
            );
        }
        if self.channels.telegram.enabled && self.channels.telegram.token.is_none() {
            warnings.push(
                "Telegram channel enabled but RUSTY_PINCH_CHANNELS_TELEGRAM_TOKEN is missing"
                    .to_string(),
            );
        }
        if self.channels.whatsapp.enabled && self.channels.whatsapp.bridge_url.is_none() {
            warnings.push(
                "WhatsApp channel enabled but RUSTY_PINCH_CHANNELS_WHATSAPP_BRIDGE_URL is missing"
                    .to_string(),
            );
        }
        if self.codex.enabled && self.codex.accounts.is_empty() {
            warnings.push(
                "Codex enabled but no accounts were configured. Set RUSTY_PINCH_CODEX_ACCOUNTS"
                    .to_string(),
            );
        }
        if self.codex.enabled && self.codex.cli_bin.trim().is_empty() {
            warnings.push("Codex enabled but RUSTY_PINCH_CODEX_CLI_BIN is empty".to_string());
        }
        if self.evolution.require_manifest_signature
            && self.evolution.manifest_signing_keys.is_empty()
        {
            warnings.push(
                "Evolution manifest signature is required but no signing key is configured. Set RUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEY or RUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEYS"
                    .to_string(),
            );
        }

        if self.evolution.manifest_signing_key_id.is_some()
            && self.evolution.manifest_signing_key.is_none()
        {
            warnings.push(
                "RUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEY_ID is set but RUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEY is missing"
                    .to_string(),
            );
        }
        if self.evolution.require_verified_stage_artifact_sha256
            && !self.evolution.require_stage_artifact_sha256
        {
            warnings.push(
                "RUSTY_PINCH_EVOLUTION_REQUIRE_VERIFIED_STAGE_ARTIFACT_SHA256=true while RUSTY_PINCH_EVOLUTION_REQUIRE_STAGE_ARTIFACT_SHA256=false; stage-update may create manifests that apply policy later blocks"
                    .to_string(),
            );
        }
        if self.evolution.require_verified_stage_artifact_sha256
            && !self.evolution.require_manifest_signature
        {
            warnings.push(
                "RUSTY_PINCH_EVOLUTION_REQUIRE_VERIFIED_STAGE_ARTIFACT_SHA256 is enabled without RUSTY_PINCH_EVOLUTION_REQUIRE_MANIFEST_SIGNATURE; manifest tampering protections are weaker"
                    .to_string(),
            );
        }
        if self.evolution.require_signed_checksum_manifest_provenance
            && !self.evolution.require_sha256sums_signature
        {
            warnings.push(
                "RUSTY_PINCH_EVOLUTION_REQUIRE_SIGNED_CHECKSUM_MANIFEST_PROVENANCE=true while RUSTY_PINCH_EVOLUTION_REQUIRE_SHA256SUMS_SIGNATURE=false; stage-update may create manifests that apply policy later blocks"
                    .to_string(),
            );
        }
        if self.evolution.require_signed_checksum_manifest_provenance
            && self
                .evolution
                .trusted_sha256sums_ed25519_public_key
                .is_none()
        {
            warnings.push(
                "RUSTY_PINCH_EVOLUTION_REQUIRE_SIGNED_CHECKSUM_MANIFEST_PROVENANCE=true but RUSTY_PINCH_EVOLUTION_TRUSTED_SHA256SUMS_ED25519_PUBLIC_KEY is missing"
                    .to_string(),
            );
        }
        if self.evolution.require_non_rollback_version && !self.evolution.require_manifest_signature
        {
            warnings.push(
                "RUSTY_PINCH_EVOLUTION_REQUIRE_NON_ROLLBACK_VERSION is enabled without RUSTY_PINCH_EVOLUTION_REQUIRE_MANIFEST_SIGNATURE; manifest version metadata tampering protections are weaker"
                    .to_string(),
            );
        }
        if self.evolution.max_staged_manifest_age_secs.is_none() {
            warnings.push(
                "RUSTY_PINCH_EVOLUTION_MAX_STAGED_MANIFEST_AGE_SECS is 0/disabled; stale staged manifests can be applied"
                    .to_string(),
            );
        }
        if self.evolution.max_staged_manifest_age_secs.is_some()
            && !self.evolution.require_manifest_signature
        {
            warnings.push(
                "RUSTY_PINCH_EVOLUTION_MAX_STAGED_MANIFEST_AGE_SECS is enabled without RUSTY_PINCH_EVOLUTION_REQUIRE_MANIFEST_SIGNATURE; manifest timestamp tampering protections are weaker"
                    .to_string(),
            );
        }
        if self
            .evolution
            .trusted_sha256sums_sha256
            .as_ref()
            .is_some_and(|value| {
                value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit())
            })
        {
            warnings.push(
                "RUSTY_PINCH_EVOLUTION_TRUSTED_SHA256SUMS_SHA256 must be a 64-character SHA-256 hex string"
                    .to_string(),
            );
        }
        if self.evolution.require_sha256sums_signature
            && self
                .evolution
                .trusted_sha256sums_ed25519_public_key
                .is_none()
        {
            warnings.push(
                "RUSTY_PINCH_EVOLUTION_REQUIRE_SHA256SUMS_SIGNATURE=true but RUSTY_PINCH_EVOLUTION_TRUSTED_SHA256SUMS_ED25519_PUBLIC_KEY is missing"
                    .to_string(),
            );
        }
        if self
            .evolution
            .trusted_sha256sums_ed25519_public_key
            .as_ref()
            .is_some_and(|value| !is_valid_ed25519_key_material(value))
        {
            warnings.push(
                "RUSTY_PINCH_EVOLUTION_TRUSTED_SHA256SUMS_ED25519_PUBLIC_KEY must be base64 or 64-character hex Ed25519 public key"
                    .to_string(),
            );
        }

        let has_short_signing_key = self
            .evolution
            .manifest_signing_keys
            .iter()
            .any(|(_, key)| key.chars().count() < 16);
        if has_short_signing_key {
            warnings.push(
                "One or more evolution manifest signing keys are short; use at least 16 characters"
                    .to_string(),
            );
        }

        let mut seen = HashSet::new();
        let has_duplicate_signing_key_id = self
            .evolution
            .manifest_signing_keys
            .iter()
            .any(|(id, _)| !seen.insert(id.to_ascii_lowercase()));
        if has_duplicate_signing_key_id {
            warnings.push(
                "RUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEYS contains duplicate key ids"
                    .to_string(),
            );
        }
        if self.evolution.auto_recover_stale_lock && self.evolution.lock_stale_after_secs.is_none()
        {
            warnings.push(
                "RUSTY_PINCH_EVOLUTION_AUTO_RECOVER_STALE_LOCK=true but RUSTY_PINCH_EVOLUTION_LOCK_STALE_AFTER_SECS is 0/disabled"
                    .to_string(),
            );
        }
        if self.evolution.max_consecutive_apply_failures.is_none() {
            warnings.push(
                "RUSTY_PINCH_EVOLUTION_MAX_CONSECUTIVE_APPLY_FAILURES is 0/disabled; repeated failed applies will not open circuit breaker"
                    .to_string(),
            );
        }
        if self.evolution.require_signed_active_slot
            && self.evolution.active_slot_signing_key.is_none()
        {
            warnings.push(
                "RUSTY_PINCH_EVOLUTION_REQUIRE_SIGNED_ACTIVE_SLOT=true but no active-slot signing key is configured. Set RUSTY_PINCH_EVOLUTION_ACTIVE_SLOT_SIGNING_KEY"
                    .to_string(),
            );
        }
        if self.evolution.active_slot_signing_key_id.is_some()
            && self.evolution.active_slot_signing_key.is_none()
        {
            warnings.push(
                "RUSTY_PINCH_EVOLUTION_ACTIVE_SLOT_SIGNING_KEY_ID is set but RUSTY_PINCH_EVOLUTION_ACTIVE_SLOT_SIGNING_KEY is missing"
                    .to_string(),
            );
        }
        if self
            .evolution
            .active_slot_signing_key
            .as_ref()
            .is_some_and(|key| key.chars().count() < 16)
        {
            warnings.push(
                "RUSTY_PINCH_EVOLUTION_ACTIVE_SLOT_SIGNING_KEY is short; use at least 16 characters"
                    .to_string(),
            );
        }

        DoctorReport {
            provider: self.provider.clone(),
            model: self.model.clone(),
            api_base: self.api_base.clone(),
            data_dir: self.data_dir.clone(),
            workspace: self.workspace.clone(),
            telemetry_file: self.telemetry_file.clone(),
            key_present,
            request_timeout_secs: self.request_timeout_secs,
            request_retries: self.request_retries,
            retry_backoff_ms: self.retry_backoff_ms,
            retry_max_backoff_ms: self.retry_max_backoff_ms,
            telegram_enabled: self.channels.telegram.enabled,
            telegram_allow_from_count: self.channels.telegram.allow_from.len(),
            whatsapp_enabled: self.channels.whatsapp.enabled,
            whatsapp_allow_from_count: self.channels.whatsapp.allow_from.len(),
            codex_enabled: self.codex.enabled,
            codex_accounts_count: self.codex.accounts.len(),
            codex_queue_capacity: self.codex.queue_capacity,
            codex_rate_limit_threshold_percent: self.codex.rate_limit_threshold_percent,
            pulse_auto_allow_actions_count: self.pulse.auto_allow_actions.len(),
            evolution_require_apply_confirm: self.evolution.require_apply_confirm,
            evolution_require_stage_artifact_sha256: self.evolution.require_stage_artifact_sha256,
            evolution_require_verified_stage_artifact_sha256: self
                .evolution
                .require_verified_stage_artifact_sha256,
            evolution_require_signed_checksum_manifest_provenance: self
                .evolution
                .require_signed_checksum_manifest_provenance,
            evolution_require_non_rollback_version: self.evolution.require_non_rollback_version,
            evolution_trusted_sha256sums_sha256_loaded: self
                .evolution
                .trusted_sha256sums_sha256
                .is_some(),
            evolution_trusted_sha256sums_ed25519_public_key_loaded: self
                .evolution
                .trusted_sha256sums_ed25519_public_key
                .is_some(),
            evolution_require_sha256sums_signature: self.evolution.require_sha256sums_signature,
            evolution_manifest_signing_key_id: self.evolution.manifest_signing_key_id.clone(),
            evolution_manifest_signing_key_loaded: self.evolution.manifest_signing_key.is_some(),
            evolution_manifest_signing_keys_count: self.evolution.manifest_signing_keys.len(),
            evolution_require_manifest_signature: self.evolution.require_manifest_signature,
            evolution_active_slot_signing_key_id: self.evolution.active_slot_signing_key_id.clone(),
            evolution_active_slot_signing_key_loaded: self
                .evolution
                .active_slot_signing_key
                .is_some(),
            evolution_require_signed_active_slot: self.evolution.require_signed_active_slot,
            evolution_max_staged_manifest_age_secs: self.evolution.max_staged_manifest_age_secs,
            evolution_max_consecutive_apply_failures: self.evolution.max_consecutive_apply_failures,
            evolution_lock_stale_after_secs: self.evolution.lock_stale_after_secs,
            evolution_auto_recover_stale_lock: self.evolution.auto_recover_stale_lock,
            warnings,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DoctorReport {
    pub provider: String,
    pub model: String,
    pub api_base: Option<String>,
    pub data_dir: PathBuf,
    pub workspace: PathBuf,
    pub telemetry_file: PathBuf,
    pub key_present: bool,
    pub request_timeout_secs: u64,
    pub request_retries: u32,
    pub retry_backoff_ms: u64,
    pub retry_max_backoff_ms: u64,
    pub telegram_enabled: bool,
    pub telegram_allow_from_count: usize,
    pub whatsapp_enabled: bool,
    pub whatsapp_allow_from_count: usize,
    pub codex_enabled: bool,
    pub codex_accounts_count: usize,
    pub codex_queue_capacity: usize,
    pub codex_rate_limit_threshold_percent: u8,
    pub pulse_auto_allow_actions_count: usize,
    pub evolution_require_apply_confirm: bool,
    pub evolution_require_stage_artifact_sha256: bool,
    pub evolution_require_verified_stage_artifact_sha256: bool,
    pub evolution_require_signed_checksum_manifest_provenance: bool,
    pub evolution_require_non_rollback_version: bool,
    pub evolution_trusted_sha256sums_sha256_loaded: bool,
    pub evolution_trusted_sha256sums_ed25519_public_key_loaded: bool,
    pub evolution_require_sha256sums_signature: bool,
    pub evolution_manifest_signing_key_id: Option<String>,
    pub evolution_manifest_signing_key_loaded: bool,
    pub evolution_manifest_signing_keys_count: usize,
    pub evolution_require_manifest_signature: bool,
    pub evolution_active_slot_signing_key_id: Option<String>,
    pub evolution_active_slot_signing_key_loaded: bool,
    pub evolution_require_signed_active_slot: bool,
    pub evolution_max_staged_manifest_age_secs: Option<u64>,
    pub evolution_max_consecutive_apply_failures: Option<u64>,
    pub evolution_lock_stale_after_secs: Option<u64>,
    pub evolution_auto_recover_stale_lock: bool,
    pub warnings: Vec<String>,
}

fn default_model(provider: &str) -> &'static str {
    match provider {
        "openai" => "gpt-4o-mini",
        "anthropic" => "claude-3-5-sonnet-latest",
        _ => "openrouter/qwen/qwen3-coder",
    }
}

fn resolve_api_key(provider: &str) -> Option<String> {
    let mut keys: Vec<&str> = vec!["RUSTY_PINCH_API_KEY"];

    match provider {
        "openai" => keys.extend([
            "RUSTY_PINCH_OPENAI_API_KEY",
            "OPENAI_API_KEY",
            "PICOCLAW_PROVIDERS_OPENAI_API_KEY",
        ]),
        "openrouter" => keys.extend([
            "RUSTY_PINCH_OPENROUTER_API_KEY",
            "OPENROUTER_API_KEY",
            "PICOCLAW_PROVIDERS_OPENROUTER_API_KEY",
        ]),
        "anthropic" => keys.extend([
            "RUSTY_PINCH_ANTHROPIC_API_KEY",
            "ANTHROPIC_API_KEY",
            "PICOCLAW_PROVIDERS_ANTHROPIC_API_KEY",
        ]),
        "groq" => keys.extend([
            "RUSTY_PINCH_GROQ_API_KEY",
            "GROQ_API_KEY",
            "PICOCLAW_PROVIDERS_GROQ_API_KEY",
        ]),
        _ => keys.extend([
            "OPENAI_API_KEY",
            "OPENROUTER_API_KEY",
            "ANTHROPIC_API_KEY",
            "PICOCLAW_PROVIDERS_OPENAI_API_KEY",
            "PICOCLAW_PROVIDERS_OPENROUTER_API_KEY",
            "PICOCLAW_PROVIDERS_ANTHROPIC_API_KEY",
        ]),
    }

    keys.into_iter().find_map(read_non_empty_env)
}

fn resolve_api_base(provider: &str) -> Option<String> {
    let mut keys: Vec<&str> = vec!["RUSTY_PINCH_API_BASE"];

    match provider {
        "openai" => keys.extend([
            "RUSTY_PINCH_OPENAI_API_BASE",
            "OPENAI_API_BASE",
            "PICOCLAW_PROVIDERS_OPENAI_API_BASE",
        ]),
        "openrouter" => keys.extend([
            "RUSTY_PINCH_OPENROUTER_API_BASE",
            "OPENROUTER_API_BASE",
            "PICOCLAW_PROVIDERS_OPENROUTER_API_BASE",
        ]),
        "groq" => keys.extend([
            "RUSTY_PINCH_GROQ_API_BASE",
            "GROQ_API_BASE",
            "PICOCLAW_PROVIDERS_GROQ_API_BASE",
        ]),
        _ => keys.extend([
            "RUSTY_PINCH_OPENAI_API_BASE",
            "RUSTY_PINCH_OPENROUTER_API_BASE",
            "OPENAI_API_BASE",
            "OPENROUTER_API_BASE",
            "PICOCLAW_PROVIDERS_OPENAI_API_BASE",
            "PICOCLAW_PROVIDERS_OPENROUTER_API_BASE",
        ]),
    }

    if let Some(base) = keys.into_iter().find_map(read_non_empty_env) {
        return Some(base.trim_end_matches('/').to_string());
    }

    match provider {
        "openai" => Some("https://api.openai.com/v1".to_string()),
        "openrouter" => Some("https://openrouter.ai/api/v1".to_string()),
        "groq" => Some("https://api.groq.com/openai/v1".to_string()),
        _ => None,
    }
}

fn load_codex_settings(default_model: &str) -> CodexSettings {
    let enabled = read_bool_env("RUSTY_PINCH_CODEX_ENABLED", false);
    let cli_bin = env::var("RUSTY_PINCH_CODEX_CLI_BIN")
        .unwrap_or_else(|_| "codex".to_string())
        .trim()
        .to_string();
    let cli_args = read_args_env("RUSTY_PINCH_CODEX_CLI_ARGS");
    let prompt_flag = env::var("RUSTY_PINCH_CODEX_PROMPT_FLAG")
        .unwrap_or_else(|_| "--prompt".to_string())
        .trim()
        .to_string();
    let model_flag = env::var("RUSTY_PINCH_CODEX_MODEL_FLAG")
        .unwrap_or_else(|_| "--model".to_string())
        .trim()
        .to_string();
    let timeout_secs = read_u64_env("RUSTY_PINCH_CODEX_TIMEOUT_SECS", 120);
    let queue_capacity = read_usize_env("RUSTY_PINCH_CODEX_QUEUE_CAPACITY", 256);
    let rate_limit_threshold_percent =
        read_u8_env("RUSTY_PINCH_CODEX_RATE_LIMIT_THRESHOLD_PERCENT", 25).clamp(1, 99);
    let rate_window_secs = read_u64_env("RUSTY_PINCH_CODEX_RATE_WINDOW_SECS", 3600).max(1);
    let healthcheck_interval_secs =
        read_u64_env("RUSTY_PINCH_CODEX_HEALTHCHECK_INTERVAL_SECS", 300).max(1);
    let healthcheck_args = {
        let values = read_args_env("RUSTY_PINCH_CODEX_HEALTHCHECK_ARGS");
        if values.is_empty() {
            vec!["--version".to_string()]
        } else {
            values
        }
    };
    let default_model = read_non_empty_env("RUSTY_PINCH_CODEX_MODEL")
        .or_else(|| Some(default_model.to_string()).filter(|v| !v.trim().is_empty()));
    let accounts = read_codex_accounts();

    CodexSettings {
        enabled,
        cli_bin,
        cli_args,
        prompt_flag,
        model_flag,
        timeout_secs,
        queue_capacity: queue_capacity.max(1),
        rate_limit_threshold_percent,
        rate_window_secs,
        healthcheck_interval_secs,
        healthcheck_args,
        default_model,
        accounts,
    }
}

fn load_pulse_settings() -> PulseSettings {
    let mut auto_allow_actions = read_csv_env("RUSTY_PINCH_PULSE_AUTO_ALLOW_ACTIONS")
        .into_iter()
        .map(|value| value.to_ascii_lowercase())
        .filter(|value| !value.trim().is_empty())
        .collect::<Vec<String>>();

    if auto_allow_actions.is_empty() {
        auto_allow_actions = vec![
            "deploy".to_string(),
            "restart".to_string(),
            "email".to_string(),
            "purchase".to_string(),
            "self-update".to_string(),
        ];
    }

    PulseSettings { auto_allow_actions }
}

fn load_evolution_settings() -> EvolutionSettings {
    let manifest_signing_key = read_non_empty_env("RUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEY");
    let manifest_signing_key_id =
        read_non_empty_env("RUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEY_ID")
            .or_else(|| manifest_signing_key.as_ref().map(|_| "default".to_string()));
    let mut manifest_signing_keys =
        read_manifest_signing_keys_env("RUSTY_PINCH_EVOLUTION_MANIFEST_SIGNING_KEYS");

    if let Some(key) = manifest_signing_key.as_ref() {
        let key_id = manifest_signing_key_id
            .as_ref()
            .cloned()
            .unwrap_or_else(|| "default".to_string());
        upsert_manifest_signing_key(&mut manifest_signing_keys, key_id, key.clone());
    }
    let active_slot_signing_key =
        read_non_empty_env("RUSTY_PINCH_EVOLUTION_ACTIVE_SLOT_SIGNING_KEY")
            .or_else(|| manifest_signing_key.clone());
    let active_slot_signing_key_id =
        read_non_empty_env("RUSTY_PINCH_EVOLUTION_ACTIVE_SLOT_SIGNING_KEY_ID")
            .or_else(|| manifest_signing_key_id.clone());

    EvolutionSettings {
        require_apply_confirm: read_bool_env("RUSTY_PINCH_EVOLUTION_REQUIRE_APPLY_CONFIRM", true),
        require_stage_artifact_sha256: read_bool_env(
            "RUSTY_PINCH_EVOLUTION_REQUIRE_STAGE_ARTIFACT_SHA256",
            false,
        ),
        require_verified_stage_artifact_sha256: read_bool_env(
            "RUSTY_PINCH_EVOLUTION_REQUIRE_VERIFIED_STAGE_ARTIFACT_SHA256",
            false,
        ),
        require_signed_checksum_manifest_provenance: read_bool_env(
            "RUSTY_PINCH_EVOLUTION_REQUIRE_SIGNED_CHECKSUM_MANIFEST_PROVENANCE",
            false,
        ),
        require_non_rollback_version: read_bool_env(
            "RUSTY_PINCH_EVOLUTION_REQUIRE_NON_ROLLBACK_VERSION",
            false,
        ),
        trusted_sha256sums_sha256: read_non_empty_env(
            "RUSTY_PINCH_EVOLUTION_TRUSTED_SHA256SUMS_SHA256",
        )
        .map(|value| value.to_ascii_lowercase()),
        trusted_sha256sums_ed25519_public_key: read_non_empty_env(
            "RUSTY_PINCH_EVOLUTION_TRUSTED_SHA256SUMS_ED25519_PUBLIC_KEY",
        ),
        require_sha256sums_signature: read_bool_env(
            "RUSTY_PINCH_EVOLUTION_REQUIRE_SHA256SUMS_SIGNATURE",
            false,
        ),
        manifest_signing_key_id,
        manifest_signing_key,
        manifest_signing_keys,
        require_manifest_signature: read_bool_env(
            "RUSTY_PINCH_EVOLUTION_REQUIRE_MANIFEST_SIGNATURE",
            false,
        ),
        active_slot_signing_key_id,
        active_slot_signing_key,
        require_signed_active_slot: read_bool_env(
            "RUSTY_PINCH_EVOLUTION_REQUIRE_SIGNED_ACTIVE_SLOT",
            false,
        ),
        max_staged_manifest_age_secs: Some(read_u64_env(
            "RUSTY_PINCH_EVOLUTION_MAX_STAGED_MANIFEST_AGE_SECS",
            86_400,
        ))
        .filter(|value| *value > 0),
        max_consecutive_apply_failures: Some(read_u64_env(
            "RUSTY_PINCH_EVOLUTION_MAX_CONSECUTIVE_APPLY_FAILURES",
            3,
        ))
        .filter(|value| *value > 0),
        lock_stale_after_secs: Some(read_u64_env(
            "RUSTY_PINCH_EVOLUTION_LOCK_STALE_AFTER_SECS",
            900,
        ))
        .filter(|value| *value > 0),
        auto_recover_stale_lock: read_bool_env(
            "RUSTY_PINCH_EVOLUTION_AUTO_RECOVER_STALE_LOCK",
            true,
        ),
    }
}

fn read_manifest_signing_keys_env(key: &str) -> Vec<(String, String)> {
    let Some(value) = env::var(key).ok() else {
        return Vec::new();
    };

    let mut keys = Vec::new();
    for entry in value.split(';') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut parts = trimmed.splitn(2, '|').map(str::trim);
        let key_id = parts.next().unwrap_or_default();
        let key_value = parts.next().unwrap_or_default();
        if key_id.is_empty() || key_value.is_empty() {
            continue;
        }
        upsert_manifest_signing_key(&mut keys, key_id.to_string(), key_value.to_string());
    }
    keys
}

fn upsert_manifest_signing_key(
    keys: &mut Vec<(String, String)>,
    key_id: String,
    key_value: String,
) {
    if let Some(existing) = keys
        .iter_mut()
        .find(|(id, _)| id.eq_ignore_ascii_case(key_id.as_str()))
    {
        *existing = (key_id, key_value);
    } else {
        keys.push((key_id, key_value));
    }
}

fn is_valid_ed25519_key_material(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return true;
    }

    base64_decoded_len(trimmed).is_some_and(|len| len == 32)
}

fn base64_decoded_len(value: &str) -> Option<usize> {
    decode_base64(value).map(|decoded| decoded.len()).ok()
}

fn decode_base64(value: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    use base64::engine::general_purpose;
    use base64::Engine as _;

    general_purpose::STANDARD
        .decode(value)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(value))
        .or_else(|_| general_purpose::URL_SAFE.decode(value))
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(value))
}

fn read_codex_accounts() -> Vec<CodexAccountSettings> {
    let default_max_requests = env::var("RUSTY_PINCH_CODEX_ACCOUNT_MAX_REQUESTS")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(200)
        .max(1);

    let Some(raw) = env::var("RUSTY_PINCH_CODEX_ACCOUNTS").ok() else {
        return vec![CodexAccountSettings {
            id: "default".to_string(),
            api_key_env: read_non_empty_env("RUSTY_PINCH_CODEX_ACCOUNT_API_KEY_ENV"),
            max_requests: default_max_requests,
            model: read_non_empty_env("RUSTY_PINCH_CODEX_ACCOUNT_MODEL"),
        }];
    };

    let mut accounts = Vec::new();
    for entry in raw.split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        let mut parts = entry.split('|').map(str::trim);
        let id = parts.next().unwrap_or_default();
        if id.is_empty() {
            continue;
        }

        let api_key_env = parts
            .next()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string);
        let max_requests = parts
            .next()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(default_max_requests)
            .max(1);
        let model = parts
            .next()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string);

        accounts.push(CodexAccountSettings {
            id: id.to_string(),
            api_key_env,
            max_requests,
            model,
        });
    }

    if accounts.is_empty() {
        accounts.push(CodexAccountSettings {
            id: "default".to_string(),
            api_key_env: read_non_empty_env("RUSTY_PINCH_CODEX_ACCOUNT_API_KEY_ENV"),
            max_requests: default_max_requests,
            model: read_non_empty_env("RUSTY_PINCH_CODEX_ACCOUNT_MODEL"),
        });
    }

    accounts
}

fn read_non_empty_env(key: &str) -> Option<String> {
    env::var(key).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn read_u64_env(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn read_usize_env(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn read_u8_env(key: &str, default: u8) -> u8 {
    env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u8>().ok())
        .unwrap_or(default)
}

fn read_bool_env(key: &str, default: bool) -> bool {
    let Some(value) = env::var(key).ok() else {
        return default;
    };
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => default,
    }
}

fn read_csv_env(key: &str) -> Vec<String> {
    let Some(value) = env::var(key).ok() else {
        return Vec::new();
    };

    value
        .split(',')
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .map(|part| part.to_string())
        .collect()
}

fn read_args_env(key: &str) -> Vec<String> {
    let Some(value) = env::var(key).ok() else {
        return Vec::new();
    };

    value
        .split_whitespace()
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn load_dotenv() -> Result<()> {
    if let Ok(path) = env::var(ENV_FILE_ENV) {
        if !path.trim().is_empty() {
            dotenvy::from_path(path.trim())
                .with_context(|| format!("failed loading {} from {}", ENV_FILE_ENV, path.trim()))?;
            return Ok(());
        }
    }

    if Path::new(".env").exists() {
        dotenvy::from_path(".env").context("failed loading .env from current directory")?;
    }

    Ok(())
}
