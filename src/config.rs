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
