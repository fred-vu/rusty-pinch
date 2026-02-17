use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};

const TELEMETRY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnRecord {
    pub timestamp: String,
    pub request_id: String,
    pub session_id: String,
    pub path: String,
    pub status: String,
    pub provider: String,
    pub model: String,
    pub tool_name: Option<String>,
    pub attempts: Option<u32>,
    pub latency_ms: Option<u64>,
    pub user_chars: usize,
    pub response_chars: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    pub schema_version: u32,
    pub updated_at: String,
    pub total_turns: u64,
    pub ok_turns: u64,
    pub error_turns: u64,
    pub provider_turns: u64,
    pub tool_turns: u64,
    pub total_provider_attempts: u64,
    pub last_turn: Option<TurnRecord>,
}

impl Default for TelemetrySnapshot {
    fn default() -> Self {
        Self {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            updated_at: Utc::now().to_rfc3339(),
            total_turns: 0,
            ok_turns: 0,
            error_turns: 0,
            provider_turns: 0,
            tool_turns: 0,
            total_provider_attempts: 0,
            last_turn: None,
        }
    }
}

pub struct TelemetryStore {
    path: PathBuf,
    snapshot: TelemetrySnapshot,
}

impl TelemetryStore {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let snapshot = load_snapshot(&path)?;
        Ok(Self { path, snapshot })
    }

    pub fn record_turn(&mut self, turn: TurnRecord) -> Result<()> {
        self.snapshot.schema_version = TELEMETRY_SCHEMA_VERSION;
        self.snapshot.updated_at = Utc::now().to_rfc3339();
        self.snapshot.total_turns = self.snapshot.total_turns.saturating_add(1);

        if turn.status == "ok" {
            self.snapshot.ok_turns = self.snapshot.ok_turns.saturating_add(1);
        } else {
            self.snapshot.error_turns = self.snapshot.error_turns.saturating_add(1);
        }

        match turn.path.as_str() {
            "tool" => {
                self.snapshot.tool_turns = self.snapshot.tool_turns.saturating_add(1);
            }
            _ => {
                self.snapshot.provider_turns = self.snapshot.provider_turns.saturating_add(1);
            }
        }

        if let Some(attempts) = turn.attempts {
            self.snapshot.total_provider_attempts = self
                .snapshot
                .total_provider_attempts
                .saturating_add(u64::from(attempts));
        }

        self.snapshot.last_turn = Some(turn);
        self.persist()
    }

    pub fn snapshot(&self) -> TelemetrySnapshot {
        self.snapshot.clone()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn persist(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed creating telemetry dir {}", parent.display()))?;
        }

        let payload = serde_json::to_string_pretty(&self.snapshot)
            .context("failed encoding telemetry snapshot")?;
        let tmp_path = self.path.with_extension("tmp");

        fs::write(&tmp_path, payload).with_context(|| {
            format!(
                "failed writing temporary telemetry file {}",
                tmp_path.display()
            )
        })?;
        fs::rename(&tmp_path, &self.path).with_context(|| {
            format!(
                "failed moving telemetry snapshot {} -> {}",
                tmp_path.display(),
                self.path.display()
            )
        })?;

        Ok(())
    }
}

fn load_snapshot(path: &Path) -> Result<TelemetrySnapshot> {
    if !path.exists() {
        return Ok(TelemetrySnapshot::default());
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed reading telemetry file {}", path.display()))?;
    let mut snapshot: TelemetrySnapshot = serde_json::from_str(&raw)
        .with_context(|| format!("failed decoding telemetry file {}", path.display()))?;

    if snapshot.schema_version == 0 {
        snapshot.schema_version = TELEMETRY_SCHEMA_VERSION;
    }
    if snapshot.updated_at.trim().is_empty() {
        snapshot.updated_at = Utc::now().to_rfc3339();
    }

    Ok(snapshot)
}
