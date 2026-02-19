use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::codex::CodexStatus;
use crate::evolution::{
    BlueGreenApplyReport, EvolutionActiveSlotIntegrityReport, EvolutionApplyFailureCircuitReport,
    SkillEvolutionReport,
};
use crate::pulse::PulseStatus;

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
pub struct CodexTelemetry {
    pub updated_at: String,
    pub enabled: bool,
    pub accounts_total: usize,
    pub accounts_healthy: usize,
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub queue_mode_reason: Option<String>,
    pub rate_limit_threshold_percent: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PulseTelemetry {
    pub updated_at: String,
    pub jobs_total: usize,
    pub jobs_enabled: usize,
    pub jobs_disabled: usize,
    pub pending_approvals: usize,
    pub goals_total: usize,
    pub goals_achieved: usize,
    pub last_tick_executed_jobs: Option<usize>,
    pub last_tick_error_jobs: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionTelemetry {
    pub updated_at: String,
    pub last_skill_name: Option<String>,
    pub last_skill_status: Option<String>,
    pub last_apply_status: Option<String>,
    pub last_apply_from_slot: Option<String>,
    pub last_apply_to_slot: Option<String>,
    pub rollback_performed: Option<bool>,
    pub healthcheck_ok: Option<bool>,
    pub healthcheck_timed_out: Option<bool>,
    pub healthcheck_timeout_secs: Option<u64>,
    pub healthcheck_exit_code: Option<i32>,
    pub manifest_path: Option<String>,
    pub active_slot_integrity_status: Option<String>,
    pub active_slot_integrity_message: Option<String>,
    pub active_slot_signature_present: Option<bool>,
    pub active_slot_signature_verified: Option<bool>,
    pub active_slot_require_signed: Option<bool>,
    pub apply_failure_consecutive: Option<u64>,
    pub apply_failure_threshold: Option<u64>,
    pub apply_failure_circuit_open: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TelemetrySnapshot {
    pub schema_version: u32,
    pub updated_at: String,
    pub total_turns: u64,
    pub ok_turns: u64,
    pub error_turns: u64,
    pub provider_turns: u64,
    pub tool_turns: u64,
    pub skill_turns: u64,
    pub total_provider_attempts: u64,
    pub codex: Option<CodexTelemetry>,
    pub pulse: Option<PulseTelemetry>,
    pub evolution: Option<EvolutionTelemetry>,
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
            skill_turns: 0,
            total_provider_attempts: 0,
            codex: None,
            pulse: None,
            evolution: None,
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
            "skill" => {
                self.snapshot.skill_turns = self.snapshot.skill_turns.saturating_add(1);
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

    pub fn record_codex_status(&mut self, status: &CodexStatus) -> Result<()> {
        let healthy = status
            .accounts
            .iter()
            .filter(|account| account.healthy)
            .count();
        self.snapshot.schema_version = TELEMETRY_SCHEMA_VERSION;
        self.snapshot.updated_at = Utc::now().to_rfc3339();
        self.snapshot.codex = Some(CodexTelemetry {
            updated_at: Utc::now().to_rfc3339(),
            enabled: status.enabled,
            accounts_total: status.accounts.len(),
            accounts_healthy: healthy,
            queue_depth: status.queue_depth,
            queue_capacity: status.queue_capacity,
            queue_mode_reason: status.queue_mode_reason.clone(),
            rate_limit_threshold_percent: status.rate_limit_threshold_percent,
        });
        self.persist()
    }

    pub fn record_pulse_status(&mut self, status: &PulseStatus) -> Result<()> {
        self.update_pulse_snapshot(status, None)
    }

    pub fn record_pulse_tick(
        &mut self,
        status: &PulseStatus,
        executed_jobs: usize,
        error_jobs: usize,
    ) -> Result<()> {
        self.update_pulse_snapshot(status, Some((executed_jobs, error_jobs)))
    }

    pub fn record_evolution_skill(&mut self, report: &SkillEvolutionReport) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let mut evo = self
            .snapshot
            .evolution
            .clone()
            .unwrap_or(EvolutionTelemetry {
                updated_at: now.clone(),
                last_skill_name: None,
                last_skill_status: None,
                last_apply_status: None,
                last_apply_from_slot: None,
                last_apply_to_slot: None,
                rollback_performed: None,
                healthcheck_ok: None,
                healthcheck_timed_out: None,
                healthcheck_timeout_secs: None,
                healthcheck_exit_code: None,
                manifest_path: None,
                active_slot_integrity_status: None,
                active_slot_integrity_message: None,
                active_slot_signature_present: None,
                active_slot_signature_verified: None,
                active_slot_require_signed: None,
                apply_failure_consecutive: None,
                apply_failure_threshold: None,
                apply_failure_circuit_open: None,
            });
        evo.updated_at = now.clone();
        evo.last_skill_name = Some(report.skill_name.clone());
        evo.last_skill_status = Some(report.status.clone());

        self.snapshot.schema_version = TELEMETRY_SCHEMA_VERSION;
        self.snapshot.updated_at = now;
        self.snapshot.evolution = Some(evo);
        self.persist()
    }

    pub fn record_evolution_apply(&mut self, report: &BlueGreenApplyReport) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let mut evo = self
            .snapshot
            .evolution
            .clone()
            .unwrap_or(EvolutionTelemetry {
                updated_at: now.clone(),
                last_skill_name: None,
                last_skill_status: None,
                last_apply_status: None,
                last_apply_from_slot: None,
                last_apply_to_slot: None,
                rollback_performed: None,
                healthcheck_ok: None,
                healthcheck_timed_out: None,
                healthcheck_timeout_secs: None,
                healthcheck_exit_code: None,
                manifest_path: None,
                active_slot_integrity_status: None,
                active_slot_integrity_message: None,
                active_slot_signature_present: None,
                active_slot_signature_verified: None,
                active_slot_require_signed: None,
                apply_failure_consecutive: None,
                apply_failure_threshold: None,
                apply_failure_circuit_open: None,
            });
        evo.updated_at = now.clone();
        evo.last_apply_status = Some(report.status.clone());
        evo.last_apply_from_slot = Some(report.from_slot.clone());
        evo.last_apply_to_slot = Some(report.to_slot.clone());
        evo.rollback_performed = Some(report.rollback_performed);
        evo.healthcheck_ok = Some(report.healthcheck_ok);
        evo.healthcheck_timed_out = Some(report.healthcheck_timed_out);
        evo.healthcheck_timeout_secs = Some(report.healthcheck_timeout_secs);
        evo.healthcheck_exit_code = report.healthcheck_exit_code;
        evo.manifest_path = Some(report.manifest_path.clone());

        self.snapshot.schema_version = TELEMETRY_SCHEMA_VERSION;
        self.snapshot.updated_at = now;
        self.snapshot.evolution = Some(evo);
        self.persist()
    }

    pub fn record_evolution_active_slot_integrity(
        &mut self,
        report: &EvolutionActiveSlotIntegrityReport,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let mut evo = self
            .snapshot
            .evolution
            .clone()
            .unwrap_or(EvolutionTelemetry {
                updated_at: now.clone(),
                last_skill_name: None,
                last_skill_status: None,
                last_apply_status: None,
                last_apply_from_slot: None,
                last_apply_to_slot: None,
                rollback_performed: None,
                healthcheck_ok: None,
                healthcheck_timed_out: None,
                healthcheck_timeout_secs: None,
                healthcheck_exit_code: None,
                manifest_path: None,
                active_slot_integrity_status: None,
                active_slot_integrity_message: None,
                active_slot_signature_present: None,
                active_slot_signature_verified: None,
                active_slot_require_signed: None,
                apply_failure_consecutive: None,
                apply_failure_threshold: None,
                apply_failure_circuit_open: None,
            });
        evo.updated_at = now.clone();
        evo.active_slot_integrity_status = Some(report.status.clone());
        evo.active_slot_integrity_message = report.message.clone();
        evo.active_slot_signature_present = Some(report.signature_present);
        evo.active_slot_signature_verified = report.signature_verified;
        evo.active_slot_require_signed = Some(report.require_signed);

        self.snapshot.schema_version = TELEMETRY_SCHEMA_VERSION;
        self.snapshot.updated_at = now;
        self.snapshot.evolution = Some(evo);
        self.persist()
    }

    pub fn record_evolution_failure_circuit(
        &mut self,
        report: &EvolutionApplyFailureCircuitReport,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let mut evo = self
            .snapshot
            .evolution
            .clone()
            .unwrap_or(EvolutionTelemetry {
                updated_at: now.clone(),
                last_skill_name: None,
                last_skill_status: None,
                last_apply_status: None,
                last_apply_from_slot: None,
                last_apply_to_slot: None,
                rollback_performed: None,
                healthcheck_ok: None,
                healthcheck_timed_out: None,
                healthcheck_timeout_secs: None,
                healthcheck_exit_code: None,
                manifest_path: None,
                active_slot_integrity_status: None,
                active_slot_integrity_message: None,
                active_slot_signature_present: None,
                active_slot_signature_verified: None,
                active_slot_require_signed: None,
                apply_failure_consecutive: None,
                apply_failure_threshold: None,
                apply_failure_circuit_open: None,
            });
        evo.updated_at = now.clone();
        evo.apply_failure_consecutive = Some(report.consecutive_failures);
        evo.apply_failure_threshold = report.threshold;
        evo.apply_failure_circuit_open = Some(report.circuit_open);

        self.snapshot.schema_version = TELEMETRY_SCHEMA_VERSION;
        self.snapshot.updated_at = now;
        self.snapshot.evolution = Some(evo);
        self.persist()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn update_pulse_snapshot(
        &mut self,
        status: &PulseStatus,
        tick_result: Option<(usize, usize)>,
    ) -> Result<()> {
        let jobs_total = status.jobs.len();
        let jobs_enabled = status.jobs.iter().filter(|job| job.enabled).count();
        let goals_total = status.goals.len();
        let goals_achieved = status.goals.iter().filter(|goal| goal.achieved).count();
        let previous = self.snapshot.pulse.clone();
        let (last_tick_executed_jobs, last_tick_error_jobs) = tick_result.unwrap_or_else(|| {
            previous
                .as_ref()
                .map(|pulse| {
                    (
                        pulse.last_tick_executed_jobs.unwrap_or(0),
                        pulse.last_tick_error_jobs.unwrap_or(0),
                    )
                })
                .unwrap_or((0, 0))
        });

        let now = Utc::now().to_rfc3339();
        self.snapshot.schema_version = TELEMETRY_SCHEMA_VERSION;
        self.snapshot.updated_at = now.clone();
        self.snapshot.pulse = Some(PulseTelemetry {
            updated_at: now,
            jobs_total,
            jobs_enabled,
            jobs_disabled: jobs_total.saturating_sub(jobs_enabled),
            pending_approvals: status.pending_approvals.len(),
            goals_total,
            goals_achieved,
            last_tick_executed_jobs: Some(last_tick_executed_jobs),
            last_tick_error_jobs: Some(last_tick_error_jobs),
        });
        self.persist()
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

#[cfg(test)]
mod tests {
    use super::TelemetryStore;
    use crate::codex::{CodexAccountSnapshot, CodexStatus};
    use crate::evolution::{
        BlueGreenApplyReport, EvolutionActiveSlotIntegrityReport,
        EvolutionApplyFailureCircuitReport,
    };
    use crate::pulse::{
        GoalSnapshot, PendingApproval, PulseAction, PulseJobSnapshot, PulseStatus, RiskLevel,
    };

    #[test]
    fn record_codex_status_persists_snapshot() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("telemetry").join("latest.json");
        let mut telemetry = TelemetryStore::new(&path).expect("telemetry");

        let status = CodexStatus {
            enabled: true,
            queue_depth: 2,
            queue_capacity: 10,
            queue_mode_reason: Some("rate_limit_guard".to_string()),
            rate_limit_threshold_percent: 25,
            accounts: vec![
                CodexAccountSnapshot {
                    id: "a1".to_string(),
                    healthy: true,
                    used_requests: 10,
                    max_requests: 100,
                    remaining_percent: 90,
                    model: Some("m1".to_string()),
                    api_key_env: Some("KEY1".to_string()),
                    last_error: None,
                    last_healthcheck_at: Some("2025-01-01T00:00:00Z".to_string()),
                },
                CodexAccountSnapshot {
                    id: "a2".to_string(),
                    healthy: false,
                    used_requests: 95,
                    max_requests: 100,
                    remaining_percent: 5,
                    model: Some("m2".to_string()),
                    api_key_env: Some("KEY2".to_string()),
                    last_error: Some("unhealthy".to_string()),
                    last_healthcheck_at: Some("2025-01-01T00:00:00Z".to_string()),
                },
            ],
        };

        telemetry
            .record_codex_status(&status)
            .expect("record codex status");
        let snapshot = telemetry.snapshot();

        let codex = snapshot.codex.expect("codex metrics");
        assert_eq!(codex.accounts_total, 2);
        assert_eq!(codex.accounts_healthy, 1);
        assert_eq!(codex.queue_depth, 2);
        assert_eq!(codex.queue_capacity, 10);
    }

    #[test]
    fn record_pulse_tick_persists_snapshot() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("telemetry").join("latest.json");
        let mut telemetry = TelemetryStore::new(&path).expect("telemetry");

        let status = PulseStatus {
            jobs: vec![
                PulseJobSnapshot {
                    id: "j1".to_string(),
                    interval_secs: 60,
                    action: PulseAction::EmitLog {
                        message: "ok".to_string(),
                    },
                    enabled: true,
                    runs: 1,
                    next_due_at: "2025-01-01T00:00:00Z".to_string(),
                    last_run_at: None,
                    last_status: Some("ok".to_string()),
                    last_message: None,
                },
                PulseJobSnapshot {
                    id: "j2".to_string(),
                    interval_secs: 60,
                    action: PulseAction::EmitLog {
                        message: "ok".to_string(),
                    },
                    enabled: false,
                    runs: 0,
                    next_due_at: "2025-01-01T00:00:00Z".to_string(),
                    last_run_at: None,
                    last_status: None,
                    last_message: None,
                },
            ],
            pending_approvals: vec![PendingApproval {
                token: "pa-1".to_string(),
                action: "deploy".to_string(),
                risk: RiskLevel::High,
                reason: "approval".to_string(),
                created_at: "2025-01-01T00:00:00Z".to_string(),
                status: crate::pulse::ApprovalStatus::Pending,
            }],
            goals: vec![GoalSnapshot {
                id: "g1".to_string(),
                description: "keep healthy".to_string(),
                achieved: true,
                updated_at: "2025-01-01T00:00:00Z".to_string(),
                notes: None,
            }],
        };

        telemetry
            .record_pulse_tick(&status, 3, 1)
            .expect("record pulse status");
        let snapshot = telemetry.snapshot();
        let pulse = snapshot.pulse.expect("pulse metrics");
        assert_eq!(pulse.jobs_total, 2);
        assert_eq!(pulse.jobs_enabled, 1);
        assert_eq!(pulse.jobs_disabled, 1);
        assert_eq!(pulse.pending_approvals, 1);
        assert_eq!(pulse.goals_total, 1);
        assert_eq!(pulse.goals_achieved, 1);
        assert_eq!(pulse.last_tick_executed_jobs, Some(3));
        assert_eq!(pulse.last_tick_error_jobs, Some(1));
    }

    #[test]
    fn record_evolution_apply_persists_snapshot() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("telemetry").join("latest.json");
        let mut telemetry = TelemetryStore::new(&path).expect("telemetry");

        let report = BlueGreenApplyReport {
            status: "rolled_back".to_string(),
            from_slot: "blue".to_string(),
            to_slot: "green".to_string(),
            rollback_performed: true,
            healthcheck_ok: false,
            healthcheck_timed_out: true,
            healthcheck_timeout_secs: 10,
            healthcheck_exit_code: Some(137),
            healthcheck_stdout: String::new(),
            healthcheck_stderr: String::new(),
            manifest_path: "/tmp/manifest.json".to_string(),
        };
        telemetry
            .record_evolution_apply(&report)
            .expect("record evolution apply");

        let snapshot = telemetry.snapshot();
        let evolution = snapshot.evolution.expect("evolution metrics");
        assert_eq!(evolution.last_apply_status.as_deref(), Some("rolled_back"));
        assert_eq!(evolution.rollback_performed, Some(true));
        assert_eq!(evolution.healthcheck_timed_out, Some(true));
        assert_eq!(
            evolution.manifest_path.as_deref(),
            Some("/tmp/manifest.json")
        );
    }

    #[test]
    fn record_evolution_active_slot_integrity_persists_snapshot() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("telemetry").join("latest.json");
        let mut telemetry = TelemetryStore::new(&path).expect("telemetry");

        let report = EvolutionActiveSlotIntegrityReport {
            marker_path: "/tmp/active-slot".to_string(),
            signature_path: "/tmp/active-slot.sig".to_string(),
            marker_exists: true,
            slot: Some("green".to_string()),
            signature_present: true,
            signature_verified: Some(false),
            status: "signature_invalid".to_string(),
            message: Some("active-slot signature mismatch".to_string()),
            require_signed: true,
            key_loaded: true,
            key_id: Some("ops-2026".to_string()),
        };
        telemetry
            .record_evolution_active_slot_integrity(&report)
            .expect("record evolution active-slot integrity");

        let snapshot = telemetry.snapshot();
        let evolution = snapshot.evolution.expect("evolution metrics");
        assert_eq!(
            evolution.active_slot_integrity_status.as_deref(),
            Some("signature_invalid")
        );
        assert_eq!(evolution.active_slot_signature_verified, Some(false));
        assert_eq!(evolution.active_slot_require_signed, Some(true));
    }

    #[test]
    fn record_evolution_failure_circuit_persists_snapshot() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("telemetry").join("latest.json");
        let mut telemetry = TelemetryStore::new(&path).expect("telemetry");

        let report = EvolutionApplyFailureCircuitReport {
            circuit_path: "/tmp/apply-failure-circuit.json".to_string(),
            state_exists: true,
            threshold: Some(3),
            consecutive_failures: 3,
            circuit_open: true,
            last_failure_at: Some("2026-02-19T00:00:00Z".to_string()),
            last_failure_status: Some("rolled_back".to_string()),
            last_failure_error: Some(
                "post-stage health check failed; rollback performed".to_string(),
            ),
            last_success_at: None,
            last_reset_at: None,
        };
        telemetry
            .record_evolution_failure_circuit(&report)
            .expect("record evolution failure circuit");

        let snapshot = telemetry.snapshot();
        let evolution = snapshot.evolution.expect("evolution metrics");
        assert_eq!(evolution.apply_failure_consecutive, Some(3));
        assert_eq!(evolution.apply_failure_threshold, Some(3));
        assert_eq!(evolution.apply_failure_circuit_open, Some(true));
    }
}
