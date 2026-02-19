use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::skills::SkillManager;

#[derive(Debug, Clone, Serialize)]
pub struct SkillEvolutionReport {
    pub skill_name: String,
    pub staged_path: String,
    pub promoted_path: Option<String>,
    pub status: String,
    pub validation_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueGreenUpdatePlan {
    pub current_binary: String,
    pub artifact_binary: String,
    pub updates_root: String,
    pub active_slot: String,
    pub passive_slot: String,
    pub passive_binary_path: String,
    pub manifest_path: String,
    pub rollback_binary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecksumManifestProvenance {
    pub checksum_manifest_path: String,
    pub checksum_manifest_sha256: String,
    pub checksum_manifest_signature_path: Option<String>,
    pub checksum_manifest_signature_verified: bool,
}

#[derive(Debug, Clone)]
pub struct ResolvedArtifactChecksumFromSums {
    pub artifact_sha256: String,
    pub checksum_manifest: ChecksumManifestProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlueGreenStagedManifest {
    pub timestamp: String,
    pub status: String,
    pub active_slot: String,
    pub passive_slot: String,
    pub apply_started_at: Option<String>,
    pub apply_from_slot: Option<String>,
    pub apply_to_slot: Option<String>,
    pub apply_resume_count: Option<u64>,
    pub last_recovery_note: Option<String>,
    pub last_observed_active_slot: Option<String>,
    pub current_binary_version: Option<String>,
    pub artifact_binary_version: Option<String>,
    pub checksum_manifest_path: Option<String>,
    pub checksum_manifest_sha256: Option<String>,
    pub checksum_manifest_signature_path: Option<String>,
    pub checksum_manifest_signature_verified: Option<bool>,
    pub artifact_binary_path: Option<String>,
    pub artifact_binary_sha256: Option<String>,
    pub artifact_checksum_verified: Option<bool>,
    pub passive_binary_path: String,
    pub passive_binary_sha256: Option<String>,
    pub manifest_signature: Option<String>,
    pub manifest_signature_key_id: Option<String>,
    pub manifest_signature_algorithm: Option<String>,
    pub rollback_binary: String,
    pub healthcheck_stdout: Option<String>,
    pub healthcheck_stderr: Option<String>,
    pub healthcheck_exit_code: Option<i32>,
    pub healthcheck_timed_out: Option<bool>,
    pub healthcheck_timeout_secs: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlueGreenApplyReport {
    pub status: String,
    pub from_slot: String,
    pub to_slot: String,
    pub rollback_performed: bool,
    pub healthcheck_ok: bool,
    pub healthcheck_timed_out: bool,
    pub healthcheck_timeout_secs: u64,
    pub healthcheck_exit_code: Option<i32>,
    pub healthcheck_stdout: String,
    pub healthcheck_stderr: String,
    pub manifest_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvolutionAuditVerifyReport {
    pub audit_log_path: String,
    pub entries: usize,
    pub last_hash: Option<String>,
    pub valid: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvolutionRecoveryStatusReport {
    pub manifest_path: String,
    pub manifest_exists: bool,
    pub manifest_timestamp: Option<String>,
    pub manifest_age_secs: Option<u64>,
    pub manifest_max_age_secs: Option<u64>,
    pub manifest_expired: bool,
    pub manifest_status: Option<String>,
    pub apply_started_at: Option<String>,
    pub apply_from_slot: Option<String>,
    pub apply_to_slot: Option<String>,
    pub apply_resume_count: u64,
    pub last_recovery_note: Option<String>,
    pub last_observed_active_slot: Option<String>,
    pub active_slot_marker: Option<String>,
    pub active_slot_integrity_status: String,
    pub active_slot_integrity_message: Option<String>,
    pub active_slot_signature_present: bool,
    pub active_slot_signature_verified: Option<bool>,
    pub apply_failure_threshold: Option<u64>,
    pub apply_failure_consecutive: u64,
    pub apply_failure_circuit_open: bool,
    pub drift_detected: bool,
    pub recommendation: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvolutionActiveSlotIntegrityReport {
    pub marker_path: String,
    pub signature_path: String,
    pub marker_exists: bool,
    pub slot: Option<String>,
    pub signature_present: bool,
    pub signature_verified: Option<bool>,
    pub status: String,
    pub message: Option<String>,
    pub require_signed: bool,
    pub key_loaded: bool,
    pub key_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvolutionLockStatusReport {
    pub lock_path: String,
    pub lock_exists: bool,
    pub operation: Option<String>,
    pub pid: Option<u32>,
    pub started_at: Option<String>,
    pub age_secs: Option<u64>,
    pub stale: Option<bool>,
    pub stale_after_secs: Option<u64>,
    pub auto_recover_stale_lock: bool,
    pub force_unlocked: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvolutionApplyFailureCircuitReport {
    pub circuit_path: String,
    pub state_exists: bool,
    pub threshold: Option<u64>,
    pub consecutive_failures: u64,
    pub circuit_open: bool,
    pub last_failure_at: Option<String>,
    pub last_failure_status: Option<String>,
    pub last_failure_error: Option<String>,
    pub last_success_at: Option<String>,
    pub last_reset_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvolutionAuditRecord {
    pub timestamp: String,
    pub event: String,
    pub status: String,
    pub manifest_path: String,
    pub active_slot: String,
    pub passive_slot: String,
    pub current_binary_version: Option<String>,
    pub artifact_binary_version: Option<String>,
    pub checksum_manifest_sha256: Option<String>,
    pub checksum_manifest_signature_verified: Option<bool>,
    pub artifact_binary_sha256: Option<String>,
    pub artifact_checksum_verified: Option<bool>,
    pub manifest_signature_key_id: Option<String>,
    pub apply_started_at: Option<String>,
    pub apply_from_slot: Option<String>,
    pub apply_to_slot: Option<String>,
    pub apply_resume_count: Option<u64>,
    pub last_recovery_note: Option<String>,
    pub last_observed_active_slot: Option<String>,
    pub rollback_performed: Option<bool>,
    pub healthcheck_ok: Option<bool>,
    pub healthcheck_timed_out: Option<bool>,
    pub error: Option<String>,
    pub prev_hash: Option<String>,
    pub hash: String,
}

#[derive(Debug)]
struct EvolutionAuditParams<'a> {
    event: &'a str,
    status: &'a str,
    manifest_path: &'a Path,
    manifest: &'a BlueGreenStagedManifest,
    rollback_performed: Option<bool>,
    healthcheck_ok: Option<bool>,
    healthcheck_timed_out: Option<bool>,
    error: Option<String>,
}

#[derive(Debug)]
struct EvolutionOperationLock {
    path: PathBuf,
}

#[derive(Debug, Clone)]
struct ParsedEvolutionLock {
    operation: Option<String>,
    pid: Option<u32>,
    started_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActiveSlotSignatureEnvelope {
    pub slot: String,
    pub signature: String,
    pub signature_algorithm: String,
    pub signature_key_id: Option<String>,
    pub signed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct EvolutionApplyFailureCircuitState {
    pub consecutive_failures: u64,
    pub circuit_open: bool,
    pub last_failure_at: Option<String>,
    pub last_failure_status: Option<String>,
    pub last_failure_error: Option<String>,
    pub last_success_at: Option<String>,
    pub last_reset_at: Option<String>,
}

impl EvolutionOperationLock {
    fn acquire(
        updates_root: &Path,
        operation: &str,
        stale_after_secs: Option<u64>,
        auto_recover_stale_lock: bool,
    ) -> Result<Self> {
        let path = updates_root.join("evolution.lock");
        let stale_after = stale_after_secs.filter(|value| *value > 0);

        for attempt in 0..2 {
            let mut file = match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => file,
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                    let snapshot = inspect_lock_file(&path, stale_after)?;
                    let stale = snapshot.stale.unwrap_or(false);
                    if attempt == 0 && auto_recover_stale_lock && stale {
                        fs::remove_file(&path).with_context(|| {
                            format!("failed removing stale evolution lock {}", path.display())
                        })?;
                        eprintln!(
                            "{{\"event\":\"evolution_lock_recovered\",\"lock\":\"{}\",\"age_secs\":{},\"stale_after_secs\":{}}}",
                            path.display(),
                            snapshot.age_secs.unwrap_or(0),
                            stale_after.unwrap_or(0)
                        );
                        continue;
                    }

                    let holder = format_lock_owner(&snapshot.parsed_lock);
                    let mut message = if holder.trim().is_empty() {
                        format!(
                            "another evolution operation is already in progress (lock: {})",
                            path.display()
                        )
                    } else {
                        format!(
                            "another evolution operation is already in progress: {} (lock: {})",
                            holder,
                            path.display()
                        )
                    };
                    if stale {
                        message.push_str(
                            ". lock appears stale; re-run with evolution force-unlock --confirm",
                        );
                    }
                    return Err(anyhow!(message));
                }
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("failed creating evolution lock {}", path.display())
                    });
                }
            };

            let details = format!(
                "operation={} pid={} started_at={}",
                operation.trim(),
                std::process::id(),
                Utc::now().to_rfc3339()
            );
            file.write_all(details.as_bytes())
                .with_context(|| format!("failed writing evolution lock {}", path.display()))?;

            return Ok(Self { path });
        }

        Err(anyhow!(
            "failed acquiring evolution operation lock {}",
            path.display()
        ))
    }
}

#[derive(Debug, Clone)]
struct LockInspection {
    parsed_lock: Option<ParsedEvolutionLock>,
    age_secs: Option<u64>,
    stale: Option<bool>,
}

fn inspect_lock_file(path: &Path, stale_after_secs: Option<u64>) -> Result<LockInspection> {
    if !path.exists() {
        return Ok(LockInspection {
            parsed_lock: None,
            age_secs: None,
            stale: None,
        });
    }

    let parsed_lock = read_lock_file(path)?;
    let age_secs = compute_lock_age_secs(path, parsed_lock.as_ref())?;
    let stale = stale_after_secs.map(|threshold| age_secs.unwrap_or(0) >= threshold);

    Ok(LockInspection {
        parsed_lock,
        age_secs,
        stale,
    })
}

fn compute_lock_age_secs(path: &Path, parsed: Option<&ParsedEvolutionLock>) -> Result<Option<u64>> {
    if let Some(started_at) = parsed.and_then(|value| value.started_at.as_deref()) {
        if let Ok(parsed_started_at) = chrono::DateTime::parse_from_rfc3339(started_at) {
            let parsed_started_at = parsed_started_at.with_timezone(&Utc);
            let now = Utc::now();
            if now >= parsed_started_at {
                let secs = (now - parsed_started_at).num_seconds();
                return Ok(Some(secs.max(0) as u64));
            }
        }
    }

    let metadata = fs::metadata(path)
        .with_context(|| format!("failed reading evolution lock metadata {}", path.display()))?;
    let modified = metadata.modified().unwrap_or_else(|_| SystemTime::now());
    let age = SystemTime::now()
        .duration_since(modified)
        .unwrap_or_default()
        .as_secs();
    Ok(Some(age))
}

fn read_lock_file(path: &Path) -> Result<Option<ParsedEvolutionLock>> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed reading evolution lock {}", path.display()))?;
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }

    let mut operation = None;
    let mut pid = None;
    let mut started_at = None;
    for token in raw.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        match key {
            "operation" => {
                if !value.trim().is_empty() {
                    operation = Some(value.trim().to_string());
                }
            }
            "pid" => {
                if let Ok(parsed) = value.trim().parse::<u32>() {
                    pid = Some(parsed);
                }
            }
            "started_at" => {
                if !value.trim().is_empty() {
                    started_at = Some(value.trim().to_string());
                }
            }
            _ => {}
        }
    }

    Ok(Some(ParsedEvolutionLock {
        operation,
        pid,
        started_at,
    }))
}

fn format_lock_owner(parsed_lock: &Option<ParsedEvolutionLock>) -> String {
    let Some(parsed_lock) = parsed_lock else {
        return String::new();
    };

    let mut parts = Vec::new();
    if let Some(operation) = parsed_lock.operation.as_deref() {
        parts.push(format!("operation={}", operation));
    }
    if let Some(pid) = parsed_lock.pid {
        parts.push(format!("pid={}", pid));
    }
    if let Some(started_at) = parsed_lock.started_at.as_deref() {
        parts.push(format!("started_at={}", started_at));
    }

    parts.join(" ")
}

impl Drop for EvolutionOperationLock {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.path) {
            if err.kind() != ErrorKind::NotFound {
                eprintln!(
                    "{{\"event\":\"evolution_lock_release_error\",\"message\":\"{}\"}}",
                    err
                );
            }
        }
    }
}

pub struct EvolutionManager {
    workspace: PathBuf,
    staging_dir: PathBuf,
    updates_root: PathBuf,
    lock_stale_after_secs: Option<u64>,
    auto_recover_stale_lock: bool,
    max_staged_manifest_age_secs: Option<u64>,
    max_consecutive_apply_failures: Option<u64>,
    active_slot_signing_key_id: Option<String>,
    active_slot_signing_key: Option<String>,
    require_signed_active_slot: bool,
}

impl EvolutionManager {
    pub fn new(workspace: impl AsRef<Path>) -> Result<Self> {
        let workspace = workspace.as_ref().to_path_buf();
        let staging_dir = workspace.join("skills").join("staging");
        let updates_root = workspace.join("updates");

        fs::create_dir_all(&staging_dir)
            .with_context(|| format!("failed creating {}", staging_dir.display()))?;
        fs::create_dir_all(&updates_root)
            .with_context(|| format!("failed creating {}", updates_root.display()))?;
        fs::create_dir_all(updates_root.join("blue"))
            .with_context(|| format!("failed creating {}", updates_root.join("blue").display()))?;
        fs::create_dir_all(updates_root.join("green"))
            .with_context(|| format!("failed creating {}", updates_root.join("green").display()))?;

        Ok(Self {
            workspace,
            staging_dir,
            updates_root,
            lock_stale_after_secs: Some(900),
            auto_recover_stale_lock: true,
            max_staged_manifest_age_secs: Some(86_400),
            max_consecutive_apply_failures: Some(3),
            active_slot_signing_key_id: None,
            active_slot_signing_key: None,
            require_signed_active_slot: false,
        })
    }

    pub fn with_lock_policy(
        mut self,
        lock_stale_after_secs: Option<u64>,
        auto_recover_stale_lock: bool,
    ) -> Self {
        self.lock_stale_after_secs = lock_stale_after_secs.filter(|value| *value > 0);
        self.auto_recover_stale_lock = auto_recover_stale_lock;
        self
    }

    pub fn with_apply_failure_policy(
        mut self,
        max_consecutive_apply_failures: Option<u64>,
    ) -> Self {
        self.max_consecutive_apply_failures =
            max_consecutive_apply_failures.filter(|value| *value > 0);
        self
    }

    pub fn with_staged_manifest_age_policy(
        mut self,
        max_staged_manifest_age_secs: Option<u64>,
    ) -> Self {
        self.max_staged_manifest_age_secs = max_staged_manifest_age_secs.filter(|value| *value > 0);
        self
    }

    pub fn with_active_slot_signing_policy(
        mut self,
        key_id: Option<&str>,
        key: Option<&str>,
        require_signed_active_slot: bool,
    ) -> Self {
        self.active_slot_signing_key_id = key_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        self.active_slot_signing_key = key
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        self.require_signed_active_slot = require_signed_active_slot;
        self
    }

    fn audit_log_path(&self) -> PathBuf {
        self.updates_root.join("evolution-audit.jsonl")
    }

    fn append_audit_record_safe(&self, params: EvolutionAuditParams<'_>) {
        if let Err(err) = self.append_audit_record(params) {
            eprintln!(
                "{{\"event\":\"evolution_audit_error\",\"message\":\"{}\"}}",
                err
            );
        }
    }

    fn append_audit_record(&self, params: EvolutionAuditParams<'_>) -> Result<()> {
        let path = self.audit_log_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed creating audit dir {}", parent.display()))?;
        }

        let prev_hash = read_last_audit_hash(&path)?;
        let mut record = EvolutionAuditRecord {
            timestamp: Utc::now().to_rfc3339(),
            event: params.event.to_string(),
            status: params.status.to_string(),
            manifest_path: params.manifest_path.display().to_string(),
            active_slot: params.manifest.active_slot.clone(),
            passive_slot: params.manifest.passive_slot.clone(),
            current_binary_version: params.manifest.current_binary_version.clone(),
            artifact_binary_version: params.manifest.artifact_binary_version.clone(),
            checksum_manifest_sha256: params.manifest.checksum_manifest_sha256.clone(),
            checksum_manifest_signature_verified: params
                .manifest
                .checksum_manifest_signature_verified,
            artifact_binary_sha256: params.manifest.artifact_binary_sha256.clone(),
            artifact_checksum_verified: params.manifest.artifact_checksum_verified,
            manifest_signature_key_id: params.manifest.manifest_signature_key_id.clone(),
            apply_started_at: params.manifest.apply_started_at.clone(),
            apply_from_slot: params.manifest.apply_from_slot.clone(),
            apply_to_slot: params.manifest.apply_to_slot.clone(),
            apply_resume_count: params.manifest.apply_resume_count,
            last_recovery_note: params.manifest.last_recovery_note.clone(),
            last_observed_active_slot: params.manifest.last_observed_active_slot.clone(),
            rollback_performed: params.rollback_performed,
            healthcheck_ok: params.healthcheck_ok,
            healthcheck_timed_out: params.healthcheck_timed_out,
            error: params.error,
            prev_hash,
            hash: String::new(),
        };
        record.hash = compute_audit_record_hash(&record);

        let line = serde_json::to_string(&record).context("failed encoding evolution audit")?;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("failed opening evolution audit log {}", path.display()))?;
        file.write_all(line.as_bytes())
            .with_context(|| format!("failed writing evolution audit log {}", path.display()))?;
        file.write_all(b"\n")
            .with_context(|| format!("failed finalizing evolution audit log {}", path.display()))?;
        Ok(())
    }

    pub fn verify_audit_log(&self) -> Result<EvolutionAuditVerifyReport> {
        let path = self.audit_log_path();
        if !path.exists() {
            return Ok(EvolutionAuditVerifyReport {
                audit_log_path: path.display().to_string(),
                entries: 0,
                last_hash: None,
                valid: true,
            });
        }

        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed reading evolution audit log {}", path.display()))?;
        let mut entries = 0usize;
        let mut expected_prev_hash: Option<String> = None;
        let mut last_hash = None;

        for (idx, line) in raw.lines().enumerate() {
            let line_no = idx + 1;
            if line.trim().is_empty() {
                continue;
            }
            let record: EvolutionAuditRecord = serde_json::from_str(line).with_context(|| {
                format!(
                    "failed decoding evolution audit record at line {} in {}",
                    line_no,
                    path.display()
                )
            })?;
            let record_hash = normalize_audit_hash(&record.hash)
                .with_context(|| format!("invalid audit hash at line {}", line_no))?;
            let computed_hash = compute_audit_record_hash(&record);
            if computed_hash != record_hash {
                return Err(anyhow!("audit hash mismatch at line {}", line_no));
            }

            let prev_hash = normalize_optional_audit_hash(record.prev_hash.as_deref())
                .with_context(|| format!("invalid audit prev_hash at line {}", line_no))?;
            match expected_prev_hash.as_deref() {
                None if prev_hash.is_some() => {
                    return Err(anyhow!(
                        "audit chain prev_hash mismatch at line {}",
                        line_no
                    ));
                }
                Some(expected) if prev_hash.as_deref() != Some(expected) => {
                    return Err(anyhow!(
                        "audit chain prev_hash mismatch at line {}",
                        line_no
                    ));
                }
                _ => {}
            }

            expected_prev_hash = Some(record_hash.clone());
            last_hash = Some(record_hash);
            entries += 1;
        }

        Ok(EvolutionAuditVerifyReport {
            audit_log_path: path.display().to_string(),
            entries,
            last_hash,
            valid: true,
        })
    }

    pub fn lock_status(&self) -> Result<EvolutionLockStatusReport> {
        let path = self.updates_root.join("evolution.lock");
        let stale_after = self.lock_stale_after_secs;
        let inspection = inspect_lock_file(&path, stale_after)?;
        let parsed = inspection.parsed_lock;
        Ok(EvolutionLockStatusReport {
            lock_path: path.display().to_string(),
            lock_exists: path.exists(),
            operation: parsed.as_ref().and_then(|value| value.operation.clone()),
            pid: parsed.as_ref().and_then(|value| value.pid),
            started_at: parsed.as_ref().and_then(|value| value.started_at.clone()),
            age_secs: inspection.age_secs,
            stale: inspection.stale,
            stale_after_secs: stale_after,
            auto_recover_stale_lock: self.auto_recover_stale_lock,
            force_unlocked: false,
        })
    }

    pub fn force_unlock(&self) -> Result<EvolutionLockStatusReport> {
        let path = self.updates_root.join("evolution.lock");
        let stale_after = self.lock_stale_after_secs;
        let inspection = inspect_lock_file(&path, stale_after)?;
        let parsed = inspection.parsed_lock;

        let mut force_unlocked = false;
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("failed removing evolution lock {}", path.display()))?;
            force_unlocked = true;
        }

        Ok(EvolutionLockStatusReport {
            lock_path: path.display().to_string(),
            lock_exists: false,
            operation: parsed.as_ref().and_then(|value| value.operation.clone()),
            pid: parsed.as_ref().and_then(|value| value.pid),
            started_at: parsed.as_ref().and_then(|value| value.started_at.clone()),
            age_secs: inspection.age_secs,
            stale: inspection.stale,
            stale_after_secs: stale_after,
            auto_recover_stale_lock: self.auto_recover_stale_lock,
            force_unlocked,
        })
    }

    fn apply_failure_circuit_path(&self) -> PathBuf {
        self.updates_root.join("apply-failure-circuit.json")
    }

    pub fn apply_failure_circuit_status(&self) -> Result<EvolutionApplyFailureCircuitReport> {
        let path = self.apply_failure_circuit_path();
        let state_exists = path.exists();
        let state = read_apply_failure_circuit_state(&path)?;
        Ok(build_apply_failure_circuit_report(
            &path,
            state_exists,
            self.max_consecutive_apply_failures,
            &state,
        ))
    }

    pub fn reset_apply_failure_circuit(&self) -> Result<EvolutionApplyFailureCircuitReport> {
        let path = self.apply_failure_circuit_path();
        let mut state = read_apply_failure_circuit_state(&path)?;
        state.consecutive_failures = 0;
        state.circuit_open = false;
        state.last_reset_at = Some(Utc::now().to_rfc3339());
        write_apply_failure_circuit_state(&path, &state)?;
        self.apply_failure_circuit_status()
    }

    fn ensure_apply_failure_circuit_closed(&self) -> Result<()> {
        let report = self.apply_failure_circuit_status()?;
        if !report.circuit_open {
            return Ok(());
        }

        let threshold = report
            .threshold
            .map(|value| value.to_string())
            .unwrap_or_else(|| "disabled".to_string());
        Err(anyhow!(
            "evolution apply is blocked by failure circuit after {} consecutive failures (threshold {}). Inspect with 'evolution failure-circuit-status' and reset with 'evolution failure-circuit-reset --confirm' after remediation",
            report.consecutive_failures,
            threshold
        ))
    }

    fn record_apply_failure_safe(&self, status: &str, error: &str) {
        if let Err(err) = self.record_apply_failure(status, error) {
            eprintln!(
                "{{\"event\":\"evolution_failure_circuit_error\",\"message\":\"{}\"}}",
                err
            );
        }
    }

    fn record_apply_failure(
        &self,
        status: &str,
        error: &str,
    ) -> Result<EvolutionApplyFailureCircuitReport> {
        let path = self.apply_failure_circuit_path();
        let mut state = read_apply_failure_circuit_state(&path)?;
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        state.last_failure_at = Some(Utc::now().to_rfc3339());
        state.last_failure_status = Some(status.trim().to_string());
        state.last_failure_error = Some(error.trim().to_string());
        state.circuit_open = self
            .max_consecutive_apply_failures
            .is_some_and(|value| state.consecutive_failures >= value);
        write_apply_failure_circuit_state(&path, &state)?;
        self.apply_failure_circuit_status()
    }

    fn record_apply_success_safe(&self) {
        if let Err(err) = self.record_apply_success() {
            eprintln!(
                "{{\"event\":\"evolution_failure_circuit_error\",\"message\":\"{}\"}}",
                err
            );
        }
    }

    fn record_apply_success(&self) -> Result<EvolutionApplyFailureCircuitReport> {
        let path = self.apply_failure_circuit_path();
        let mut state = read_apply_failure_circuit_state(&path)?;
        state.consecutive_failures = 0;
        state.circuit_open = false;
        state.last_success_at = Some(Utc::now().to_rfc3339());
        write_apply_failure_circuit_state(&path, &state)?;
        self.apply_failure_circuit_status()
    }

    pub fn active_slot_integrity_status(&self) -> Result<EvolutionActiveSlotIntegrityReport> {
        let marker_path = self.updates_root.join("active-slot");
        inspect_active_slot_integrity(
            &marker_path,
            self.active_slot_signing_key_id.as_deref(),
            self.active_slot_signing_key.as_deref(),
            self.require_signed_active_slot,
        )
    }

    pub fn recovery_status(&self) -> Result<EvolutionRecoveryStatusReport> {
        let manifest_path = self.updates_root.join("blue-green-staged.json");
        let active_slot_integrity = self.active_slot_integrity_status()?;
        let failure_circuit = self.apply_failure_circuit_status()?;
        let active_slot_marker = active_slot_integrity.slot.clone();
        let manifest_max_age_secs = self.max_staged_manifest_age_secs;

        let Some(manifest) = read_manifest_if_exists(&manifest_path)? else {
            let recommendation = if failure_circuit.circuit_open {
                Some(
                    "apply failure circuit is open; inspect evolution failure-circuit-status and reset with evolution failure-circuit-reset --confirm after remediation"
                        .to_string(),
                )
            } else {
                Some("no staged update manifest found".to_string())
            };
            return Ok(EvolutionRecoveryStatusReport {
                manifest_path: manifest_path.display().to_string(),
                manifest_exists: false,
                manifest_timestamp: None,
                manifest_age_secs: None,
                manifest_max_age_secs,
                manifest_expired: false,
                manifest_status: None,
                apply_started_at: None,
                apply_from_slot: None,
                apply_to_slot: None,
                apply_resume_count: 0,
                last_recovery_note: None,
                last_observed_active_slot: None,
                active_slot_marker,
                active_slot_integrity_status: active_slot_integrity.status,
                active_slot_integrity_message: active_slot_integrity.message,
                active_slot_signature_present: active_slot_integrity.signature_present,
                active_slot_signature_verified: active_slot_integrity.signature_verified,
                apply_failure_threshold: failure_circuit.threshold,
                apply_failure_consecutive: failure_circuit.consecutive_failures,
                apply_failure_circuit_open: failure_circuit.circuit_open,
                drift_detected: false,
                recommendation,
            });
        };

        let (manifest_age_secs, manifest_expired) =
            inspect_staged_manifest_freshness(&manifest, manifest_max_age_secs);
        let drift_detected = detect_recovery_drift(&manifest, active_slot_marker.as_deref());
        let mut recommendation =
            build_recovery_recommendation(&manifest, active_slot_marker.as_deref(), drift_detected);
        if manifest_expired {
            recommendation = Some(build_expired_manifest_recommendation(
                manifest_age_secs,
                manifest_max_age_secs,
            ));
        }
        if failure_circuit.circuit_open {
            recommendation = Some(
                "apply failure circuit is open; inspect evolution failure-circuit-status and reset with evolution failure-circuit-reset --confirm after remediation"
                    .to_string(),
            );
        }

        Ok(EvolutionRecoveryStatusReport {
            manifest_path: manifest_path.display().to_string(),
            manifest_exists: true,
            manifest_timestamp: Some(manifest.timestamp.clone()),
            manifest_age_secs,
            manifest_max_age_secs,
            manifest_expired,
            manifest_status: Some(manifest.status.clone()),
            apply_started_at: manifest.apply_started_at.clone(),
            apply_from_slot: manifest.apply_from_slot.clone(),
            apply_to_slot: manifest.apply_to_slot.clone(),
            apply_resume_count: manifest.apply_resume_count.unwrap_or(0),
            last_recovery_note: manifest.last_recovery_note.clone(),
            last_observed_active_slot: manifest.last_observed_active_slot.clone(),
            active_slot_marker,
            active_slot_integrity_status: active_slot_integrity.status,
            active_slot_integrity_message: active_slot_integrity.message,
            active_slot_signature_present: active_slot_integrity.signature_present,
            active_slot_signature_verified: active_slot_integrity.signature_verified,
            apply_failure_threshold: failure_circuit.threshold,
            apply_failure_consecutive: failure_circuit.consecutive_failures,
            apply_failure_circuit_open: failure_circuit.circuit_open,
            drift_detected,
            recommendation,
        })
    }

    pub fn stage_and_promote_skill(
        &self,
        skills: &SkillManager,
        skill_name: &str,
        script: &str,
    ) -> Result<SkillEvolutionReport> {
        let skill_name = normalize_skill_name(skill_name)?;
        if script.trim().is_empty() {
            return Err(anyhow!("generated skill script is empty"));
        }

        let staged_path = self.staging_dir.join(format!(
            "{}-{}.rhai",
            skill_name,
            Utc::now().format("%Y%m%d%H%M%S")
        ));
        fs::write(&staged_path, script)
            .with_context(|| format!("failed writing {}", staged_path.display()))?;

        match skills.dry_run_source(script) {
            Ok(()) => {
                let promoted = skills
                    .write_skill(&skill_name, script)
                    .with_context(|| format!("failed promoting skill '{}'", skill_name))?;
                Ok(SkillEvolutionReport {
                    skill_name,
                    staged_path: staged_path.display().to_string(),
                    promoted_path: Some(promoted.display().to_string()),
                    status: "promoted".to_string(),
                    validation_error: None,
                })
            }
            Err(err) => Ok(SkillEvolutionReport {
                skill_name,
                staged_path: staged_path.display().to_string(),
                promoted_path: None,
                status: "validation_failed".to_string(),
                validation_error: Some(err.to_string()),
            }),
        }
    }

    pub fn plan_blue_green_update(
        &self,
        current_binary: impl AsRef<Path>,
        artifact_binary: impl AsRef<Path>,
    ) -> Result<BlueGreenUpdatePlan> {
        let current_binary = current_binary.as_ref().to_path_buf();
        let artifact_binary = artifact_binary.as_ref().to_path_buf();
        if !artifact_binary.exists() {
            return Err(anyhow!(
                "artifact binary does not exist: {}",
                artifact_binary.display()
            ));
        }

        let active_marker = self.updates_root.join("active-slot");
        let active_slot_integrity = inspect_active_slot_integrity(
            &active_marker,
            self.active_slot_signing_key_id.as_deref(),
            self.active_slot_signing_key.as_deref(),
            self.require_signed_active_slot,
        )?;
        enforce_active_slot_integrity_for_operation(&active_slot_integrity, "stage-update")?;
        let active_slot = active_slot_integrity
            .slot
            .unwrap_or_else(|| "blue".to_string());
        let passive_slot = if active_slot == "blue" {
            "green"
        } else {
            "blue"
        }
        .to_string();
        let passive_binary_path = self.updates_root.join(&passive_slot).join("rusty-pinch");
        let manifest_path = self.updates_root.join("blue-green-staged.json");

        Ok(BlueGreenUpdatePlan {
            current_binary: current_binary.display().to_string(),
            artifact_binary: artifact_binary.display().to_string(),
            updates_root: self.updates_root.display().to_string(),
            active_slot,
            passive_slot,
            passive_binary_path: passive_binary_path.display().to_string(),
            manifest_path: manifest_path.display().to_string(),
            rollback_binary: current_binary.display().to_string(),
        })
    }

    pub fn resolve_artifact_sha256_from_sums(
        &self,
        artifact_path: &Path,
        sums_path: &Path,
        entry_name: Option<&str>,
        trusted_sums_sha256: Option<&str>,
        sums_signature_path: Option<&Path>,
        trusted_sums_ed25519_public_key: Option<&str>,
        require_sums_signature: bool,
    ) -> Result<String> {
        let resolved = self.resolve_artifact_sha256_from_sums_with_provenance(
            artifact_path,
            sums_path,
            entry_name,
            trusted_sums_sha256,
            sums_signature_path,
            trusted_sums_ed25519_public_key,
            require_sums_signature,
        )?;
        Ok(resolved.artifact_sha256)
    }

    pub fn resolve_artifact_sha256_from_sums_with_provenance(
        &self,
        artifact_path: &Path,
        sums_path: &Path,
        entry_name: Option<&str>,
        trusted_sums_sha256: Option<&str>,
        sums_signature_path: Option<&Path>,
        trusted_sums_ed25519_public_key: Option<&str>,
        require_sums_signature: bool,
    ) -> Result<ResolvedArtifactChecksumFromSums> {
        if !artifact_path.exists() {
            return Err(anyhow!(
                "artifact binary does not exist: {}",
                artifact_path.display()
            ));
        }
        if !sums_path.exists() {
            return Err(anyhow!(
                "checksum manifest does not exist: {}",
                sums_path.display()
            ));
        }

        let sums_sha256 = compute_sha256_hex(sums_path)?;
        if let Some(expected) = trusted_sums_sha256 {
            let expected = normalize_sha256_hex(expected)?;
            if sums_sha256 != expected {
                return Err(anyhow!(
                    "checksum manifest SHA-256 mismatch (expected {}, got {})",
                    expected,
                    sums_sha256
                ));
            }
        }

        if require_sums_signature && sums_signature_path.is_none() {
            return Err(anyhow!(
                "checksum manifest signature is required by policy. Re-run with --artifact-sha256-sums-signature-file or set RUSTY_PINCH_EVOLUTION_REQUIRE_SHA256SUMS_SIGNATURE=false"
            ));
        }

        let mut signature_verified = false;
        if let Some(signature_path) = sums_signature_path {
            verify_checksum_manifest_signature(
                sums_path,
                signature_path,
                trusted_sums_ed25519_public_key,
            )?;
            signature_verified = true;
        }

        let raw = fs::read_to_string(sums_path)
            .with_context(|| format!("failed reading checksum manifest {}", sums_path.display()))?;
        let artifact_basename = artifact_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow!("artifact path has no valid filename"))?;
        let entry_name = entry_name
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(artifact_basename);

        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((hash, name)) = parse_sha256sum_line(line) else {
                continue;
            };

            if checksum_entry_matches(name, entry_name, artifact_basename) {
                let artifact_sha256 = normalize_sha256_hex(hash)?;
                return Ok(ResolvedArtifactChecksumFromSums {
                    artifact_sha256,
                    checksum_manifest: ChecksumManifestProvenance {
                        checksum_manifest_path: sums_path.display().to_string(),
                        checksum_manifest_sha256: sums_sha256,
                        checksum_manifest_signature_path: sums_signature_path
                            .map(|path| path.display().to_string()),
                        checksum_manifest_signature_verified: signature_verified,
                    },
                });
            }
        }

        Err(anyhow!(
            "artifact entry '{}' not found in checksum manifest {}",
            entry_name,
            sums_path.display()
        ))
    }

    pub fn stage_blue_green_update(
        &self,
        plan: &BlueGreenUpdatePlan,
        manifest_signing_key_id: Option<&str>,
        manifest_signing_key: Option<&str>,
        expected_artifact_sha256: Option<&str>,
        checksum_manifest_provenance: Option<ChecksumManifestProvenance>,
        current_version: Option<&str>,
        artifact_version: Option<&str>,
        require_non_rollback_version: bool,
    ) -> Result<()> {
        let _operation_lock = EvolutionOperationLock::acquire(
            &self.updates_root,
            "stage-update",
            self.lock_stale_after_secs,
            self.auto_recover_stale_lock,
        )?;
        let manifest_path = Path::new(&plan.manifest_path);
        if let Some(existing_manifest) = read_manifest_if_exists(manifest_path)? {
            if is_apply_in_progress_status(&existing_manifest.status) {
                return Err(anyhow!(
                    "cannot stage while an apply operation is in progress (manifest status '{}'); re-run evolution apply-staged-update first",
                    existing_manifest.status
                ));
            }
        }

        let artifact = PathBuf::from(&plan.artifact_binary);
        let artifact_sha256 = compute_sha256_hex(&artifact)?;
        verify_artifact_sha256(expected_artifact_sha256, &artifact_sha256)?;
        let (current_binary_version, artifact_binary_version) = normalize_update_versions(
            current_version,
            artifact_version,
            require_non_rollback_version,
        )?;

        let passive_binary = PathBuf::from(&plan.passive_binary_path);
        if let Some(parent) = passive_binary.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed creating {}", parent.display()))?;
        }

        fs::copy(&artifact, &passive_binary).with_context(|| {
            format!(
                "failed copying staged artifact {} -> {}",
                artifact.display(),
                passive_binary.display()
            )
        })?;
        let permissions = fs::metadata(&artifact)
            .with_context(|| format!("failed reading artifact metadata {}", artifact.display()))?
            .permissions();
        fs::set_permissions(&passive_binary, permissions).with_context(|| {
            format!(
                "failed setting permissions on staged passive binary {}",
                passive_binary.display()
            )
        })?;
        let passive_binary_sha256 = compute_sha256_hex(&passive_binary)?;

        let mut manifest = BlueGreenStagedManifest {
            timestamp: Utc::now().to_rfc3339(),
            status: "staged".to_string(),
            active_slot: plan.active_slot.clone(),
            passive_slot: plan.passive_slot.clone(),
            apply_started_at: None,
            apply_from_slot: None,
            apply_to_slot: None,
            apply_resume_count: None,
            last_recovery_note: None,
            last_observed_active_slot: None,
            current_binary_version,
            artifact_binary_version,
            checksum_manifest_path: checksum_manifest_provenance
                .as_ref()
                .map(|value| value.checksum_manifest_path.clone()),
            checksum_manifest_sha256: checksum_manifest_provenance
                .as_ref()
                .map(|value| value.checksum_manifest_sha256.clone()),
            checksum_manifest_signature_path: checksum_manifest_provenance
                .as_ref()
                .and_then(|value| value.checksum_manifest_signature_path.clone()),
            checksum_manifest_signature_verified: checksum_manifest_provenance
                .as_ref()
                .map(|value| value.checksum_manifest_signature_verified),
            artifact_binary_path: Some(plan.artifact_binary.clone()),
            artifact_binary_sha256: Some(artifact_sha256),
            artifact_checksum_verified: Some(expected_artifact_sha256.is_some()),
            passive_binary_path: plan.passive_binary_path.clone(),
            passive_binary_sha256: Some(passive_binary_sha256),
            manifest_signature: None,
            manifest_signature_key_id: None,
            manifest_signature_algorithm: None,
            rollback_binary: plan.rollback_binary.clone(),
            healthcheck_stdout: None,
            healthcheck_stderr: None,
            healthcheck_exit_code: None,
            healthcheck_timed_out: None,
            healthcheck_timeout_secs: None,
            error: None,
        };
        if let Some(signing_key) = normalized_signing_key(manifest_signing_key) {
            let signing_key_id =
                normalized_signing_key_id(manifest_signing_key_id).unwrap_or("default");
            manifest.manifest_signature_key_id = Some(signing_key_id.to_string());
            manifest.manifest_signature_algorithm = Some("hmac-sha256".to_string());
            manifest.manifest_signature =
                Some(compute_manifest_signature_hex(&manifest, signing_key)?);
        }
        write_manifest(manifest_path, &manifest)?;
        self.append_audit_record_safe(EvolutionAuditParams {
            event: "stage",
            status: "staged",
            manifest_path,
            manifest: &manifest,
            rollback_performed: None,
            healthcheck_ok: None,
            healthcheck_timed_out: None,
            error: None,
        });

        Ok(())
    }

    pub fn apply_staged_update(
        &self,
        healthcheck_args: &[String],
        healthcheck_timeout_secs: u64,
        manifest_signing_keys: &[(String, String)],
        require_manifest_signature: bool,
        require_verified_stage_artifact_sha256: bool,
        require_signed_checksum_manifest_provenance: bool,
        trusted_checksum_manifest_sha256: Option<&str>,
        trusted_checksum_manifest_ed25519_public_key: Option<&str>,
        require_non_rollback_version: bool,
    ) -> Result<BlueGreenApplyReport> {
        let _operation_lock = EvolutionOperationLock::acquire(
            &self.updates_root,
            "apply-staged-update",
            self.lock_stale_after_secs,
            self.auto_recover_stale_lock,
        )?;
        self.ensure_apply_failure_circuit_closed()?;
        let manifest_path = self.updates_root.join("blue-green-staged.json");
        let active_slot_path = self.updates_root.join("active-slot");
        let mut manifest = read_manifest(&manifest_path)?;
        if is_apply_terminal_status(&manifest.status) {
            return build_apply_report_from_manifest(&manifest_path, &manifest);
        }
        if manifest.status != "staged" && !is_apply_in_progress_status(&manifest.status) {
            return Err(anyhow!(
                "no staged update available (manifest status '{}')",
                manifest.status
            ));
        }
        let resumed_from_status = if is_apply_in_progress_status(&manifest.status) {
            Some(manifest.status.clone())
        } else {
            None
        };
        if let Some(previous_status) = resumed_from_status.as_deref() {
            let resume_count = manifest.apply_resume_count.unwrap_or(0).saturating_add(1);
            manifest.apply_resume_count = Some(resume_count);
            manifest.last_recovery_note = Some(format!(
                "resumed apply invocation from '{}'",
                previous_status
            ));
        }

        if manifest.status == "staged" {
            if let Err(err) =
                verify_staged_manifest_freshness(&manifest, self.max_staged_manifest_age_secs)
            {
                let message = err.to_string();
                manifest.status = "stale_failed".to_string();
                manifest.error = Some(message.clone());
                write_manifest(&manifest_path, &manifest)?;
                self.append_audit_record_safe(EvolutionAuditParams {
                    event: "apply",
                    status: "stale_failed",
                    manifest_path: &manifest_path,
                    manifest: &manifest,
                    rollback_performed: None,
                    healthcheck_ok: None,
                    healthcheck_timed_out: None,
                    error: Some(message.clone()),
                });
                self.record_apply_failure_safe("stale_failed", &message);
                return Err(anyhow!(message));
            }
            if let Err(err) =
                verify_staged_artifact_provenance(&manifest, require_verified_stage_artifact_sha256)
            {
                let message = err.to_string();
                manifest.timestamp = Utc::now().to_rfc3339();
                manifest.status = "provenance_failed".to_string();
                manifest.error = Some(message.clone());
                write_manifest(&manifest_path, &manifest)?;
                self.append_audit_record_safe(EvolutionAuditParams {
                    event: "apply",
                    status: "provenance_failed",
                    manifest_path: &manifest_path,
                    manifest: &manifest,
                    rollback_performed: None,
                    healthcheck_ok: None,
                    healthcheck_timed_out: None,
                    error: Some(message.clone()),
                });
                self.record_apply_failure_safe("provenance_failed", &message);
                return Err(anyhow!(message));
            }
            if let Err(err) = verify_signed_checksum_manifest_provenance(
                &manifest,
                require_signed_checksum_manifest_provenance,
                trusted_checksum_manifest_sha256,
                trusted_checksum_manifest_ed25519_public_key,
            ) {
                let message = err.to_string();
                manifest.timestamp = Utc::now().to_rfc3339();
                manifest.status = "checksum_provenance_failed".to_string();
                manifest.error = Some(message.clone());
                write_manifest(&manifest_path, &manifest)?;
                self.append_audit_record_safe(EvolutionAuditParams {
                    event: "apply",
                    status: "checksum_provenance_failed",
                    manifest_path: &manifest_path,
                    manifest: &manifest,
                    rollback_performed: None,
                    healthcheck_ok: None,
                    healthcheck_timed_out: None,
                    error: Some(message.clone()),
                });
                self.record_apply_failure_safe("checksum_provenance_failed", &message);
                return Err(anyhow!(message));
            }
            if let Err(err) =
                verify_non_rollback_update_version(&manifest, require_non_rollback_version)
            {
                let message = err.to_string();
                manifest.timestamp = Utc::now().to_rfc3339();
                manifest.status = "version_failed".to_string();
                manifest.error = Some(message.clone());
                write_manifest(&manifest_path, &manifest)?;
                self.append_audit_record_safe(EvolutionAuditParams {
                    event: "apply",
                    status: "version_failed",
                    manifest_path: &manifest_path,
                    manifest: &manifest,
                    rollback_performed: None,
                    healthcheck_ok: None,
                    healthcheck_timed_out: None,
                    error: Some(message.clone()),
                });
                self.record_apply_failure_safe("version_failed", &message);
                return Err(anyhow!(message));
            }
            if let Err(err) = verify_manifest_signature(
                &manifest,
                manifest_signing_keys,
                require_manifest_signature,
            ) {
                let message = err.to_string();
                manifest.timestamp = Utc::now().to_rfc3339();
                manifest.status = "signature_failed".to_string();
                manifest.error = Some(message.clone());
                write_manifest(&manifest_path, &manifest)?;
                self.append_audit_record_safe(EvolutionAuditParams {
                    event: "apply",
                    status: "signature_failed",
                    manifest_path: &manifest_path,
                    manifest: &manifest,
                    rollback_performed: None,
                    healthcheck_ok: None,
                    healthcheck_timed_out: None,
                    error: Some(message.clone()),
                });
                self.record_apply_failure_safe("signature_failed", &message);
                return Err(anyhow!(message));
            }
            if let Err(err) = verify_staged_binary_integrity(
                Path::new(&manifest.passive_binary_path),
                manifest.passive_binary_sha256.as_deref(),
            ) {
                let message = err.to_string();
                manifest.timestamp = Utc::now().to_rfc3339();
                manifest.status = "integrity_failed".to_string();
                manifest.error = Some(message.clone());
                write_manifest(&manifest_path, &manifest)?;
                self.append_audit_record_safe(EvolutionAuditParams {
                    event: "apply",
                    status: "integrity_failed",
                    manifest_path: &manifest_path,
                    manifest: &manifest,
                    rollback_performed: None,
                    healthcheck_ok: None,
                    healthcheck_timed_out: None,
                    error: Some(message.clone()),
                });
                self.record_apply_failure_safe("integrity_failed", &message);
                return Err(anyhow!(message));
            }

            manifest.timestamp = Utc::now().to_rfc3339();
            manifest.status = "applying".to_string();
            manifest.apply_started_at = Some(manifest.timestamp.clone());
            manifest.apply_from_slot = Some(manifest.active_slot.clone());
            manifest.apply_to_slot = Some(manifest.passive_slot.clone());
            manifest.apply_resume_count = Some(0);
            manifest.last_recovery_note = None;
            manifest.last_observed_active_slot = None;
            manifest.error = None;
            manifest.healthcheck_stdout = None;
            manifest.healthcheck_stderr = None;
            manifest.healthcheck_exit_code = None;
            manifest.healthcheck_timed_out = None;
            manifest.healthcheck_timeout_secs = None;
            write_manifest(&manifest_path, &manifest)?;
            self.append_audit_record_safe(EvolutionAuditParams {
                event: "apply",
                status: "applying",
                manifest_path: &manifest_path,
                manifest: &manifest,
                rollback_performed: None,
                healthcheck_ok: None,
                healthcheck_timed_out: None,
                error: None,
            });
        }

        let previous_slot = manifest
            .apply_from_slot
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(manifest.active_slot.as_str())
            .to_string();
        let next_slot = manifest
            .apply_to_slot
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(manifest.passive_slot.as_str())
            .to_string();
        manifest.apply_from_slot = Some(previous_slot.clone());
        manifest.apply_to_slot = Some(next_slot.clone());
        if manifest.apply_started_at.is_none() {
            manifest.apply_started_at = Some(Utc::now().to_rfc3339());
        }

        if manifest.status == "applying" {
            let active_slot = read_active_slot_marker_with_integrity(
                &active_slot_path,
                self.active_slot_signing_key_id.as_deref(),
                self.active_slot_signing_key.as_deref(),
                self.require_signed_active_slot,
                "apply-staged-update",
            )?
            .unwrap_or_else(|| previous_slot.clone());
            manifest.last_observed_active_slot = Some(active_slot.clone());
            if active_slot != next_slot {
                if active_slot != previous_slot {
                    let message = format!(
                        "active slot marker '{}' conflicts with apply state (expected '{}' or '{}')",
                        active_slot, previous_slot, next_slot
                    );
                    manifest.timestamp = Utc::now().to_rfc3339();
                    manifest.status = "state_failed".to_string();
                    manifest.error = Some(message.clone());
                    manifest.last_recovery_note = Some(message.clone());
                    write_manifest(&manifest_path, &manifest)?;
                    self.append_audit_record_safe(EvolutionAuditParams {
                        event: "apply",
                        status: "state_failed",
                        manifest_path: &manifest_path,
                        manifest: &manifest,
                        rollback_performed: None,
                        healthcheck_ok: None,
                        healthcheck_timed_out: None,
                        error: Some(message.clone()),
                    });
                    self.record_apply_failure_safe("state_failed", &message);
                    return Err(anyhow!(message));
                }
                write_active_slot_marker(
                    &active_slot_path,
                    &next_slot,
                    self.active_slot_signing_key_id.as_deref(),
                    self.active_slot_signing_key.as_deref(),
                    self.require_signed_active_slot,
                )?;
                if resumed_from_status.is_some() {
                    manifest.last_recovery_note = Some(
                        "resumed apply by restoring target active slot before healthcheck"
                            .to_string(),
                    );
                }
            }

            manifest.timestamp = Utc::now().to_rfc3339();
            manifest.status = "healthcheck_pending".to_string();
            manifest.error = None;
            write_manifest(&manifest_path, &manifest)?;
            self.append_audit_record_safe(EvolutionAuditParams {
                event: "apply",
                status: "healthcheck_pending",
                manifest_path: &manifest_path,
                manifest: &manifest,
                rollback_performed: None,
                healthcheck_ok: None,
                healthcheck_timed_out: None,
                error: None,
            });
        }

        if manifest.status == "healthcheck_pending" {
            let active_slot = read_active_slot_marker_with_integrity(
                &active_slot_path,
                self.active_slot_signing_key_id.as_deref(),
                self.active_slot_signing_key.as_deref(),
                self.require_signed_active_slot,
                "apply-staged-update",
            )?
            .unwrap_or_else(|| previous_slot.clone());
            manifest.last_observed_active_slot = Some(active_slot.clone());
            if active_slot == previous_slot {
                manifest.timestamp = Utc::now().to_rfc3339();
                manifest.status = "rolled_back".to_string();
                manifest.error = Some(
                    "detected interrupted apply with rollback slot already active; preserving rollback state"
                        .to_string(),
                );
                manifest.last_recovery_note = manifest.error.clone();
                manifest.healthcheck_stdout = Some(String::new());
                manifest.healthcheck_stderr =
                    Some("interrupted apply resumed after rollback".to_string());
                manifest.healthcheck_exit_code = None;
                manifest.healthcheck_timed_out = Some(false);
                manifest.healthcheck_timeout_secs = Some(healthcheck_timeout_secs.max(1));
                manifest.apply_started_at = None;
                manifest.apply_from_slot = None;
                manifest.apply_to_slot = None;
                write_manifest(&manifest_path, &manifest)?;
                self.append_audit_record_safe(EvolutionAuditParams {
                    event: "apply",
                    status: "rolled_back",
                    manifest_path: &manifest_path,
                    manifest: &manifest,
                    rollback_performed: Some(true),
                    healthcheck_ok: Some(false),
                    healthcheck_timed_out: Some(false),
                    error: manifest.error.clone(),
                });
                self.record_apply_failure_safe(
                    "rolled_back",
                    manifest
                        .error
                        .as_deref()
                        .unwrap_or("interrupted apply resumed after rollback"),
                );
                return build_apply_report_from_manifest(&manifest_path, &manifest);
            }
            if active_slot != next_slot {
                let message = format!(
                    "active slot marker '{}' conflicts with pending healthcheck state (expected '{}')",
                    active_slot, next_slot
                );
                manifest.timestamp = Utc::now().to_rfc3339();
                manifest.status = "state_failed".to_string();
                manifest.error = Some(message.clone());
                manifest.last_recovery_note = Some(message.clone());
                write_manifest(&manifest_path, &manifest)?;
                self.append_audit_record_safe(EvolutionAuditParams {
                    event: "apply",
                    status: "state_failed",
                    manifest_path: &manifest_path,
                    manifest: &manifest,
                    rollback_performed: None,
                    healthcheck_ok: None,
                    healthcheck_timed_out: None,
                    error: Some(message.clone()),
                });
                self.record_apply_failure_safe("state_failed", &message);
                return Err(anyhow!(message));
            }
            if resumed_from_status.is_some() {
                manifest.last_recovery_note = Some(
                    "resumed apply and continued from pending healthcheck checkpoint".to_string(),
                );
            }
        } else {
            return Err(anyhow!(
                "no staged update available (manifest status '{}')",
                manifest.status
            ));
        }

        let args = if healthcheck_args.is_empty() {
            vec!["doctor".to_string()]
        } else {
            healthcheck_args.to_vec()
        };
        let timeout_secs = healthcheck_timeout_secs.max(1);
        let check = run_healthcheck(&manifest.passive_binary_path, &args, timeout_secs)?;

        let mut rollback_performed = false;
        let mut status = "activated".to_string();
        let mut healthcheck_ok = check.success;
        if !check.success {
            rollback_performed = true;
            status = "rolled_back".to_string();
            healthcheck_ok = false;

            write_active_slot_marker(
                &active_slot_path,
                &previous_slot,
                self.active_slot_signing_key_id.as_deref(),
                self.active_slot_signing_key.as_deref(),
                self.require_signed_active_slot,
            )
            .with_context(|| {
                format!(
                    "failed rolling back active slot from '{}' to '{}'",
                    next_slot, previous_slot
                )
            })?;
        }

        manifest.timestamp = Utc::now().to_rfc3339();
        manifest.status = status.clone();
        manifest.healthcheck_stdout = Some(check.stdout.clone());
        manifest.healthcheck_stderr = Some(check.stderr.clone());
        manifest.healthcheck_exit_code = check.exit_code;
        manifest.healthcheck_timed_out = Some(check.timed_out);
        manifest.healthcheck_timeout_secs = Some(timeout_secs);
        manifest.apply_started_at = None;
        manifest.apply_from_slot = None;
        manifest.apply_to_slot = None;
        if let Some(previous_status) = resumed_from_status.as_deref() {
            manifest.last_recovery_note = Some(format!(
                "resumed from '{}' and completed apply with status '{}'",
                previous_status, status
            ));
        } else if !check.success {
            manifest.last_recovery_note =
                Some("apply healthcheck failed and rollback was performed".to_string());
        }
        manifest.error = if check.success {
            None
        } else {
            Some("post-stage health check failed; rollback performed".to_string())
        };
        write_manifest(&manifest_path, &manifest)?;
        self.append_audit_record_safe(EvolutionAuditParams {
            event: "apply",
            status: &status,
            manifest_path: &manifest_path,
            manifest: &manifest,
            rollback_performed: Some(rollback_performed),
            healthcheck_ok: Some(healthcheck_ok),
            healthcheck_timed_out: Some(check.timed_out),
            error: manifest.error.clone(),
        });
        if check.success {
            self.record_apply_success_safe();
        } else if let Some(error) = manifest.error.as_deref() {
            self.record_apply_failure_safe("rolled_back", error);
        } else {
            self.record_apply_failure_safe(
                "rolled_back",
                "post-stage health check failed; rollback performed",
            );
        }

        Ok(BlueGreenApplyReport {
            status,
            from_slot: previous_slot,
            to_slot: next_slot,
            rollback_performed,
            healthcheck_ok,
            healthcheck_timed_out: check.timed_out,
            healthcheck_timeout_secs: timeout_secs,
            healthcheck_exit_code: check.exit_code,
            healthcheck_stdout: check.stdout,
            healthcheck_stderr: check.stderr,
            manifest_path: manifest_path.display().to_string(),
        })
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }
}

#[derive(Debug)]
struct HealthCheckOutput {
    success: bool,
    timed_out: bool,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn read_manifest(path: &Path) -> Result<BlueGreenStagedManifest> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed reading staged manifest {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("failed decoding staged manifest {}", path.display()))
}

fn read_manifest_if_exists(path: &Path) -> Result<Option<BlueGreenStagedManifest>> {
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(read_manifest(path)?))
}

fn write_manifest(path: &Path, manifest: &BlueGreenStagedManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating manifest dir {}", parent.display()))?;
    }
    let payload = serde_json::to_string_pretty(manifest).context("failed encoding manifest")?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, payload)
        .with_context(|| format!("failed writing staged manifest {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| {
        format!(
            "failed replacing staged manifest {} -> {}",
            tmp.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn is_apply_in_progress_status(status: &str) -> bool {
    matches!(status.trim(), "applying" | "healthcheck_pending")
}

fn is_apply_terminal_status(status: &str) -> bool {
    matches!(status.trim(), "activated" | "rolled_back")
}

fn parse_rfc3339_age_secs(timestamp: &str) -> Option<u64> {
    let parsed = chrono::DateTime::parse_from_rfc3339(timestamp).ok()?;
    let parsed = parsed.with_timezone(&Utc);
    let now = Utc::now();
    if now < parsed {
        return Some(0);
    }
    let secs = (now - parsed).num_seconds();
    Some(secs.max(0) as u64)
}

fn inspect_staged_manifest_freshness(
    manifest: &BlueGreenStagedManifest,
    max_age_secs: Option<u64>,
) -> (Option<u64>, bool) {
    let age_secs = parse_rfc3339_age_secs(manifest.timestamp.as_str());
    let expired =
        max_age_secs.is_some_and(|threshold| age_secs.is_some_and(|age| age >= threshold));
    (age_secs, expired)
}

fn verify_staged_manifest_freshness(
    manifest: &BlueGreenStagedManifest,
    max_age_secs: Option<u64>,
) -> Result<()> {
    let Some(max_age_secs) = max_age_secs.filter(|value| *value > 0) else {
        return Ok(());
    };
    let Some(age_secs) = parse_rfc3339_age_secs(manifest.timestamp.as_str()) else {
        return Err(anyhow!(
            "staged manifest timestamp '{}' is invalid; cannot enforce freshness threshold {}s",
            manifest.timestamp,
            max_age_secs
        ));
    };
    if age_secs >= max_age_secs {
        return Err(anyhow!(
            "staged manifest is stale (age {}s >= threshold {}s); re-stage artifact before apply",
            age_secs,
            max_age_secs
        ));
    }
    Ok(())
}

fn build_expired_manifest_recommendation(
    age_secs: Option<u64>,
    max_age_secs: Option<u64>,
) -> String {
    match (age_secs, max_age_secs) {
        (Some(age), Some(max_age)) => format!(
            "staged update is stale (age {}s >= threshold {}s); re-stage artifact before apply",
            age, max_age
        ),
        _ => "staged update appears stale; re-stage artifact before apply".to_string(),
    }
}

fn detect_recovery_drift(
    manifest: &BlueGreenStagedManifest,
    active_slot_marker: Option<&str>,
) -> bool {
    let Some(marker) = active_slot_marker else {
        return false;
    };
    let marker = marker.trim();
    if marker.is_empty() {
        return false;
    }

    let from_slot = manifest
        .apply_from_slot
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(manifest.active_slot.as_str());
    let to_slot = manifest
        .apply_to_slot
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(manifest.passive_slot.as_str());

    match manifest.status.trim() {
        "activated" => marker != to_slot,
        "rolled_back" => marker != from_slot,
        "applying" | "healthcheck_pending" => marker != from_slot && marker != to_slot,
        _ => false,
    }
}

fn build_recovery_recommendation(
    manifest: &BlueGreenStagedManifest,
    active_slot_marker: Option<&str>,
    drift_detected: bool,
) -> Option<String> {
    if drift_detected {
        return Some(format!(
            "active-slot marker '{}' conflicts with staged apply state '{}'; inspect and re-run apply or rollback with operator approval",
            active_slot_marker.unwrap_or("<missing>"),
            manifest.status
        ));
    }

    let status = manifest.status.trim();
    match status {
        "staged" => Some("staged update is ready; run evolution apply-staged-update --confirm".to_string()),
        "applying" | "healthcheck_pending" => Some(
            "apply appears interrupted mid-flight; re-run evolution apply-staged-update --confirm to resume"
                .to_string(),
        ),
        "activated" => Some("staged update already activated; no recovery action needed".to_string()),
        "rolled_back" => Some(
            "staged update rolled back; inspect healthcheck output and re-stage a new artifact"
                .to_string(),
        ),
        "stale_failed" => Some(
            "staged manifest failed freshness checks; re-stage artifact before apply".to_string(),
        ),
        "state_failed" => Some(
            "state validation failed; inspect lock/active-slot state and consider evolution force-unlock --confirm after review"
                .to_string(),
        ),
        _ => None,
    }
}

fn read_active_slot_marker(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed reading active slot marker {}", path.display()))?;
    let slot = raw.trim();
    if slot.is_empty() {
        return Ok(None);
    }
    if slot != "blue" && slot != "green" {
        return Err(anyhow!(
            "active slot marker '{}' is invalid in {}",
            slot,
            path.display()
        ));
    }
    Ok(Some(slot.to_string()))
}

fn read_active_slot_marker_with_integrity(
    marker_path: &Path,
    configured_key_id: Option<&str>,
    configured_key: Option<&str>,
    require_signed: bool,
    operation: &str,
) -> Result<Option<String>> {
    let report = inspect_active_slot_integrity(
        marker_path,
        configured_key_id,
        configured_key,
        require_signed,
    )?;
    enforce_active_slot_integrity_for_operation(&report, operation)?;
    Ok(report.slot)
}

fn inspect_active_slot_integrity(
    marker_path: &Path,
    configured_key_id: Option<&str>,
    configured_key: Option<&str>,
    require_signed: bool,
) -> Result<EvolutionActiveSlotIntegrityReport> {
    let signature_path = active_slot_signature_path(marker_path);
    let marker_exists = marker_path.exists();
    let signature_present = signature_path.exists();
    let key_loaded = normalized_signing_key(configured_key).is_some();
    let key_id = normalized_signing_key_id(configured_key_id).map(ToString::to_string);

    let slot = match read_active_slot_marker(marker_path) {
        Ok(value) => value,
        Err(err) => {
            return Ok(build_active_slot_integrity_report(
                marker_path,
                &signature_path,
                marker_exists,
                None,
                signature_present,
                Some(false),
                "invalid_marker",
                Some(err.to_string()),
                require_signed,
                key_loaded,
                key_id,
            ));
        }
    };

    if slot.is_none() {
        let (status, message, verified) = if marker_exists {
            (
                "invalid_marker",
                Some(format!(
                    "active slot marker is empty in {}",
                    marker_path.display()
                )),
                Some(false),
            )
        } else if signature_present {
            (
                "orphan_signature",
                Some(format!(
                    "active-slot signature exists without marker: {}",
                    signature_path.display()
                )),
                Some(false),
            )
        } else {
            (
                "missing_marker",
                Some(
                    "active slot marker does not exist; default slot bootstrap applies".to_string(),
                ),
                None,
            )
        };
        return Ok(build_active_slot_integrity_report(
            marker_path,
            &signature_path,
            marker_exists,
            None,
            signature_present,
            verified,
            status,
            message,
            require_signed,
            key_loaded,
            key_id,
        ));
    }

    let slot = slot.unwrap_or_default();
    if !signature_present {
        let (status, message, verified) = if require_signed {
            (
                "signature_missing",
                Some(format!(
                    "active-slot signature missing while policy requires signatures: {}",
                    signature_path.display()
                )),
                Some(false),
            )
        } else {
            (
                "unsigned",
                Some("active-slot marker is unsigned".to_string()),
                None,
            )
        };
        return Ok(build_active_slot_integrity_report(
            marker_path,
            &signature_path,
            marker_exists,
            Some(slot),
            signature_present,
            verified,
            status,
            message,
            require_signed,
            key_loaded,
            key_id,
        ));
    }

    let signature = match read_active_slot_signature(&signature_path) {
        Ok(Some(value)) => value,
        Ok(None) => {
            return Ok(build_active_slot_integrity_report(
                marker_path,
                &signature_path,
                marker_exists,
                Some(slot),
                signature_present,
                Some(false),
                "signature_missing",
                Some(format!(
                    "active-slot signature file not found: {}",
                    signature_path.display()
                )),
                require_signed,
                key_loaded,
                key_id,
            ));
        }
        Err(err) => {
            return Ok(build_active_slot_integrity_report(
                marker_path,
                &signature_path,
                marker_exists,
                Some(slot),
                signature_present,
                Some(false),
                "signature_invalid",
                Some(err.to_string()),
                require_signed,
                key_loaded,
                key_id,
            ));
        }
    };

    if !key_loaded {
        let (status, message, verified) = if require_signed {
            (
                "signature_unverified",
                Some(
                    "active-slot signature exists but no signing key is configured for verification"
                        .to_string(),
                ),
                Some(false),
            )
        } else {
            (
                "signature_present_unverified",
                Some(
                    "active-slot signature exists but verification key is not configured"
                        .to_string(),
                ),
                None,
            )
        };
        return Ok(build_active_slot_integrity_report(
            marker_path,
            &signature_path,
            marker_exists,
            Some(slot),
            signature_present,
            verified,
            status,
            message,
            require_signed,
            key_loaded,
            key_id,
        ));
    }

    let signing_key = normalized_signing_key(configured_key).unwrap_or_default();
    let verify_result =
        verify_active_slot_signature(&slot, &signature, configured_key_id, signing_key);
    match verify_result {
        Ok(()) => Ok(build_active_slot_integrity_report(
            marker_path,
            &signature_path,
            marker_exists,
            Some(slot),
            signature_present,
            Some(true),
            "valid",
            Some("active-slot marker signature verified".to_string()),
            require_signed,
            key_loaded,
            key_id,
        )),
        Err(err) => Ok(build_active_slot_integrity_report(
            marker_path,
            &signature_path,
            marker_exists,
            Some(slot),
            signature_present,
            Some(false),
            "signature_invalid",
            Some(err.to_string()),
            require_signed,
            key_loaded,
            key_id,
        )),
    }
}

fn build_active_slot_integrity_report(
    marker_path: &Path,
    signature_path: &Path,
    marker_exists: bool,
    slot: Option<String>,
    signature_present: bool,
    signature_verified: Option<bool>,
    status: &str,
    message: Option<String>,
    require_signed: bool,
    key_loaded: bool,
    key_id: Option<String>,
) -> EvolutionActiveSlotIntegrityReport {
    EvolutionActiveSlotIntegrityReport {
        marker_path: marker_path.display().to_string(),
        signature_path: signature_path.display().to_string(),
        marker_exists,
        slot,
        signature_present,
        signature_verified,
        status: status.to_string(),
        message,
        require_signed,
        key_loaded,
        key_id,
    }
}

fn enforce_active_slot_integrity_for_operation(
    report: &EvolutionActiveSlotIntegrityReport,
    operation: &str,
) -> Result<()> {
    if report.slot.is_none() {
        if report.marker_exists || report.signature_present {
            return Err(anyhow!(
                "active-slot integrity check failed for {}: {}",
                operation,
                report
                    .message
                    .clone()
                    .unwrap_or_else(|| "invalid active-slot marker state".to_string())
            ));
        }
        return Ok(());
    }

    if report.require_signed {
        if !report.signature_present || report.signature_verified != Some(true) {
            return Err(anyhow!(
                "active-slot integrity check failed for {}: {}",
                operation,
                report.message.clone().unwrap_or_else(|| {
                    "signed active-slot marker is required but not verified".to_string()
                })
            ));
        }
    } else if report.signature_present && report.signature_verified == Some(false) {
        return Err(anyhow!(
            "active-slot integrity check failed for {}: {}",
            operation,
            report
                .message
                .clone()
                .unwrap_or_else(|| "active-slot signature verification failed".to_string())
        ));
    }

    Ok(())
}

fn write_active_slot_marker(
    path: &Path,
    slot: &str,
    signing_key_id: Option<&str>,
    signing_key: Option<&str>,
    require_signed: bool,
) -> Result<()> {
    let slot = slot.trim();
    if slot != "blue" && slot != "green" {
        return Err(anyhow!("active slot value must be 'blue' or 'green'"));
    }
    let signing_key = normalized_signing_key(signing_key);
    if require_signed && signing_key.is_none() {
        return Err(anyhow!(
            "active-slot signing policy requires RUSTY_PINCH_EVOLUTION_ACTIVE_SLOT_SIGNING_KEY"
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating active slot dir {}", parent.display()))?;
    }

    let tmp = atomic_tmp_path(path);
    fs::write(&tmp, format!("{slot}\n"))
        .with_context(|| format!("failed writing active slot marker {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| {
        format!(
            "failed replacing active slot marker {} -> {}",
            tmp.display(),
            path.display()
        )
    })?;

    let signature_path = active_slot_signature_path(path);
    if let Some(signing_key) = signing_key {
        let key_id = normalized_signing_key_id(signing_key_id).unwrap_or("default");
        let signed_at = Utc::now().to_rfc3339();
        let signature =
            compute_active_slot_signature_hex(slot, Some(key_id), &signed_at, signing_key)?;
        let envelope = ActiveSlotSignatureEnvelope {
            slot: slot.to_string(),
            signature,
            signature_algorithm: "hmac-sha256".to_string(),
            signature_key_id: Some(key_id.to_string()),
            signed_at,
        };
        write_active_slot_signature(&signature_path, &envelope)?;
    } else if signature_path.exists() {
        fs::remove_file(&signature_path).with_context(|| {
            format!(
                "failed removing stale active-slot signature {}",
                signature_path.display()
            )
        })?;
    }

    Ok(())
}

fn read_active_slot_signature(path: &Path) -> Result<Option<ActiveSlotSignatureEnvelope>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed reading active slot signature {}", path.display()))?;
    let envelope: ActiveSlotSignatureEnvelope = serde_json::from_str(&raw)
        .with_context(|| format!("failed decoding active slot signature {}", path.display()))?;
    Ok(Some(envelope))
}

fn write_active_slot_signature(path: &Path, envelope: &ActiveSlotSignatureEnvelope) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating active slot signature dir {}",
                parent.display()
            )
        })?;
    }
    let payload =
        serde_json::to_string_pretty(envelope).context("failed encoding active slot signature")?;
    let tmp = atomic_tmp_path(path);
    fs::write(&tmp, payload)
        .with_context(|| format!("failed writing active slot signature {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| {
        format!(
            "failed replacing active slot signature {} -> {}",
            tmp.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn active_slot_signature_path(marker_path: &Path) -> PathBuf {
    marker_path.with_extension("sig")
}

fn atomic_tmp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("tmp");
    path.with_file_name(format!("{file_name}.tmp"))
}

fn build_apply_report_from_manifest(
    manifest_path: &Path,
    manifest: &BlueGreenStagedManifest,
) -> Result<BlueGreenApplyReport> {
    if !is_apply_terminal_status(&manifest.status) {
        return Err(anyhow!(
            "apply report can only be built for terminal manifest states (got '{}')",
            manifest.status
        ));
    }

    let from_slot = manifest
        .apply_from_slot
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(manifest.active_slot.as_str())
        .to_string();
    let to_slot = manifest
        .apply_to_slot
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(manifest.passive_slot.as_str())
        .to_string();
    let rollback_performed = manifest.status == "rolled_back";
    let healthcheck_ok = manifest.status == "activated";

    Ok(BlueGreenApplyReport {
        status: manifest.status.clone(),
        from_slot,
        to_slot,
        rollback_performed,
        healthcheck_ok,
        healthcheck_timed_out: manifest.healthcheck_timed_out.unwrap_or(false),
        healthcheck_timeout_secs: manifest.healthcheck_timeout_secs.unwrap_or(1),
        healthcheck_exit_code: manifest.healthcheck_exit_code,
        healthcheck_stdout: manifest.healthcheck_stdout.clone().unwrap_or_default(),
        healthcheck_stderr: manifest.healthcheck_stderr.clone().unwrap_or_default(),
        manifest_path: manifest_path.display().to_string(),
    })
}

fn build_apply_failure_circuit_report(
    circuit_path: &Path,
    state_exists: bool,
    threshold: Option<u64>,
    state: &EvolutionApplyFailureCircuitState,
) -> EvolutionApplyFailureCircuitReport {
    let circuit_open =
        threshold.is_some_and(|value| state.consecutive_failures >= value) || state.circuit_open;
    EvolutionApplyFailureCircuitReport {
        circuit_path: circuit_path.display().to_string(),
        state_exists,
        threshold,
        consecutive_failures: state.consecutive_failures,
        circuit_open,
        last_failure_at: state.last_failure_at.clone(),
        last_failure_status: state.last_failure_status.clone(),
        last_failure_error: state.last_failure_error.clone(),
        last_success_at: state.last_success_at.clone(),
        last_reset_at: state.last_reset_at.clone(),
    }
}

fn read_apply_failure_circuit_state(path: &Path) -> Result<EvolutionApplyFailureCircuitState> {
    if !path.exists() {
        return Ok(EvolutionApplyFailureCircuitState::default());
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed reading apply-failure circuit {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("failed decoding apply-failure circuit {}", path.display()))
}

fn write_apply_failure_circuit_state(
    path: &Path,
    state: &EvolutionApplyFailureCircuitState,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating apply-failure circuit dir {}",
                parent.display()
            )
        })?;
    }
    let payload =
        serde_json::to_string_pretty(state).context("failed encoding apply-failure circuit")?;
    let tmp = atomic_tmp_path(path);
    fs::write(&tmp, payload)
        .with_context(|| format!("failed writing apply-failure circuit {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| {
        format!(
            "failed replacing apply-failure circuit {} -> {}",
            tmp.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn read_last_audit_hash(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed reading evolution audit log {}", path.display()))?;
    let Some(last_line) = raw.lines().rev().find(|line| !line.trim().is_empty()) else {
        return Ok(None);
    };
    let parsed: EvolutionAuditRecord =
        serde_json::from_str(last_line).context("failed decoding evolution audit log line")?;
    let Some(hash) = normalize_optional_audit_hash(Some(parsed.hash.as_str()))? else {
        return Ok(None);
    };
    Ok(Some(hash))
}

fn compute_audit_record_hash(record: &EvolutionAuditRecord) -> String {
    let payload = format!(
        "timestamp={}\nevent={}\nstatus={}\nmanifest_path={}\nactive_slot={}\npassive_slot={}\ncurrent_binary_version={}\nartifact_binary_version={}\nchecksum_manifest_sha256={}\nchecksum_manifest_signature_verified={}\nartifact_binary_sha256={}\nartifact_checksum_verified={}\nmanifest_signature_key_id={}\nrollback_performed={}\nhealthcheck_ok={}\nhealthcheck_timed_out={}\nerror={}\nprev_hash={}\n",
        record.timestamp,
        record.event,
        record.status,
        record.manifest_path,
        record.active_slot,
        record.passive_slot,
        record.current_binary_version.as_deref().unwrap_or_default(),
        record.artifact_binary_version.as_deref().unwrap_or_default(),
        record.checksum_manifest_sha256.as_deref().unwrap_or_default(),
        record
            .checksum_manifest_signature_verified
            .map(|value| value.to_string())
            .unwrap_or_default(),
        record.artifact_binary_sha256.as_deref().unwrap_or_default(),
        record
            .artifact_checksum_verified
            .map(|value| value.to_string())
            .unwrap_or_default(),
        record
            .manifest_signature_key_id
            .as_deref()
            .unwrap_or_default(),
        record
            .rollback_performed
            .map(|value| value.to_string())
            .unwrap_or_default(),
        record
            .healthcheck_ok
            .map(|value| value.to_string())
            .unwrap_or_default(),
        record
            .healthcheck_timed_out
            .map(|value| value.to_string())
            .unwrap_or_default(),
        record.error.as_deref().unwrap_or_default(),
        record.prev_hash.as_deref().unwrap_or_default(),
    );
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn normalize_audit_hash(raw: &str) -> Result<String> {
    normalize_sha256_hex(raw)
}

fn normalize_optional_audit_hash(raw: Option<&str>) -> Result<Option<String>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(normalize_audit_hash(trimmed)?))
}

fn verify_staged_binary_integrity(binary_path: &Path, expected_sha256: Option<&str>) -> Result<()> {
    if !binary_path.exists() {
        return Err(anyhow!(
            "staged passive binary does not exist: {}",
            binary_path.display()
        ));
    }

    let expected = expected_sha256
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("staged manifest missing passive binary checksum; re-stage update"))?
        .to_ascii_lowercase();
    let actual = compute_sha256_hex(binary_path)?;
    if actual != expected {
        return Err(anyhow!(
            "staged passive binary checksum mismatch (expected {}, got {})",
            expected,
            actual
        ));
    }
    Ok(())
}

fn verify_staged_artifact_provenance(
    manifest: &BlueGreenStagedManifest,
    require_verified_stage_artifact_sha256: bool,
) -> Result<()> {
    if !require_verified_stage_artifact_sha256 {
        return Ok(());
    }

    if manifest.artifact_checksum_verified != Some(true) {
        return Err(anyhow!(
            "staged manifest is not marked as artifact-checksum-verified; re-stage update with --artifact-sha256"
        ));
    }

    let artifact_path = manifest
        .artifact_binary_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("staged manifest missing artifact binary path; re-stage update"))?;
    let expected = manifest.artifact_binary_sha256.as_deref().ok_or_else(|| {
        anyhow!("staged manifest missing artifact binary checksum; re-stage update")
    })?;
    let expected = normalize_sha256_hex(expected)?;

    let artifact = Path::new(artifact_path);
    if artifact.exists() {
        let actual = compute_sha256_hex(artifact)?;
        if actual != expected {
            return Err(anyhow!(
                "staged artifact binary checksum mismatch (expected {}, got {})",
                expected,
                actual
            ));
        }
    }

    Ok(())
}

fn verify_signed_checksum_manifest_provenance(
    manifest: &BlueGreenStagedManifest,
    require_signed_checksum_manifest_provenance: bool,
    trusted_checksum_manifest_sha256: Option<&str>,
    trusted_checksum_manifest_ed25519_public_key: Option<&str>,
) -> Result<()> {
    if !require_signed_checksum_manifest_provenance {
        return Ok(());
    }

    if manifest.checksum_manifest_signature_verified != Some(true) {
        return Err(anyhow!(
            "staged manifest is not marked as checksum-manifest-signature-verified; re-stage update with --artifact-sha256-sums-signature-file"
        ));
    }

    let checksum_manifest_path = manifest
        .checksum_manifest_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "staged manifest missing checksum manifest path; re-stage update from SHA256SUMS"
            )
        })?;
    let checksum_manifest_sha256 = manifest
        .checksum_manifest_sha256
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow!("staged manifest missing checksum manifest SHA-256; re-stage update from SHA256SUMS")
        })?;
    let checksum_manifest_sha256 = normalize_sha256_hex(checksum_manifest_sha256)?;

    if let Some(trusted) = trusted_checksum_manifest_sha256 {
        let trusted = normalize_sha256_hex(trusted)?;
        if trusted != checksum_manifest_sha256 {
            return Err(anyhow!(
                "staged checksum manifest SHA-256 does not match trusted pin (expected {}, got {})",
                trusted,
                checksum_manifest_sha256
            ));
        }
    }

    let checksum_manifest = Path::new(checksum_manifest_path);
    if !checksum_manifest.exists() {
        return Err(anyhow!(
            "recorded checksum manifest does not exist at apply time: {}",
            checksum_manifest.display()
        ));
    }
    let checksum_manifest_actual_sha256 = compute_sha256_hex(checksum_manifest)?;
    if checksum_manifest_actual_sha256 != checksum_manifest_sha256 {
        return Err(anyhow!(
            "recorded checksum manifest SHA-256 mismatch at apply time (expected {}, got {})",
            checksum_manifest_sha256,
            checksum_manifest_actual_sha256
        ));
    }

    let checksum_manifest_signature_path = manifest
        .checksum_manifest_signature_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow!("staged manifest missing checksum manifest signature path; re-stage update with --artifact-sha256-sums-signature-file")
        })?;
    let checksum_manifest_signature = Path::new(checksum_manifest_signature_path);
    verify_checksum_manifest_signature(
        checksum_manifest,
        checksum_manifest_signature,
        trusted_checksum_manifest_ed25519_public_key,
    )?;

    Ok(())
}

fn normalize_update_versions(
    current_version: Option<&str>,
    artifact_version: Option<&str>,
    require_non_rollback_version: bool,
) -> Result<(Option<String>, Option<String>)> {
    let current_version = current_version
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let artifact_version = artifact_version
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);

    if current_version.is_some() ^ artifact_version.is_some() {
        return Err(anyhow!(
            "--current-version and --artifact-version must be provided together"
        ));
    }

    if require_non_rollback_version && current_version.is_none() {
        return Err(anyhow!(
            "evolution stage-update is blocked by version policy. Re-run with --current-version and --artifact-version or set RUSTY_PINCH_EVOLUTION_REQUIRE_NON_ROLLBACK_VERSION=false"
        ));
    }

    if let (Some(current), Some(artifact)) = (&current_version, &artifact_version) {
        ensure_artifact_version_is_upgrade(current, artifact)?;
    }

    Ok((current_version, artifact_version))
}

fn verify_non_rollback_update_version(
    manifest: &BlueGreenStagedManifest,
    require_non_rollback_version: bool,
) -> Result<()> {
    if !require_non_rollback_version {
        return Ok(());
    }

    let current_version = manifest
        .current_binary_version
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "staged manifest missing current binary version; re-stage update with --current-version"
            )
        })?;
    let artifact_version = manifest
        .artifact_binary_version
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "staged manifest missing artifact version; re-stage update with --artifact-version"
            )
        })?;

    ensure_artifact_version_is_upgrade(current_version, artifact_version)
}

fn ensure_artifact_version_is_upgrade(current_version: &str, artifact_version: &str) -> Result<()> {
    let current = parse_version_components(current_version)?;
    let artifact = parse_version_components(artifact_version)?;
    match compare_version_components(&artifact, &current) {
        std::cmp::Ordering::Greater => Ok(()),
        _ => Err(anyhow!(
            "artifact version '{}' must be greater than current version '{}' to prevent rollback",
            artifact_version,
            current_version
        )),
    }
}

fn parse_version_components(raw: &str) -> Result<Vec<u64>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("version value is empty"));
    }

    let normalized = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    if normalized.is_empty() {
        return Err(anyhow!("version value is empty"));
    }
    if normalized.starts_with('.') || normalized.ends_with('.') {
        return Err(anyhow!(
            "version '{}' must be dot-separated numeric segments",
            raw
        ));
    }

    let mut values = Vec::new();
    for segment in normalized.split('.') {
        if segment.is_empty() || !segment.chars().all(|ch| ch.is_ascii_digit()) {
            return Err(anyhow!(
                "version '{}' must be dot-separated numeric segments",
                raw
            ));
        }
        let value = segment
            .parse::<u64>()
            .map_err(|_| anyhow!("version '{}' contains unsupported numeric segment", raw))?;
        values.push(value);
    }

    Ok(values)
}

fn compare_version_components(lhs: &[u64], rhs: &[u64]) -> std::cmp::Ordering {
    let max_len = lhs.len().max(rhs.len());
    for idx in 0..max_len {
        let left = lhs.get(idx).copied().unwrap_or(0);
        let right = rhs.get(idx).copied().unwrap_or(0);
        match left.cmp(&right) {
            std::cmp::Ordering::Equal => continue,
            non_eq => return non_eq,
        }
    }
    std::cmp::Ordering::Equal
}

fn compute_sha256_hex(path: &Path) -> Result<String> {
    let mut file =
        fs::File::open(path).with_context(|| format!("failed opening file {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("failed reading file {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn verify_artifact_sha256(expected_sha256: Option<&str>, actual_sha256: &str) -> Result<()> {
    let Some(expected_sha256) = expected_sha256 else {
        return Ok(());
    };
    let expected = normalize_sha256_hex(expected_sha256)?;
    if expected != actual_sha256.to_ascii_lowercase() {
        return Err(anyhow!(
            "artifact binary checksum mismatch (expected {}, got {})",
            expected,
            actual_sha256
        ));
    }
    Ok(())
}

fn normalize_sha256_hex(raw: &str) -> Result<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.len() != 64 {
        return Err(anyhow!(
            "artifact checksum must be a 64-character SHA-256 hex string"
        ));
    }
    if !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "artifact checksum must contain only hex characters"
        ));
    }
    Ok(normalized)
}

fn parse_sha256sum_line(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim();
    if trimmed.len() < 65 {
        return None;
    }

    if let Some((hash, rest)) = trimmed.split_once("  ") {
        let name = rest.trim_start_matches('*').trim();
        return Some((hash.trim(), name));
    }
    if let Some((hash, rest)) = trimmed.split_once(" *") {
        let name = rest.trim();
        return Some((hash.trim(), name));
    }

    let mut parts = trimmed.split_whitespace();
    let hash = parts.next()?;
    let name = parts.next()?.trim_start_matches('*').trim();
    Some((hash, name))
}

fn checksum_entry_matches(candidate: &str, requested: &str, artifact_basename: &str) -> bool {
    if candidate == requested {
        return true;
    }
    let normalized_candidate = candidate.trim_start_matches("./");
    if normalized_candidate == requested {
        return true;
    }
    if let Some(file_name) = Path::new(normalized_candidate)
        .file_name()
        .and_then(|value| value.to_str())
    {
        if file_name == requested || file_name == artifact_basename {
            return true;
        }
    }
    false
}

fn verify_checksum_manifest_signature(
    sums_path: &Path,
    signature_path: &Path,
    trusted_public_key: Option<&str>,
) -> Result<()> {
    if !signature_path.exists() {
        return Err(anyhow!(
            "checksum manifest signature file does not exist: {}",
            signature_path.display()
        ));
    }

    let key = trusted_public_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "checksum manifest signature verification requires RUSTY_PINCH_EVOLUTION_TRUSTED_SHA256SUMS_ED25519_PUBLIC_KEY"
            )
        })?;

    let verifying_key = parse_ed25519_public_key(key)?;
    let signature_raw = fs::read(signature_path).with_context(|| {
        format!(
            "failed reading checksum manifest signature {}",
            signature_path.display()
        )
    })?;
    let signature = parse_ed25519_signature(&signature_raw)?;

    let message = fs::read(sums_path)
        .with_context(|| format!("failed reading checksum manifest {}", sums_path.display()))?;
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| anyhow!("checksum manifest signature verification failed"))?;

    Ok(())
}

fn parse_ed25519_public_key(raw: &str) -> Result<VerifyingKey> {
    let bytes = decode_hex_or_base64(raw)?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("Ed25519 public key must decode to 32 bytes"))?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| anyhow!("invalid Ed25519 public key bytes"))
}

fn parse_ed25519_signature(raw: &[u8]) -> Result<Signature> {
    if raw.len() == 64 {
        let signature_bytes: [u8; 64] = raw
            .try_into()
            .map_err(|_| anyhow!("invalid Ed25519 signature bytes"))?;
        return Ok(Signature::from_bytes(&signature_bytes));
    }

    let text = std::str::from_utf8(raw)
        .context("checksum manifest signature must be UTF-8 text or 64-byte raw signature")?
        .trim();
    if text.is_empty() {
        return Err(anyhow!("checksum manifest signature file is empty"));
    }

    let decoded = decode_hex_or_base64(text)?;
    let signature_bytes: [u8; 64] = decoded
        .try_into()
        .map_err(|_| anyhow!("Ed25519 signature must decode to 64 bytes"))?;
    Ok(Signature::from_bytes(&signature_bytes))
}

fn decode_hex_or_base64(raw: &str) -> Result<Vec<u8>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("value is empty"));
    }
    if trimmed.len() % 2 == 0 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return decode_hex_string(trimmed);
    }

    general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(trimmed))
        .or_else(|_| general_purpose::URL_SAFE.decode(trimmed))
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
        .map_err(|_| anyhow!("value must be base64 or hex encoded"))
}

fn decode_hex_string(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(anyhow!("hex value length must be even"));
    }

    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|_| anyhow!("value must contain valid hexadecimal characters"))?;
        out.push(byte);
    }
    Ok(out)
}

fn verify_manifest_signature(
    manifest: &BlueGreenStagedManifest,
    manifest_signing_keys: &[(String, String)],
    require_manifest_signature: bool,
) -> Result<()> {
    let configured_keys = normalized_signing_keys(manifest_signing_keys);
    let signature = manifest
        .manifest_signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if require_manifest_signature && configured_keys.is_empty() {
        return Err(anyhow!(
            "manifest signature verification required but no signing key is configured"
        ));
    }
    if require_manifest_signature && signature.is_none() {
        return Err(anyhow!(
            "staged manifest signature is required but missing; re-stage update"
        ));
    }

    if configured_keys.is_empty() {
        return Ok(());
    }
    let expected = signature.ok_or_else(|| {
        anyhow!("signing keys are configured but staged manifest is unsigned; re-stage update")
    })?;

    if let Some(algorithm) = manifest.manifest_signature_algorithm.as_deref() {
        if !algorithm.eq_ignore_ascii_case("hmac-sha256") {
            return Err(anyhow!(
                "unsupported staged manifest signature algorithm '{}'",
                algorithm
            ));
        }
    }

    let key = resolve_manifest_signing_key(manifest, &configured_keys)?;
    let expected = expected.to_ascii_lowercase();
    let computed = compute_manifest_signature_hex(manifest, key)?;
    if computed == expected {
        return Ok(());
    }

    let prior_without_version = compute_manifest_signature_hex_without_version(manifest, key)?;
    if prior_without_version == expected {
        return Ok(());
    }

    let prior_without_artifact = compute_manifest_signature_hex_without_artifact(manifest, key)?;
    if prior_without_artifact == expected {
        return Ok(());
    }

    if manifest
        .manifest_signature_key_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        let legacy = compute_manifest_signature_hex_legacy(manifest, key)?;
        if legacy == expected {
            return Ok(());
        }
    }

    Err(anyhow!("staged manifest signature mismatch"))
}

fn normalized_signing_keys<'a>(
    manifest_signing_keys: &'a [(String, String)],
) -> Vec<(&'a str, &'a str)> {
    manifest_signing_keys
        .iter()
        .filter_map(|(raw_id, raw_key)| {
            let id = raw_id.trim();
            let key = raw_key.trim();
            if id.is_empty() || key.is_empty() {
                None
            } else {
                Some((id, key))
            }
        })
        .collect()
}

fn resolve_manifest_signing_key<'a>(
    manifest: &BlueGreenStagedManifest,
    configured_keys: &[(&'a str, &'a str)],
) -> Result<&'a str> {
    let key_id = manifest
        .manifest_signature_key_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if let Some(key_id) = key_id {
        if let Some((_, key)) = configured_keys
            .iter()
            .find(|(id, _)| id.eq_ignore_ascii_case(key_id))
        {
            return Ok(*key);
        }
        return Err(anyhow!(
            "staged manifest signature key id '{}' is not configured",
            key_id
        ));
    }

    if configured_keys.len() == 1 {
        return Ok(configured_keys[0].1);
    }

    Err(anyhow!(
        "staged manifest signature key id is missing and {} signing keys are configured; re-stage update",
        configured_keys.len()
    ))
}

fn compute_manifest_signature_hex(
    manifest: &BlueGreenStagedManifest,
    signing_key: &str,
) -> Result<String> {
    let payload = manifest_signature_payload(manifest);
    compute_hmac_sha256_hex(&payload, signing_key)
}

fn compute_manifest_signature_hex_without_version(
    manifest: &BlueGreenStagedManifest,
    signing_key: &str,
) -> Result<String> {
    let payload = manifest_signature_payload_without_version(manifest);
    compute_hmac_sha256_hex(&payload, signing_key)
}

fn compute_manifest_signature_hex_without_artifact(
    manifest: &BlueGreenStagedManifest,
    signing_key: &str,
) -> Result<String> {
    let payload = manifest_signature_payload_without_artifact(manifest);
    compute_hmac_sha256_hex(&payload, signing_key)
}

fn compute_manifest_signature_hex_legacy(
    manifest: &BlueGreenStagedManifest,
    signing_key: &str,
) -> Result<String> {
    let payload = manifest_signature_payload_legacy(manifest);
    compute_hmac_sha256_hex(&payload, signing_key)
}

fn compute_hmac_sha256_hex(payload: &str, signing_key: &str) -> Result<String> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(signing_key.as_bytes())
        .context("invalid manifest signing key")?;
    mac.update(payload.as_bytes());
    let bytes = mac.finalize().into_bytes();
    Ok(bytes.iter().map(|byte| format!("{:02x}", byte)).collect())
}

fn verify_active_slot_signature(
    slot: &str,
    envelope: &ActiveSlotSignatureEnvelope,
    configured_key_id: Option<&str>,
    signing_key: &str,
) -> Result<()> {
    let envelope_slot = envelope.slot.trim();
    if envelope_slot != slot {
        return Err(anyhow!(
            "active-slot signature slot mismatch (marker '{}', signature '{}')",
            slot,
            envelope.slot
        ));
    }
    if envelope.signature_algorithm.trim() != "hmac-sha256" {
        return Err(anyhow!(
            "unsupported active-slot signature algorithm '{}'",
            envelope.signature_algorithm
        ));
    }

    let normalized_signature = normalize_sha256_hex(&envelope.signature)?;
    let envelope_key_id = normalized_signing_key_id(envelope.signature_key_id.as_deref());
    if let Some(expected_key_id) = normalized_signing_key_id(configured_key_id) {
        let Some(actual_key_id) = envelope_key_id else {
            return Err(anyhow!(
                "active-slot signature key id is missing (expected '{}')",
                expected_key_id
            ));
        };
        if !actual_key_id.eq_ignore_ascii_case(expected_key_id) {
            return Err(anyhow!(
                "active-slot signature key id mismatch (expected '{}', got '{}')",
                expected_key_id,
                actual_key_id
            ));
        }
    }

    let expected_signature = compute_active_slot_signature_hex(
        envelope_slot,
        envelope_key_id,
        envelope.signed_at.as_str(),
        signing_key,
    )?;
    if normalized_signature != expected_signature {
        return Err(anyhow!("active-slot signature mismatch"));
    }

    Ok(())
}

fn compute_active_slot_signature_hex(
    slot: &str,
    signature_key_id: Option<&str>,
    signed_at: &str,
    signing_key: &str,
) -> Result<String> {
    let payload = active_slot_signature_payload(slot, signature_key_id, signed_at);
    compute_hmac_sha256_hex(&payload, signing_key)
}

fn active_slot_signature_payload(
    slot: &str,
    signature_key_id: Option<&str>,
    signed_at: &str,
) -> String {
    format!(
        "slot={}\nsignature_key_id={}\nsigned_at={}\n",
        slot,
        signature_key_id.unwrap_or_default(),
        signed_at
    )
}

fn manifest_signature_payload(manifest: &BlueGreenStagedManifest) -> String {
    format!(
        "timestamp={}\nstatus={}\nactive_slot={}\npassive_slot={}\ncurrent_binary_version={}\nartifact_binary_version={}\nchecksum_manifest_path={}\nchecksum_manifest_sha256={}\nchecksum_manifest_signature_path={}\nchecksum_manifest_signature_verified={}\nartifact_binary_path={}\nartifact_binary_sha256={}\nartifact_checksum_verified={}\npassive_binary_path={}\npassive_binary_sha256={}\nrollback_binary={}\nmanifest_signature_key_id={}\n",
        manifest.timestamp,
        manifest.status,
        manifest.active_slot,
        manifest.passive_slot,
        manifest.current_binary_version.as_deref().unwrap_or_default(),
        manifest.artifact_binary_version.as_deref().unwrap_or_default(),
        manifest.checksum_manifest_path.as_deref().unwrap_or_default(),
        manifest.checksum_manifest_sha256.as_deref().unwrap_or_default(),
        manifest
            .checksum_manifest_signature_path
            .as_deref()
            .unwrap_or_default(),
        manifest
            .checksum_manifest_signature_verified
            .unwrap_or(false),
        manifest.artifact_binary_path.as_deref().unwrap_or_default(),
        manifest.artifact_binary_sha256.as_deref().unwrap_or_default(),
        manifest.artifact_checksum_verified.unwrap_or(false),
        manifest.passive_binary_path,
        manifest.passive_binary_sha256.as_deref().unwrap_or_default(),
        manifest.rollback_binary,
        manifest
            .manifest_signature_key_id
            .as_deref()
            .unwrap_or_default()
    )
}

fn normalized_signing_key(manifest_signing_key: Option<&str>) -> Option<&str> {
    manifest_signing_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn manifest_signature_payload_legacy(manifest: &BlueGreenStagedManifest) -> String {
    format!(
        "timestamp={}\nstatus={}\nactive_slot={}\npassive_slot={}\npassive_binary_path={}\npassive_binary_sha256={}\nrollback_binary={}\n",
        manifest.timestamp,
        manifest.status,
        manifest.active_slot,
        manifest.passive_slot,
        manifest.passive_binary_path,
        manifest.passive_binary_sha256.as_deref().unwrap_or_default(),
        manifest.rollback_binary
    )
}

fn manifest_signature_payload_without_version(manifest: &BlueGreenStagedManifest) -> String {
    format!(
        "timestamp={}\nstatus={}\nactive_slot={}\npassive_slot={}\nartifact_binary_path={}\nartifact_binary_sha256={}\nartifact_checksum_verified={}\npassive_binary_path={}\npassive_binary_sha256={}\nrollback_binary={}\nmanifest_signature_key_id={}\n",
        manifest.timestamp,
        manifest.status,
        manifest.active_slot,
        manifest.passive_slot,
        manifest.artifact_binary_path.as_deref().unwrap_or_default(),
        manifest.artifact_binary_sha256.as_deref().unwrap_or_default(),
        manifest.artifact_checksum_verified.unwrap_or(false),
        manifest.passive_binary_path,
        manifest.passive_binary_sha256.as_deref().unwrap_or_default(),
        manifest.rollback_binary,
        manifest
            .manifest_signature_key_id
            .as_deref()
            .unwrap_or_default()
    )
}

fn manifest_signature_payload_without_artifact(manifest: &BlueGreenStagedManifest) -> String {
    format!(
        "timestamp={}\nstatus={}\nactive_slot={}\npassive_slot={}\npassive_binary_path={}\npassive_binary_sha256={}\nrollback_binary={}\nmanifest_signature_key_id={}\n",
        manifest.timestamp,
        manifest.status,
        manifest.active_slot,
        manifest.passive_slot,
        manifest.passive_binary_path,
        manifest.passive_binary_sha256.as_deref().unwrap_or_default(),
        manifest.rollback_binary,
        manifest
            .manifest_signature_key_id
            .as_deref()
            .unwrap_or_default()
    )
}

fn normalized_signing_key_id(manifest_signing_key_id: Option<&str>) -> Option<&str> {
    manifest_signing_key_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn run_healthcheck(
    binary_path: &str,
    args: &[String],
    timeout_secs: u64,
) -> Result<HealthCheckOutput> {
    let binary = PathBuf::from(binary_path);
    if !binary.exists() {
        return Err(anyhow!(
            "staged passive binary does not exist: {}",
            binary.display()
        ));
    }

    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut child = Command::new(&binary)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "failed running health check command '{}' with args {:?}",
                binary.display(),
                args
            )
        })?;

    let started = Instant::now();
    loop {
        if child
            .try_wait()
            .with_context(|| format!("failed checking health command {}", binary.display()))?
            .is_some()
        {
            let output = child.wait_with_output().with_context(|| {
                format!(
                    "failed collecting health command output '{}' with args {:?}",
                    binary.display(),
                    args
                )
            })?;
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Ok(HealthCheckOutput {
                success: output.status.success(),
                timed_out: false,
                exit_code: output.status.code(),
                stdout: summarize_log(&stdout),
                stderr: summarize_log(&stderr),
            });
        }

        if started.elapsed() >= timeout {
            let _ = child.kill();
            let output = child.wait_with_output().ok();
            let stdout = output
                .as_ref()
                .map(|out| String::from_utf8_lossy(&out.stdout).to_string())
                .unwrap_or_default();
            let stderr = output
                .as_ref()
                .map(|out| String::from_utf8_lossy(&out.stderr).to_string())
                .unwrap_or_default();
            let timeout_msg = format!(
                "health check timed out after {} seconds and process was killed",
                timeout.as_secs()
            );
            let merged_stderr = if stderr.trim().is_empty() {
                timeout_msg
            } else {
                format!("{} | {}", timeout_msg, stderr.trim())
            };
            return Ok(HealthCheckOutput {
                success: false,
                timed_out: true,
                exit_code: output.and_then(|out| out.status.code()),
                stdout: summarize_log(&stdout),
                stderr: summarize_log(&merged_stderr),
            });
        }

        thread::sleep(Duration::from_millis(50));
    }
}

fn summarize_log(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.chars().count() <= 500 {
        return trimmed.to_string();
    }
    let prefix = trimmed.chars().take(500).collect::<String>();
    format!("{}...", prefix)
}

fn normalize_skill_name(raw: &str) -> Result<String> {
    let trimmed = raw.trim().strip_suffix(".rhai").unwrap_or(raw.trim());
    if trimmed.is_empty() {
        return Err(anyhow!("skill name is empty"));
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        return Err(anyhow!("skill name must not contain path separators"));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    {
        return Err(anyhow!(
            "invalid skill name '{}'. allowed chars: a-z, 0-9, '_' and '-'",
            trimmed
        ));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        compute_manifest_signature_hex_legacy, compute_manifest_signature_hex_without_artifact,
        compute_manifest_signature_hex_without_version, compute_sha256_hex, read_manifest,
        write_active_slot_marker, write_manifest, EvolutionManager,
    };
    use crate::skills::SkillManager;
    use ed25519_dalek::{Signer, SigningKey};

    fn to_lower_hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>()
    }

    #[test]
    fn stage_and_promote_handles_validation_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let skills = SkillManager::new(dir.path().join("skills")).expect("skills");

        let report = manager
            .stage_and_promote_skill(
                &skills,
                "bad_skill",
                r#"
fn main() {
    let x = ;
}
"#,
            )
            .expect("report");
        assert_eq!(report.status, "validation_failed");
        assert!(report.promoted_path.is_none());
    }

    #[test]
    fn blue_green_plan_selects_passive_slot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        std::fs::write(dir.path().join("artifact.bin"), "bin").expect("artifact");
        std::fs::write(dir.path().join("workspace/current.bin"), "bin").ok();

        let plan = manager
            .plan_blue_green_update(
                dir.path().join("workspace/current.bin"),
                dir.path().join("artifact.bin"),
            )
            .expect("plan");
        assert_eq!(plan.active_slot, "blue");
        assert_eq!(plan.passive_slot, "green");
    }

    #[test]
    fn blue_green_plan_allows_missing_marker_when_signed_policy_enabled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path())
            .expect("evolution")
            .with_active_slot_signing_policy(
                Some("ops-2026"),
                Some("top-secret-signing-key"),
                true,
            );
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        assert_eq!(plan.active_slot, "blue");
        assert_eq!(plan.passive_slot, "green");
    }

    #[test]
    fn active_slot_integrity_reports_valid_signed_marker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path())
            .expect("evolution")
            .with_active_slot_signing_policy(
                Some("ops-2026"),
                Some("top-secret-signing-key"),
                true,
            );
        let marker = dir.path().join("updates").join("active-slot");
        write_active_slot_marker(
            &marker,
            "green",
            Some("ops-2026"),
            Some("top-secret-signing-key"),
            true,
        )
        .expect("write signed marker");

        let report = manager
            .active_slot_integrity_status()
            .expect("integrity report");
        assert_eq!(report.slot.as_deref(), Some("green"));
        assert_eq!(report.status, "valid");
        assert_eq!(report.signature_present, true);
        assert_eq!(report.signature_verified, Some(true));
        assert_eq!(report.key_id.as_deref(), Some("ops-2026"));
    }

    #[test]
    fn active_slot_integrity_detects_marker_signature_tampering() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path())
            .expect("evolution")
            .with_active_slot_signing_policy(
                Some("ops-2026"),
                Some("top-secret-signing-key"),
                true,
            );
        let marker = dir.path().join("updates").join("active-slot");
        write_active_slot_marker(
            &marker,
            "green",
            Some("ops-2026"),
            Some("top-secret-signing-key"),
            true,
        )
        .expect("write signed marker");
        std::fs::write(&marker, "blue\n").expect("tamper marker");

        let report = manager
            .active_slot_integrity_status()
            .expect("integrity report");
        assert_eq!(report.slot.as_deref(), Some("blue"));
        assert_eq!(report.status, "signature_invalid");
        assert_eq!(report.signature_present, true);
        assert_eq!(report.signature_verified, Some(false));
    }

    #[test]
    fn blue_green_plan_rejects_invalid_signed_marker_integrity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path())
            .expect("evolution")
            .with_active_slot_signing_policy(
                Some("ops-2026"),
                Some("top-secret-signing-key"),
                true,
            );
        let marker = dir.path().join("updates").join("active-slot");
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");
        write_active_slot_marker(
            &marker,
            "green",
            Some("ops-2026"),
            Some("top-secret-signing-key"),
            true,
        )
        .expect("write signed marker");
        std::fs::write(&marker, "blue\n").expect("tamper marker");

        let err = manager
            .plan_blue_green_update(&current, &artifact)
            .expect_err("plan should fail on invalid signed marker state");
        assert!(err
            .to_string()
            .contains("active-slot integrity check failed"));
    }

    #[test]
    fn stage_blue_green_update_fails_on_artifact_checksum_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        let err = manager
            .stage_blue_green_update(
                &plan,
                None,
                None,
                Some("0000000000000000000000000000000000000000000000000000000000000000"),
                None,
                None,
                None,
                false,
            )
            .expect_err("stage should fail on checksum mismatch");
        assert!(err
            .to_string()
            .contains("artifact binary checksum mismatch"));
    }

    #[test]
    fn stage_blue_green_update_rejects_rollback_version_when_policy_enabled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        let err = manager
            .stage_blue_green_update(
                &plan,
                None,
                None,
                None,
                None,
                Some("1.4.0"),
                Some("1.3.9"),
                true,
            )
            .expect_err("stage should fail on rollback version");
        assert!(err
            .to_string()
            .contains("must be greater than current version"));
    }

    #[test]
    fn stage_blue_green_update_records_version_metadata() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(
                &plan,
                None,
                None,
                None,
                None,
                Some("1.4.0"),
                Some("1.5.0"),
                true,
            )
            .expect("stage");

        let manifest_path = dir.path().join("updates").join("blue-green-staged.json");
        let manifest = read_manifest(&manifest_path).expect("manifest");
        assert_eq!(manifest.current_binary_version.as_deref(), Some("1.4.0"));
        assert_eq!(manifest.artifact_binary_version.as_deref(), Some("1.5.0"));
    }

    #[test]
    fn resolve_artifact_sha256_from_sums_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let artifact = dir.path().join("artifact.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        let artifact_sha256 = compute_sha256_hex(&artifact).expect("artifact checksum");

        let sums = dir.path().join("SHA256SUMS.txt");
        std::fs::write(
            &sums,
            format!("{artifact_sha256}  {}\n", artifact.display()),
        )
        .expect("write sums");

        let resolved = manager
            .resolve_artifact_sha256_from_sums(&artifact, &sums, None, None, None, None, false)
            .expect("resolve checksum");
        assert_eq!(resolved, artifact_sha256);
    }

    #[test]
    fn resolve_artifact_sha256_from_sums_rejects_untrusted_manifest_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let artifact = dir.path().join("artifact.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        let artifact_sha256 = compute_sha256_hex(&artifact).expect("artifact checksum");

        let sums = dir.path().join("SHA256SUMS.txt");
        std::fs::write(
            &sums,
            format!("{artifact_sha256}  {}\n", artifact.display()),
        )
        .expect("write sums");

        let err = manager
            .resolve_artifact_sha256_from_sums(
                &artifact,
                &sums,
                None,
                Some("0000000000000000000000000000000000000000000000000000000000000000"),
                None,
                None,
                false,
            )
            .expect_err("resolve should fail on untrusted sums hash");
        assert!(err
            .to_string()
            .contains("checksum manifest SHA-256 mismatch"));
    }

    #[test]
    fn resolve_artifact_sha256_from_sums_verifies_detached_signature() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let artifact = dir.path().join("artifact.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        let artifact_sha256 = compute_sha256_hex(&artifact).expect("artifact checksum");

        let sums = dir.path().join("SHA256SUMS.txt");
        std::fs::write(
            &sums,
            format!("{artifact_sha256}  {}\n", artifact.display()),
        )
        .expect("write sums");
        let sums_bytes = std::fs::read(&sums).expect("read sums");

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let signature = signing_key.sign(&sums_bytes);
        let signature_path = dir.path().join("SHA256SUMS.sig");
        std::fs::write(&signature_path, to_lower_hex(&signature.to_bytes())).expect("write sig");
        let public_key_hex = to_lower_hex(verifying_key.as_bytes());

        let resolved = manager
            .resolve_artifact_sha256_from_sums(
                &artifact,
                &sums,
                None,
                None,
                Some(&signature_path),
                Some(public_key_hex.as_str()),
                true,
            )
            .expect("resolve checksum");
        assert_eq!(resolved, artifact_sha256);
    }

    #[test]
    fn resolve_artifact_sha256_from_sums_rejects_invalid_detached_signature() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let artifact = dir.path().join("artifact.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        let artifact_sha256 = compute_sha256_hex(&artifact).expect("artifact checksum");

        let sums = dir.path().join("SHA256SUMS.txt");
        std::fs::write(
            &sums,
            format!("{artifact_sha256}  {}\n", artifact.display()),
        )
        .expect("write sums");

        let signature_path = dir.path().join("SHA256SUMS.sig");
        std::fs::write(&signature_path, "00".repeat(64)).expect("write sig");
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let public_key_hex = to_lower_hex(signing_key.verifying_key().as_bytes());

        let err = manager
            .resolve_artifact_sha256_from_sums(
                &artifact,
                &sums,
                None,
                None,
                Some(&signature_path),
                Some(public_key_hex.as_str()),
                true,
            )
            .expect_err("resolve should fail on invalid detached signature");
        assert!(err
            .to_string()
            .contains("checksum manifest signature verification failed"));
    }

    #[test]
    fn resolve_artifact_sha256_from_sums_requires_signature_when_policy_enabled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let artifact = dir.path().join("artifact.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        let artifact_sha256 = compute_sha256_hex(&artifact).expect("artifact checksum");

        let sums = dir.path().join("SHA256SUMS.txt");
        std::fs::write(
            &sums,
            format!("{artifact_sha256}  {}\n", artifact.display()),
        )
        .expect("write sums");

        let err = manager
            .resolve_artifact_sha256_from_sums(&artifact, &sums, None, None, None, None, true)
            .expect_err("resolve should fail when signature policy is enabled");
        assert!(err
            .to_string()
            .contains("checksum manifest signature is required by policy"));
    }

    #[test]
    fn stage_blue_green_update_records_artifact_checksum_verification() {
        use serde_json::Value;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        let artifact_sha256 = compute_sha256_hex(&artifact).expect("artifact checksum");
        manager
            .stage_blue_green_update(
                &plan,
                None,
                None,
                Some(&artifact_sha256),
                None,
                None,
                None,
                false,
            )
            .expect("stage");

        let manifest_path = dir.path().join("updates").join("blue-green-staged.json");
        let manifest = read_manifest(&manifest_path).expect("manifest");
        assert_eq!(
            manifest.artifact_binary_path.as_deref(),
            Some(plan.artifact_binary.as_str())
        );
        assert_eq!(
            manifest.artifact_binary_sha256.as_deref(),
            Some(artifact_sha256.as_str())
        );
        assert_eq!(manifest.artifact_checksum_verified, Some(true));

        let audit_path = manager.workspace().join("updates/evolution-audit.jsonl");
        let audit_raw = std::fs::read_to_string(&audit_path).expect("audit log");
        let entries = audit_raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<Value>(line).expect("audit json"))
            .collect::<Vec<Value>>();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].get("event").and_then(Value::as_str),
            Some("stage")
        );
        assert_eq!(
            entries[0].get("status").and_then(Value::as_str),
            Some("staged")
        );
        assert!(entries[0]
            .get("hash")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty()));
    }

    #[test]
    fn stage_blue_green_update_audit_log_has_hash_chain_across_entries() {
        use serde_json::Value;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("first stage");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("second stage");

        let audit_path = manager.workspace().join("updates/evolution-audit.jsonl");
        let audit_raw = std::fs::read_to_string(&audit_path).expect("audit log");
        let entries = audit_raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<Value>(line).expect("audit json"))
            .collect::<Vec<Value>>();
        assert_eq!(entries.len(), 2);

        let first_hash = entries[0]
            .get("hash")
            .and_then(Value::as_str)
            .expect("first hash");
        let second_prev_hash = entries[1]
            .get("prev_hash")
            .and_then(Value::as_str)
            .expect("second prev hash");
        assert_eq!(second_prev_hash, first_hash);
    }

    #[test]
    fn lock_status_reports_stale_lock_details() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path())
            .expect("evolution")
            .with_lock_policy(Some(60), true);

        let lock_path = dir.path().join("updates").join("evolution.lock");
        std::fs::write(
            &lock_path,
            "operation=apply-staged-update pid=1234 started_at=2000-01-01T00:00:00Z",
        )
        .expect("write lock");

        let status = manager.lock_status().expect("status");
        assert!(status.lock_exists);
        assert_eq!(status.operation.as_deref(), Some("apply-staged-update"));
        assert_eq!(status.pid, Some(1234));
        assert_eq!(status.stale, Some(true));
        assert_eq!(status.stale_after_secs, Some(60));
    }

    #[test]
    fn force_unlock_removes_existing_lock_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");

        let lock_path = dir.path().join("updates").join("evolution.lock");
        std::fs::write(
            &lock_path,
            "operation=stage-update pid=42 started_at=2000-01-01T00:00:00Z",
        )
        .expect("write lock");

        let status = manager.force_unlock().expect("force unlock");
        assert!(!status.lock_exists);
        assert!(status.force_unlocked);
        assert_eq!(status.operation.as_deref(), Some("stage-update"));
        assert!(!lock_path.exists());
    }

    #[test]
    fn recovery_status_reports_interrupted_apply_context() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("stage");

        let manifest_path = dir.path().join("updates").join("blue-green-staged.json");
        let mut manifest = read_manifest(&manifest_path).expect("manifest");
        manifest.status = "healthcheck_pending".to_string();
        manifest.apply_started_at = Some("2026-01-01T00:00:00Z".to_string());
        manifest.apply_from_slot = Some("blue".to_string());
        manifest.apply_to_slot = Some("green".to_string());
        manifest.apply_resume_count = Some(2);
        manifest.last_recovery_note =
            Some("resumed apply and continued from pending healthcheck checkpoint".to_string());
        manifest.last_observed_active_slot = Some("green".to_string());
        write_manifest(&manifest_path, &manifest).expect("write manifest");
        std::fs::write(dir.path().join("updates").join("active-slot"), "green\n")
            .expect("write active slot");

        let report = manager.recovery_status().expect("recovery status");
        assert!(report.manifest_exists);
        assert_eq!(
            report.manifest_status.as_deref(),
            Some("healthcheck_pending")
        );
        assert_eq!(report.apply_resume_count, 2);
        assert_eq!(report.active_slot_marker.as_deref(), Some("green"));
        assert!(!report.drift_detected);
        assert!(report
            .recommendation
            .as_deref()
            .is_some_and(|value| value.contains("re-run evolution apply-staged-update")));
    }

    #[test]
    fn recovery_status_flags_drift_for_terminal_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("stage");

        let manifest_path = dir.path().join("updates").join("blue-green-staged.json");
        let mut manifest = read_manifest(&manifest_path).expect("manifest");
        manifest.status = "activated".to_string();
        manifest.apply_to_slot = Some("green".to_string());
        write_manifest(&manifest_path, &manifest).expect("write manifest");
        std::fs::write(dir.path().join("updates").join("active-slot"), "blue\n")
            .expect("write active slot");

        let report = manager.recovery_status().expect("recovery status");
        assert!(report.drift_detected);
        assert!(report
            .recommendation
            .as_deref()
            .is_some_and(|value| value.contains("conflicts")));
    }

    #[test]
    fn recovery_status_reports_stale_manifest_age_diagnostics() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path())
            .expect("evolution")
            .with_staged_manifest_age_policy(Some(60));
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("stage");

        let manifest_path = dir.path().join("updates").join("blue-green-staged.json");
        let mut manifest = read_manifest(&manifest_path).expect("manifest");
        manifest.timestamp = "2000-01-01T00:00:00Z".to_string();
        write_manifest(&manifest_path, &manifest).expect("write manifest");

        let report = manager.recovery_status().expect("recovery status");
        assert!(report.manifest_exists);
        assert_eq!(report.manifest_status.as_deref(), Some("staged"));
        assert_eq!(
            report.manifest_timestamp.as_deref(),
            Some("2000-01-01T00:00:00Z")
        );
        assert!(report.manifest_expired);
        assert_eq!(report.manifest_max_age_secs, Some(60));
        assert!(report.manifest_age_secs.is_some_and(|age| age >= 60));
        assert!(report
            .recommendation
            .as_deref()
            .is_some_and(|value| value.contains("stale")));
    }

    #[test]
    fn stage_blue_green_update_fails_when_operation_lock_is_held() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");

        let lock_path = dir.path().join("updates").join("evolution.lock");
        std::fs::write(&lock_path, "operation=apply-staged-update").expect("write lock");

        let err = manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect_err("stage should fail when operation lock is held");
        assert!(err
            .to_string()
            .contains("another evolution operation is already in progress"));
    }

    #[test]
    fn stage_blue_green_update_recovers_stale_lock_when_policy_enabled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path())
            .expect("evolution")
            .with_lock_policy(Some(60), true);
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");
        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");

        let lock_path = dir.path().join("updates").join("evolution.lock");
        std::fs::write(
            &lock_path,
            "operation=apply-staged-update pid=777 started_at=2000-01-01T00:00:00Z",
        )
        .expect("write stale lock");

        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("stage should recover stale lock");
        assert!(!lock_path.exists());
    }

    #[test]
    fn stage_blue_green_update_does_not_recover_stale_lock_when_policy_disabled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path())
            .expect("evolution")
            .with_lock_policy(Some(60), false);
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");
        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");

        let lock_path = dir.path().join("updates").join("evolution.lock");
        std::fs::write(
            &lock_path,
            "operation=apply-staged-update pid=777 started_at=2000-01-01T00:00:00Z",
        )
        .expect("write stale lock");

        let err = manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect_err("stage should fail without stale lock auto recovery");
        assert!(err.to_string().contains("lock appears stale"));
    }

    #[test]
    fn stage_blue_green_update_rejects_when_apply_is_in_progress() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("stage");

        let manifest_path = dir.path().join("updates").join("blue-green-staged.json");
        let mut manifest = read_manifest(&manifest_path).expect("manifest");
        manifest.status = "applying".to_string();
        manifest.apply_started_at = Some("2026-01-01T00:00:00Z".to_string());
        manifest.apply_from_slot = Some("blue".to_string());
        manifest.apply_to_slot = Some("green".to_string());
        write_manifest(&manifest_path, &manifest).expect("write manifest");

        let err = manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect_err("stage should reject in-progress apply state");
        assert!(err
            .to_string()
            .contains("cannot stage while an apply operation is in progress"));
    }

    #[test]
    fn verify_audit_log_succeeds_for_valid_chain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("first stage");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("second stage");

        let report = manager.verify_audit_log().expect("verify audit");
        assert!(report.valid);
        assert_eq!(report.entries, 2);
        assert!(report.last_hash.is_some());
    }

    #[test]
    fn verify_audit_log_fails_when_record_is_tampered() {
        use serde_json::Value;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("stage");

        let audit_path = manager.workspace().join("updates/evolution-audit.jsonl");
        let raw = std::fs::read_to_string(&audit_path).expect("audit");
        let mut record: Value = serde_json::from_str(raw.trim()).expect("record");
        record["status"] = Value::String("tampered".to_string());
        std::fs::write(
            &audit_path,
            format!(
                "{}\n",
                serde_json::to_string(&record).expect("encode tampered")
            ),
        )
        .expect("write tampered");

        let err = manager
            .verify_audit_log()
            .expect_err("verify should fail on tampered record");
        assert!(err.to_string().contains("audit hash mismatch"));
    }

    #[test]
    fn apply_staged_update_fails_when_verified_artifact_provenance_is_required() {
        use serde_json::Value;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("stage");

        let err = manager
            .apply_staged_update(&[], 3, &[], false, true, false, None, None, false)
            .expect_err("apply should fail when verified artifact provenance is required");
        assert!(err.to_string().contains("artifact-checksum-verified"));

        let active_slot = dir.path().join("updates").join("active-slot");
        assert!(
            !active_slot.exists(),
            "active slot should not be switched on provenance failure"
        );

        let manifest_path = dir.path().join("updates").join("blue-green-staged.json");
        let manifest_raw = std::fs::read_to_string(manifest_path).expect("manifest");
        let manifest: Value = serde_json::from_str(&manifest_raw).expect("manifest json");
        assert_eq!(
            manifest.get("status").and_then(Value::as_str),
            Some("provenance_failed")
        );

        let audit_path = manager.workspace().join("updates/evolution-audit.jsonl");
        let audit_raw = std::fs::read_to_string(&audit_path).expect("audit log");
        let last = audit_raw
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .expect("last audit entry");
        let audit: Value = serde_json::from_str(last).expect("audit json");
        assert_eq!(audit.get("event").and_then(Value::as_str), Some("apply"));
        assert_eq!(
            audit.get("status").and_then(Value::as_str),
            Some("provenance_failed")
        );
    }

    #[test]
    fn apply_staged_update_fails_when_non_rollback_version_is_required() {
        use serde_json::Value;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("stage");

        let err = manager
            .apply_staged_update(&[], 3, &[], false, false, false, None, None, true)
            .expect_err("apply should fail when non-rollback version is required");
        assert!(err
            .to_string()
            .contains("staged manifest missing current binary version"));

        let manifest_path = dir.path().join("updates").join("blue-green-staged.json");
        let manifest_raw = std::fs::read_to_string(manifest_path).expect("manifest");
        let manifest: Value = serde_json::from_str(&manifest_raw).expect("manifest json");
        assert_eq!(
            manifest.get("status").and_then(Value::as_str),
            Some("version_failed")
        );
    }

    #[test]
    fn apply_staged_update_fails_when_operation_lock_is_held() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let lock_path = dir.path().join("updates").join("evolution.lock");
        std::fs::write(&lock_path, "operation=stage-update").expect("write lock");

        let err = manager
            .apply_staged_update(&[], 3, &[], false, false, false, None, None, false)
            .expect_err("apply should fail when operation lock is held");
        assert!(err
            .to_string()
            .contains("another evolution operation is already in progress"));
    }

    #[test]
    fn apply_staged_update_fails_when_staged_manifest_is_stale() {
        use serde_json::Value;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path())
            .expect("evolution")
            .with_staged_manifest_age_policy(Some(60));
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("stage");

        let manifest_path = dir.path().join("updates").join("blue-green-staged.json");
        let mut manifest = read_manifest(&manifest_path).expect("manifest");
        manifest.timestamp = "2000-01-01T00:00:00Z".to_string();
        write_manifest(&manifest_path, &manifest).expect("write manifest");

        let err = manager
            .apply_staged_update(&[], 3, &[], false, false, false, None, None, false)
            .expect_err("apply should fail when staged manifest is stale");
        assert!(err.to_string().contains("stale"));

        let manifest_raw = std::fs::read_to_string(manifest_path).expect("manifest");
        let manifest: Value = serde_json::from_str(&manifest_raw).expect("manifest json");
        assert_eq!(
            manifest.get("status").and_then(Value::as_str),
            Some("stale_failed")
        );
    }

    #[test]
    fn apply_staged_update_fails_when_signed_checksum_manifest_provenance_is_tampered() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");
        let artifact = dir.path().join("artifact.bin");
        let current = dir.path().join("current.bin");
        std::fs::write(&artifact, "artifact").expect("write artifact");
        std::fs::write(&current, "current").expect("write current");

        let artifact_sha256 = compute_sha256_hex(&artifact).expect("artifact checksum");
        let sums = dir.path().join("SHA256SUMS.txt");
        std::fs::write(
            &sums,
            format!("{artifact_sha256}  {}\n", artifact.display()),
        )
        .expect("write sums");
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let sums_raw = std::fs::read(&sums).expect("read sums");
        let signature = signing_key.sign(&sums_raw);
        let sums_sig = dir.path().join("SHA256SUMS.sig");
        std::fs::write(&sums_sig, to_lower_hex(&signature.to_bytes())).expect("write signature");
        let public_key_hex = to_lower_hex(signing_key.verifying_key().as_bytes());

        let resolved = manager
            .resolve_artifact_sha256_from_sums_with_provenance(
                &artifact,
                &sums,
                None,
                None,
                Some(&sums_sig),
                Some(public_key_hex.as_str()),
                true,
            )
            .expect("resolve with provenance");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(
                &plan,
                None,
                None,
                Some(&resolved.artifact_sha256),
                Some(resolved.checksum_manifest),
                None,
                None,
                false,
            )
            .expect("stage");

        std::fs::write(
            &sums,
            format!("{artifact_sha256}  {}\n# tampered\n", artifact.display()),
        )
        .expect("tamper sums");

        let err = manager
            .apply_staged_update(
                &[],
                3,
                &[],
                false,
                false,
                true,
                None,
                Some(public_key_hex.as_str()),
                false,
            )
            .expect_err("apply should fail on tampered checksum manifest");
        assert!(err
            .to_string()
            .contains("recorded checksum manifest SHA-256 mismatch at apply time"));
    }

    #[cfg(unix)]
    #[test]
    fn apply_staged_update_succeeds_with_required_signed_checksum_manifest_provenance() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");

        let artifact = dir.path().join("artifact-ok.sh");
        std::fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");
        let mut artifact_perm = std::fs::metadata(&artifact).expect("meta").permissions();
        artifact_perm.set_mode(0o755);
        std::fs::set_permissions(&artifact, artifact_perm).expect("chmod artifact");

        let current = dir.path().join("current.sh");
        std::fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");
        let mut current_perm = std::fs::metadata(&current).expect("meta").permissions();
        current_perm.set_mode(0o755);
        std::fs::set_permissions(&current, current_perm).expect("chmod current");

        let artifact_sha256 = compute_sha256_hex(&artifact).expect("artifact checksum");
        let sums = dir.path().join("SHA256SUMS.txt");
        std::fs::write(
            &sums,
            format!("{artifact_sha256}  {}\n", artifact.display()),
        )
        .expect("write sums");
        let sums_sha256 = compute_sha256_hex(&sums).expect("sums checksum");

        let signing_key = SigningKey::from_bytes(&[77u8; 32]);
        let sums_raw = std::fs::read(&sums).expect("read sums");
        let signature = signing_key.sign(&sums_raw);
        let sums_sig = dir.path().join("SHA256SUMS.sig");
        std::fs::write(&sums_sig, to_lower_hex(&signature.to_bytes())).expect("write signature");
        let public_key_hex = to_lower_hex(signing_key.verifying_key().as_bytes());

        let resolved = manager
            .resolve_artifact_sha256_from_sums_with_provenance(
                &artifact,
                &sums,
                None,
                Some(sums_sha256.as_str()),
                Some(&sums_sig),
                Some(public_key_hex.as_str()),
                true,
            )
            .expect("resolve with provenance");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(
                &plan,
                None,
                None,
                Some(&resolved.artifact_sha256),
                Some(resolved.checksum_manifest),
                None,
                None,
                false,
            )
            .expect("stage");

        let report = manager
            .apply_staged_update(
                &[],
                3,
                &[],
                false,
                false,
                true,
                Some(sums_sha256.as_str()),
                Some(public_key_hex.as_str()),
                false,
            )
            .expect("apply");
        assert!(report.healthcheck_ok);
        assert!(!report.rollback_performed);
    }

    #[cfg(unix)]
    #[test]
    fn apply_staged_update_rolls_back_on_failed_healthcheck() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");

        let artifact = dir.path().join("artifact-fail.sh");
        std::fs::write(&artifact, "#!/bin/sh\nexit 1\n").expect("write artifact");
        let mut perm = std::fs::metadata(&artifact).expect("meta").permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&artifact, perm).expect("chmod");

        let current = dir.path().join("current.sh");
        std::fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("stage");

        let report = manager
            .apply_staged_update(&[], 3, &[], false, false, false, None, None, false)
            .expect("apply staged update");
        assert!(report.rollback_performed);
        assert!(!report.healthcheck_ok);

        let active = std::fs::read_to_string(dir.path().join("updates").join("active-slot"))
            .expect("active slot");
        assert_eq!(active.trim(), "blue");
    }

    #[cfg(unix)]
    #[test]
    fn apply_failure_circuit_blocks_apply_after_threshold() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path())
            .expect("evolution")
            .with_apply_failure_policy(Some(2));

        let artifact = dir.path().join("artifact-fail.sh");
        std::fs::write(&artifact, "#!/bin/sh\nexit 1\n").expect("write artifact");
        let mut artifact_perm = std::fs::metadata(&artifact).expect("meta").permissions();
        artifact_perm.set_mode(0o755);
        std::fs::set_permissions(&artifact, artifact_perm).expect("chmod artifact");

        let current = dir.path().join("current.sh");
        std::fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");
        let mut current_perm = std::fs::metadata(&current).expect("meta").permissions();
        current_perm.set_mode(0o755);
        std::fs::set_permissions(&current, current_perm).expect("chmod current");

        for _ in 0..2 {
            let plan = manager
                .plan_blue_green_update(&current, &artifact)
                .expect("plan");
            manager
                .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
                .expect("stage");
            let report = manager
                .apply_staged_update(&[], 3, &[], false, false, false, None, None, false)
                .expect("apply");
            assert_eq!(report.status, "rolled_back");
        }

        let circuit = manager
            .apply_failure_circuit_status()
            .expect("failure-circuit status");
        assert_eq!(circuit.threshold, Some(2));
        assert_eq!(circuit.consecutive_failures, 2);
        assert!(circuit.circuit_open);

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("stage");
        let err = manager
            .apply_staged_update(&[], 3, &[], false, false, false, None, None, false)
            .expect_err("apply should be blocked by failure circuit");
        assert!(err.to_string().contains("failure circuit"));
    }

    #[cfg(unix)]
    #[test]
    fn apply_failure_circuit_reset_allows_subsequent_success() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path())
            .expect("evolution")
            .with_apply_failure_policy(Some(1));

        let artifact = dir.path().join("artifact.sh");
        std::fs::write(&artifact, "#!/bin/sh\nexit 1\n").expect("write artifact");
        let mut artifact_perm = std::fs::metadata(&artifact).expect("meta").permissions();
        artifact_perm.set_mode(0o755);
        std::fs::set_permissions(&artifact, artifact_perm).expect("chmod artifact");

        let current = dir.path().join("current.sh");
        std::fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");
        let mut current_perm = std::fs::metadata(&current).expect("meta").permissions();
        current_perm.set_mode(0o755);
        std::fs::set_permissions(&current, current_perm).expect("chmod current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("stage");
        let report = manager
            .apply_staged_update(&[], 3, &[], false, false, false, None, None, false)
            .expect("apply");
        assert_eq!(report.status, "rolled_back");

        let blocked = manager
            .apply_failure_circuit_status()
            .expect("failure-circuit status");
        assert!(blocked.circuit_open);
        assert_eq!(blocked.consecutive_failures, 1);

        let reset = manager
            .reset_apply_failure_circuit()
            .expect("reset failure circuit");
        assert!(!reset.circuit_open);
        assert_eq!(reset.consecutive_failures, 0);

        std::fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("rewrite artifact");
        let mut artifact_perm = std::fs::metadata(&artifact).expect("meta").permissions();
        artifact_perm.set_mode(0o755);
        std::fs::set_permissions(&artifact, artifact_perm).expect("chmod artifact");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("stage");
        let report = manager
            .apply_staged_update(&[], 3, &[], false, false, false, None, None, false)
            .expect("apply after reset");
        assert_eq!(report.status, "activated");

        let status = manager
            .apply_failure_circuit_status()
            .expect("failure-circuit status");
        assert!(!status.circuit_open);
        assert_eq!(status.consecutive_failures, 0);
        assert!(status.last_success_at.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn apply_staged_update_switches_active_slot_on_success() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");

        let artifact = dir.path().join("artifact-ok.sh");
        std::fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");
        let mut perm = std::fs::metadata(&artifact).expect("meta").permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&artifact, perm).expect("chmod");

        let current = dir.path().join("current.sh");
        std::fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("stage");

        let report = manager
            .apply_staged_update(&[], 3, &[], false, false, false, None, None, false)
            .expect("apply staged update");
        assert!(!report.rollback_performed);
        assert!(report.healthcheck_ok);

        let active = std::fs::read_to_string(dir.path().join("updates").join("active-slot"))
            .expect("active slot");
        assert_eq!(active.trim(), "green");
    }

    #[cfg(unix)]
    #[test]
    fn apply_staged_update_is_idempotent_after_activation() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");

        let artifact = dir.path().join("artifact-ok.sh");
        std::fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");
        let mut perm = std::fs::metadata(&artifact).expect("meta").permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&artifact, perm).expect("chmod");

        let current = dir.path().join("current.sh");
        std::fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("stage");

        let first = manager
            .apply_staged_update(&[], 3, &[], false, false, false, None, None, false)
            .expect("first apply");
        assert_eq!(first.status, "activated");
        assert!(first.healthcheck_ok);
        assert!(!first.rollback_performed);

        let second = manager
            .apply_staged_update(&[], 3, &[], false, false, false, None, None, false)
            .expect("second apply should be idempotent");
        assert_eq!(second.status, "activated");
        assert_eq!(second.from_slot, first.from_slot);
        assert_eq!(second.to_slot, first.to_slot);
        assert!(second.healthcheck_ok);
        assert!(!second.rollback_performed);
    }

    #[cfg(unix)]
    #[test]
    fn apply_staged_update_resumes_from_healthcheck_pending_state() {
        use serde_json::Value;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");

        let artifact = dir.path().join("artifact-ok.sh");
        std::fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");
        let mut perm = std::fs::metadata(&artifact).expect("meta").permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&artifact, perm).expect("chmod");

        let current = dir.path().join("current.sh");
        std::fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("stage");

        let manifest_path = dir.path().join("updates").join("blue-green-staged.json");
        let mut manifest = read_manifest(&manifest_path).expect("manifest");
        manifest.status = "healthcheck_pending".to_string();
        manifest.apply_started_at = Some("2026-01-01T00:00:00Z".to_string());
        manifest.apply_from_slot = Some(manifest.active_slot.clone());
        manifest.apply_to_slot = Some(manifest.passive_slot.clone());
        manifest.apply_resume_count = Some(1);
        manifest.last_recovery_note = Some("resumed apply invocation from 'applying'".to_string());
        manifest.last_observed_active_slot = Some(manifest.passive_slot.clone());
        write_manifest(&manifest_path, &manifest).expect("write manifest");
        std::fs::write(
            dir.path().join("updates").join("active-slot"),
            format!("{}\n", manifest.passive_slot),
        )
        .expect("write active slot");

        let report = manager
            .apply_staged_update(&[], 3, &[], false, false, false, None, None, false)
            .expect("apply resume");
        assert_eq!(report.status, "activated");
        assert!(report.healthcheck_ok);
        assert!(!report.rollback_performed);

        let manifest = read_manifest(&manifest_path).expect("manifest");
        assert_eq!(manifest.status, "activated");
        assert!(manifest.apply_started_at.is_none());
        assert!(manifest.apply_from_slot.is_none());
        assert!(manifest.apply_to_slot.is_none());
        assert_eq!(manifest.apply_resume_count, Some(2));
        assert!(manifest
            .last_recovery_note
            .as_deref()
            .is_some_and(|value| value.contains("resumed")));
        assert_eq!(manifest.last_observed_active_slot.as_deref(), Some("green"));

        let audit_path = dir.path().join("updates").join("evolution-audit.jsonl");
        let audit_raw = std::fs::read_to_string(&audit_path).expect("audit log");
        let last = audit_raw
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .expect("last audit entry");
        let audit: Value = serde_json::from_str(last).expect("audit json");
        assert_eq!(audit.get("event").and_then(Value::as_str), Some("apply"));
        assert_eq!(
            audit.get("status").and_then(Value::as_str),
            Some("activated")
        );
        assert_eq!(
            audit.get("apply_resume_count").and_then(Value::as_u64),
            Some(2)
        );
        assert!(audit
            .get("last_recovery_note")
            .and_then(Value::as_str)
            .is_some_and(|value| value.contains("resumed")));
    }

    #[cfg(unix)]
    #[test]
    fn apply_staged_update_times_out_and_rolls_back() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");

        let artifact = dir.path().join("artifact-timeout.sh");
        std::fs::write(&artifact, "#!/bin/sh\nsleep 2\nexit 0\n").expect("write artifact");
        let mut perm = std::fs::metadata(&artifact).expect("meta").permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&artifact, perm).expect("chmod");

        let current = dir.path().join("current.sh");
        std::fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("stage");

        let report = manager
            .apply_staged_update(&[], 1, &[], false, false, false, None, None, false)
            .expect("apply staged update");
        assert!(report.rollback_performed);
        assert!(report.healthcheck_timed_out);
        assert!(!report.healthcheck_ok);
    }

    #[cfg(unix)]
    #[test]
    fn apply_staged_update_fails_on_checksum_mismatch() {
        use serde_json::Value;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");

        let artifact = dir.path().join("artifact-ok.sh");
        std::fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");
        let mut perm = std::fs::metadata(&artifact).expect("meta").permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&artifact, perm).expect("chmod");

        let current = dir.path().join("current.sh");
        std::fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(&plan, None, None, None, None, None, None, false)
            .expect("stage");

        let mut staged = std::fs::OpenOptions::new()
            .append(true)
            .open(&plan.passive_binary_path)
            .expect("open staged");
        staged.write_all(b"\n# tampered\n").expect("tamper staged");

        let err = manager
            .apply_staged_update(&[], 3, &[], false, false, false, None, None, false)
            .expect_err("apply should fail on checksum mismatch");
        assert!(err.to_string().contains("checksum mismatch"));

        let active_slot = dir.path().join("updates").join("active-slot");
        assert!(
            !active_slot.exists(),
            "active slot should not be switched on integrity failure"
        );

        let manifest_path = dir.path().join("updates").join("blue-green-staged.json");
        let manifest_raw = std::fs::read_to_string(manifest_path).expect("manifest");
        let manifest: Value = serde_json::from_str(&manifest_raw).expect("manifest json");
        assert_eq!(
            manifest.get("status").and_then(Value::as_str),
            Some("integrity_failed")
        );
    }

    #[cfg(unix)]
    #[test]
    fn apply_staged_update_fails_on_manifest_signature_mismatch() {
        use serde_json::Value;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");

        let artifact = dir.path().join("artifact-ok.sh");
        std::fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");
        let mut perm = std::fs::metadata(&artifact).expect("meta").permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&artifact, perm).expect("chmod");

        let current = dir.path().join("current.sh");
        std::fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(
                &plan,
                Some("v1"),
                Some("top-secret-signing-key"),
                None,
                None,
                None,
                None,
                false,
            )
            .expect("stage");

        let manifest_path = dir.path().join("updates").join("blue-green-staged.json");
        let manifest_raw = std::fs::read_to_string(&manifest_path).expect("manifest");
        let mut manifest: Value = serde_json::from_str(&manifest_raw).expect("manifest json");
        manifest["manifest_signature"] = Value::String("bad-signature".to_string());
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).expect("encode manifest"),
        )
        .expect("write manifest");

        let err = manager
            .apply_staged_update(
                &[],
                3,
                &[("v1".to_string(), "top-secret-signing-key".to_string())],
                true,
                false,
                false,
                None,
                None,
                false,
            )
            .expect_err("apply should fail on signature mismatch");
        assert!(err.to_string().contains("signature mismatch"));

        let active_slot = dir.path().join("updates").join("active-slot");
        assert!(
            !active_slot.exists(),
            "active slot should not be switched on signature failure"
        );

        let manifest_raw = std::fs::read_to_string(&manifest_path).expect("manifest");
        let manifest: Value = serde_json::from_str(&manifest_raw).expect("manifest json");
        assert_eq!(
            manifest.get("status").and_then(Value::as_str),
            Some("signature_failed")
        );
    }

    #[cfg(unix)]
    #[test]
    fn apply_staged_update_fails_when_signed_artifact_provenance_fields_are_tampered() {
        use serde_json::Value;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");

        let artifact = dir.path().join("artifact-ok.sh");
        std::fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");
        let mut perm = std::fs::metadata(&artifact).expect("meta").permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&artifact, perm).expect("chmod");

        let current = dir.path().join("current.sh");
        std::fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        let artifact_sha256 = compute_sha256_hex(&artifact).expect("checksum");
        manager
            .stage_blue_green_update(
                &plan,
                Some("v1"),
                Some("top-secret-signing-key"),
                Some(&artifact_sha256),
                None,
                None,
                None,
                false,
            )
            .expect("stage");

        let manifest_path = dir.path().join("updates").join("blue-green-staged.json");
        let manifest_raw = std::fs::read_to_string(&manifest_path).expect("manifest");
        let mut manifest: Value = serde_json::from_str(&manifest_raw).expect("manifest json");
        manifest["artifact_checksum_verified"] = Value::Bool(false);
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).expect("encode manifest"),
        )
        .expect("write manifest");

        let err = manager
            .apply_staged_update(
                &[],
                3,
                &[("v1".to_string(), "top-secret-signing-key".to_string())],
                true,
                false,
                false,
                None,
                None,
                false,
            )
            .expect_err("apply should fail on signature mismatch");
        assert!(err.to_string().contains("signature mismatch"));
    }

    #[cfg(unix)]
    #[test]
    fn apply_staged_update_uses_manifest_key_id_for_key_rotation() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");

        let artifact = dir.path().join("artifact-ok.sh");
        std::fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");
        let mut perm = std::fs::metadata(&artifact).expect("meta").permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&artifact, perm).expect("chmod");

        let current = dir.path().join("current.sh");
        std::fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(
                &plan,
                Some("2026-q1"),
                Some("new-signing-key"),
                None,
                None,
                None,
                None,
                false,
            )
            .expect("stage");

        let report = manager
            .apply_staged_update(
                &[],
                3,
                &[
                    ("2025-q4".to_string(), "old-signing-key".to_string()),
                    ("2026-q1".to_string(), "new-signing-key".to_string()),
                ],
                true,
                false,
                false,
                None,
                None,
                false,
            )
            .expect("apply");
        assert!(report.healthcheck_ok);
        assert!(!report.rollback_performed);
    }

    #[cfg(unix)]
    #[test]
    fn apply_staged_update_fails_when_manifest_key_id_not_in_keyring() {
        use serde_json::Value;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");

        let artifact = dir.path().join("artifact-ok.sh");
        std::fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");
        let mut perm = std::fs::metadata(&artifact).expect("meta").permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&artifact, perm).expect("chmod");

        let current = dir.path().join("current.sh");
        std::fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(
                &plan,
                Some("2026-q1"),
                Some("new-signing-key"),
                None,
                None,
                None,
                None,
                false,
            )
            .expect("stage");

        let err = manager
            .apply_staged_update(
                &[],
                3,
                &[("2025-q4".to_string(), "old-signing-key".to_string())],
                true,
                false,
                false,
                None,
                None,
                false,
            )
            .expect_err("apply should fail when manifest key id is unavailable");
        assert!(err
            .to_string()
            .contains("key id '2026-q1' is not configured"));

        let manifest_path = dir.path().join("updates").join("blue-green-staged.json");
        let manifest_raw = std::fs::read_to_string(&manifest_path).expect("manifest");
        let manifest: Value = serde_json::from_str(&manifest_raw).expect("manifest json");
        assert_eq!(
            manifest.get("status").and_then(Value::as_str),
            Some("signature_failed")
        );
    }

    #[cfg(unix)]
    #[test]
    fn apply_staged_update_accepts_legacy_unsigned_key_id_manifest_with_single_key() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");

        let artifact = dir.path().join("artifact-ok.sh");
        std::fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");
        let mut perm = std::fs::metadata(&artifact).expect("meta").permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&artifact, perm).expect("chmod");

        let current = dir.path().join("current.sh");
        std::fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(
                &plan,
                Some("legacy"),
                Some("legacy-signing-key"),
                None,
                None,
                None,
                None,
                false,
            )
            .expect("stage");

        let manifest_path = dir.path().join("updates").join("blue-green-staged.json");
        let mut manifest = read_manifest(&manifest_path).expect("read manifest");
        manifest.manifest_signature_key_id = None;
        manifest.manifest_signature = Some(
            compute_manifest_signature_hex_legacy(&manifest, "legacy-signing-key")
                .expect("compute legacy signature"),
        );
        write_manifest(&manifest_path, &manifest).expect("write manifest");

        let report = manager
            .apply_staged_update(
                &[],
                3,
                &[("legacy".to_string(), "legacy-signing-key".to_string())],
                true,
                false,
                false,
                None,
                None,
                false,
            )
            .expect("apply");
        assert!(report.healthcheck_ok);
    }

    #[cfg(unix)]
    #[test]
    fn apply_staged_update_accepts_key_id_signature_without_artifact_payload_fields() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");

        let artifact = dir.path().join("artifact-ok.sh");
        std::fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");
        let mut perm = std::fs::metadata(&artifact).expect("meta").permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&artifact, perm).expect("chmod");

        let current = dir.path().join("current.sh");
        std::fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(
                &plan,
                Some("v1"),
                Some("top-secret-signing-key"),
                None,
                None,
                None,
                None,
                false,
            )
            .expect("stage");

        let manifest_path = dir.path().join("updates").join("blue-green-staged.json");
        let mut manifest = read_manifest(&manifest_path).expect("read manifest");
        manifest.manifest_signature = Some(
            compute_manifest_signature_hex_without_artifact(&manifest, "top-secret-signing-key")
                .expect("compute v2 signature"),
        );
        write_manifest(&manifest_path, &manifest).expect("write manifest");

        let report = manager
            .apply_staged_update(
                &[],
                3,
                &[("v1".to_string(), "top-secret-signing-key".to_string())],
                true,
                false,
                false,
                None,
                None,
                false,
            )
            .expect("apply should accept older key-id signature format");
        assert!(report.healthcheck_ok);
    }

    #[cfg(unix)]
    #[test]
    fn apply_staged_update_accepts_key_id_signature_without_version_payload_fields() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let manager = EvolutionManager::new(dir.path()).expect("evolution");

        let artifact = dir.path().join("artifact-ok.sh");
        std::fs::write(&artifact, "#!/bin/sh\nexit 0\n").expect("write artifact");
        let mut perm = std::fs::metadata(&artifact).expect("meta").permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&artifact, perm).expect("chmod");

        let current = dir.path().join("current.sh");
        std::fs::write(&current, "#!/bin/sh\nexit 0\n").expect("write current");

        let plan = manager
            .plan_blue_green_update(&current, &artifact)
            .expect("plan");
        manager
            .stage_blue_green_update(
                &plan,
                Some("v1"),
                Some("top-secret-signing-key"),
                None,
                None,
                Some("1.0.0"),
                Some("1.1.0"),
                false,
            )
            .expect("stage");

        let manifest_path = dir.path().join("updates").join("blue-green-staged.json");
        let mut manifest = read_manifest(&manifest_path).expect("read manifest");
        manifest.manifest_signature = Some(
            compute_manifest_signature_hex_without_version(&manifest, "top-secret-signing-key")
                .expect("compute old version signature"),
        );
        write_manifest(&manifest_path, &manifest).expect("write manifest");

        let report = manager
            .apply_staged_update(
                &[],
                3,
                &[("v1".to_string(), "top-secret-signing-key".to_string())],
                true,
                false,
                false,
                None,
                None,
                false,
            )
            .expect("apply should accept older key-id signature payload");
        assert!(report.healthcheck_ok);
    }
}
