use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};

static APPROVAL_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PulseAction {
    CodexHealthCheck,
    CodexDrainQueueOne,
    EmitLog {
        message: String,
    },
    HttpHealthCheck {
        url: String,
        expected_status: u16,
        timeout_secs: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PulseJobSpec {
    pub id: String,
    pub interval_secs: u64,
    pub action: PulseAction,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PulseJobSnapshot {
    pub id: String,
    pub interval_secs: u64,
    pub action: PulseAction,
    pub enabled: bool,
    pub runs: u64,
    pub next_due_at: String,
    pub last_run_at: Option<String>,
    pub last_status: Option<String>,
    pub last_message: Option<String>,
}

#[derive(Debug, Clone)]
struct PulseJobState {
    spec: PulseJobSpec,
    runs: u64,
    next_due: Instant,
    next_due_at: String,
    last_run_at: Option<String>,
    last_status: Option<String>,
    last_message: Option<String>,
}

impl PulseJobState {
    fn new(spec: PulseJobSpec) -> Self {
        let interval_secs = spec.interval_secs.max(1);
        let now = Instant::now();
        let due = now + Duration::from_secs(interval_secs);
        Self {
            spec,
            runs: 0,
            next_due: due,
            next_due_at: Utc::now()
                .checked_add_signed(chrono::TimeDelta::seconds(
                    i64::try_from(interval_secs).unwrap_or(i64::MAX),
                ))
                .unwrap_or_else(Utc::now)
                .to_rfc3339(),
            last_run_at: None,
            last_status: None,
            last_message: None,
        }
    }

    fn is_due(&self, now: Instant) -> bool {
        self.spec.enabled && now >= self.next_due
    }

    fn schedule_next(&mut self) {
        let interval = Duration::from_secs(self.spec.interval_secs.max(1));
        self.next_due = Instant::now() + interval;
        self.next_due_at = Utc::now()
            .checked_add_signed(chrono::TimeDelta::seconds(
                i64::try_from(self.spec.interval_secs.max(1)).unwrap_or(i64::MAX),
            ))
            .unwrap_or_else(Utc::now)
            .to_rfc3339();
    }

    fn snapshot(&self) -> PulseJobSnapshot {
        PulseJobSnapshot {
            id: self.spec.id.clone(),
            interval_secs: self.spec.interval_secs,
            action: self.spec.action.clone(),
            enabled: self.spec.enabled,
            runs: self.runs,
            next_due_at: self.next_due_at.clone(),
            last_run_at: self.last_run_at.clone(),
            last_status: self.last_status.clone(),
            last_message: self.last_message.clone(),
        }
    }

    fn replay_from_snapshot(&mut self, snapshot: &PulseJobSnapshot) {
        self.runs = snapshot.runs;
        self.last_run_at = snapshot.last_run_at.clone();
        self.last_status = snapshot.last_status.clone();
        self.last_message = snapshot.last_message.clone();
        self.spec.enabled = snapshot.enabled;

        if let Some(remaining_secs) = remaining_seconds_until(&snapshot.next_due_at) {
            self.next_due = Instant::now() + Duration::from_secs(remaining_secs.max(1));
            self.next_due_at = snapshot.next_due_at.clone();
        } else {
            self.schedule_next();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OodaObservation {
    pub source: String,
    pub key: String,
    pub value: String,
    #[serde(default = "default_observation_severity")]
    pub severity: String,
}

fn default_observation_severity() -> String {
    "info".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OodaCycleReport {
    pub timestamp: String,
    pub observations: Vec<OodaObservation>,
    pub orientation: String,
    pub decision: String,
    pub action: String,
    pub risk: RiskLevel,
    pub approval_status: ApprovalStatus,
    pub approval_token: Option<String>,
    pub goal_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Approved,
    Pending,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApproval {
    pub token: String,
    pub action: String,
    pub risk: RiskLevel,
    pub reason: String,
    pub created_at: String,
    pub status: ApprovalStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoalSnapshot {
    pub id: String,
    pub description: String,
    pub achieved: bool,
    pub updated_at: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone)]
struct GoalState {
    id: String,
    description: String,
    achieved: bool,
    updated_at: String,
    notes: Option<String>,
}

impl GoalState {
    fn new(id: &str, description: &str) -> Self {
        Self {
            id: id.to_string(),
            description: description.to_string(),
            achieved: false,
            updated_at: Utc::now().to_rfc3339(),
            notes: None,
        }
    }

    fn snapshot(&self) -> GoalSnapshot {
        GoalSnapshot {
            id: self.id.clone(),
            description: self.description.clone(),
            achieved: self.achieved,
            updated_at: self.updated_at.clone(),
            notes: self.notes.clone(),
        }
    }

    fn from_snapshot(snapshot: GoalSnapshot) -> Self {
        Self {
            id: snapshot.id,
            description: snapshot.description,
            achieved: snapshot.achieved,
            updated_at: snapshot.updated_at,
            notes: snapshot.notes,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PulseStatus {
    pub jobs: Vec<PulseJobSnapshot>,
    pub pending_approvals: Vec<PendingApproval>,
    pub goals: Vec<GoalSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
struct PulsePersistentState {
    pub updated_at: String,
    pub jobs: Vec<PulseJobSnapshot>,
    pub pending_approvals: Vec<PendingApproval>,
    pub goals: Vec<GoalSnapshot>,
}

impl Default for PulsePersistentState {
    fn default() -> Self {
        Self {
            updated_at: Utc::now().to_rfc3339(),
            jobs: Vec::new(),
            pending_approvals: Vec::new(),
            goals: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PulseDueJob {
    pub id: String,
    pub action: PulseAction,
}

pub struct PulseRuntime {
    jobs: BTreeMap<String, PulseJobState>,
    pending_approvals: BTreeMap<String, PendingApproval>,
    goals: BTreeMap<String, GoalState>,
    auto_allow_actions: Vec<String>,
}

impl Default for PulseRuntime {
    fn default() -> Self {
        Self {
            jobs: BTreeMap::new(),
            pending_approvals: BTreeMap::new(),
            goals: BTreeMap::new(),
            auto_allow_actions: Vec::new(),
        }
    }
}

impl PulseRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_auto_allow_actions(actions: Vec<String>) -> Self {
        let mut runtime = Self::default();
        runtime.auto_allow_actions = actions
            .into_iter()
            .map(|value| value.to_ascii_lowercase())
            .filter(|value| !value.trim().is_empty())
            .collect();
        runtime
    }

    pub fn load_persistent_state(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(());
        }

        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed reading pulse state {}", path.display()))?;
        let state: PulsePersistentState = serde_json::from_str(&raw)
            .with_context(|| format!("failed decoding pulse state {}", path.display()))?;

        for snapshot in state.jobs {
            if let Some(job) = self.jobs.get_mut(&snapshot.id) {
                job.replay_from_snapshot(&snapshot);
                continue;
            }

            let snapshot_id = snapshot.id.clone();
            self.register_job(PulseJobSpec {
                id: snapshot_id.clone(),
                interval_secs: snapshot.interval_secs.max(1),
                action: snapshot.action.clone(),
                enabled: snapshot.enabled,
            })
            .with_context(|| format!("failed restoring pulse job '{}'", snapshot_id))?;

            if let Some(job) = self.jobs.get_mut(&snapshot_id) {
                job.replay_from_snapshot(&snapshot);
            }
        }

        self.pending_approvals.clear();
        for approval in state.pending_approvals {
            if matches!(approval.status, ApprovalStatus::Pending) {
                self.pending_approvals
                    .insert(approval.token.clone(), approval);
            }
        }

        self.goals.clear();
        for goal in state.goals {
            self.goals
                .insert(goal.id.clone(), GoalState::from_snapshot(goal));
        }

        Ok(())
    }

    pub fn persist_persistent_state(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed creating pulse state dir {}", parent.display()))?;
        }

        let state = PulsePersistentState {
            updated_at: Utc::now().to_rfc3339(),
            jobs: self.jobs.values().map(PulseJobState::snapshot).collect(),
            pending_approvals: self.pending_approvals.values().cloned().collect(),
            goals: self.goals.values().map(GoalState::snapshot).collect(),
        };
        let payload =
            serde_json::to_string_pretty(&state).context("failed encoding pulse state")?;
        let tmp = path.with_extension("tmp");

        fs::write(&tmp, payload)
            .with_context(|| format!("failed writing pulse temp state {}", tmp.display()))?;
        fs::rename(&tmp, path).with_context(|| {
            format!(
                "failed replacing pulse state file {} -> {}",
                tmp.display(),
                path.display()
            )
        })?;

        Ok(())
    }

    pub fn register_default_jobs(&mut self, codex_enabled: bool) -> Result<()> {
        self.register_job(PulseJobSpec {
            id: "runtime-heartbeat".to_string(),
            interval_secs: 60,
            action: PulseAction::EmitLog {
                message: "pulse heartbeat".to_string(),
            },
            enabled: true,
        })?;
        if codex_enabled {
            self.register_job(PulseJobSpec {
                id: "codex-healthcheck".to_string(),
                interval_secs: 120,
                action: PulseAction::CodexHealthCheck,
                enabled: true,
            })?;
            self.register_job(PulseJobSpec {
                id: "codex-drain-queue".to_string(),
                interval_secs: 30,
                action: PulseAction::CodexDrainQueueOne,
                enabled: true,
            })?;
        }
        Ok(())
    }

    pub fn register_job(&mut self, spec: PulseJobSpec) -> Result<()> {
        let id = spec.id.trim();
        if id.is_empty() {
            return Err(anyhow!("pulse job id is empty"));
        }
        if !id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        {
            return Err(anyhow!(
                "invalid pulse job id '{}'. allowed: a-z, 0-9, '_' and '-'",
                id
            ));
        }
        if spec.interval_secs == 0 {
            return Err(anyhow!("pulse job interval must be >= 1 second"));
        }

        self.jobs.insert(id.to_string(), PulseJobState::new(spec));
        Ok(())
    }

    pub fn remove_job(&mut self, job_id: &str) -> Result<PulseJobSnapshot> {
        let id = job_id.trim();
        if id.is_empty() {
            return Err(anyhow!("pulse job id is empty"));
        }
        let removed = self
            .jobs
            .remove(id)
            .ok_or_else(|| anyhow!("pulse job '{}' not found", id))?;
        Ok(removed.snapshot())
    }

    pub fn set_job_enabled(&mut self, job_id: &str, enabled: bool) -> Result<PulseJobSnapshot> {
        let id = job_id.trim();
        if id.is_empty() {
            return Err(anyhow!("pulse job id is empty"));
        }
        let state = self
            .jobs
            .get_mut(id)
            .ok_or_else(|| anyhow!("pulse job '{}' not found", id))?;
        let was_enabled = state.spec.enabled;
        state.spec.enabled = enabled;
        if enabled && !was_enabled {
            state.schedule_next();
        }
        Ok(state.snapshot())
    }

    pub fn enable_job(&mut self, job_id: &str) -> Result<PulseJobSnapshot> {
        self.set_job_enabled(job_id, true)
    }

    pub fn disable_job(&mut self, job_id: &str) -> Result<PulseJobSnapshot> {
        self.set_job_enabled(job_id, false)
    }

    pub fn add_http_healthcheck_job(
        &mut self,
        id: &str,
        interval_secs: u64,
        url: &str,
        expected_status: u16,
        timeout_secs: u64,
        enabled: bool,
    ) -> Result<()> {
        if !(100..=599).contains(&expected_status) {
            return Err(anyhow!(
                "expected_status must be in HTTP range 100-599, got {}",
                expected_status
            ));
        }
        validate_healthcheck_url(url)?;

        self.register_job(PulseJobSpec {
            id: id.trim().to_string(),
            interval_secs: interval_secs.max(1),
            action: PulseAction::HttpHealthCheck {
                url: url.trim().to_string(),
                expected_status,
                timeout_secs: timeout_secs.max(1),
            },
            enabled,
        })
    }

    pub fn collect_due_jobs(&mut self) -> Vec<PulseDueJob> {
        let now = Instant::now();
        let mut due = Vec::new();
        for state in self.jobs.values_mut() {
            if !state.is_due(now) {
                continue;
            }
            due.push(PulseDueJob {
                id: state.spec.id.clone(),
                action: state.spec.action.clone(),
            });
            state.schedule_next();
        }
        due
    }

    pub fn complete_job(
        &mut self,
        job_id: &str,
        status: &str,
        message: Option<String>,
    ) -> Result<()> {
        let state = self
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| anyhow!("pulse job '{}' not found", job_id))?;
        state.runs = state.runs.saturating_add(1);
        state.last_run_at = Some(Utc::now().to_rfc3339());
        state.last_status = Some(status.to_string());
        state.last_message = message;
        Ok(())
    }

    pub fn add_goal(&mut self, id: &str, description: &str) -> Result<()> {
        let id = id.trim();
        let description = description.trim();
        if id.is_empty() {
            return Err(anyhow!("goal id is empty"));
        }
        if description.is_empty() {
            return Err(anyhow!("goal description is empty"));
        }

        self.goals
            .insert(id.to_string(), GoalState::new(id, description));
        Ok(())
    }

    pub fn goals(&self) -> Vec<GoalSnapshot> {
        self.goals.values().map(GoalState::snapshot).collect()
    }

    pub fn status(&self) -> PulseStatus {
        PulseStatus {
            jobs: self.jobs.values().map(PulseJobState::snapshot).collect(),
            pending_approvals: self.pending_approvals.values().cloned().collect(),
            goals: self.goals.values().map(GoalState::snapshot).collect(),
        }
    }

    pub fn run_ooda_cycle(
        &mut self,
        observations: Vec<OodaObservation>,
        action: &str,
        goal_id: Option<&str>,
    ) -> OodaCycleReport {
        let orientation = orient_observations(&observations);
        let risk = classify_risk(action, &observations);
        let decision = if observations
            .iter()
            .any(|obs| !obs.severity.eq_ignore_ascii_case("info"))
        {
            "escalate".to_string()
        } else {
            "continue".to_string()
        };

        let action = action.trim().to_string();
        let (approval_status, approval_token) =
            if requires_human_approval(&action, &risk, &self.auto_allow_actions) {
                let token = next_approval_token();
                self.pending_approvals.insert(
                    token.clone(),
                    PendingApproval {
                        token: token.clone(),
                        action: action.clone(),
                        risk: risk.clone(),
                        reason: "human approval required for risky action".to_string(),
                        created_at: Utc::now().to_rfc3339(),
                        status: ApprovalStatus::Pending,
                    },
                );
                (ApprovalStatus::Pending, Some(token))
            } else {
                if let Some(goal) = goal_id.and_then(|id| self.goals.get_mut(id)) {
                    goal.achieved = true;
                    goal.updated_at = Utc::now().to_rfc3339();
                    goal.notes = Some("marked achieved by OODA cycle".to_string());
                }
                (ApprovalStatus::Approved, None)
            };

        OodaCycleReport {
            timestamp: Utc::now().to_rfc3339(),
            observations,
            orientation,
            decision,
            action,
            risk,
            approval_status,
            approval_token,
            goal_id: goal_id.map(ToString::to_string),
        }
    }

    pub fn approve(&mut self, token: &str) -> Result<PendingApproval> {
        let token = token.trim();
        let mut approval = self
            .pending_approvals
            .remove(token)
            .ok_or_else(|| anyhow!("approval token '{}' was not found", token))?;
        approval.status = ApprovalStatus::Approved;
        Ok(approval)
    }

    pub fn reject(&mut self, token: &str, reason: &str) -> Result<PendingApproval> {
        let token = token.trim();
        let mut approval = self
            .pending_approvals
            .remove(token)
            .ok_or_else(|| anyhow!("approval token '{}' was not found", token))?;
        approval.status = ApprovalStatus::Rejected;
        if !reason.trim().is_empty() {
            approval.reason = reason.trim().to_string();
        }
        Ok(approval)
    }
}

fn orient_observations(observations: &[OodaObservation]) -> String {
    if observations.is_empty() {
        return "no observations provided".to_string();
    }

    let total = observations.len();
    let alerts = observations
        .iter()
        .filter(|obs| !obs.severity.eq_ignore_ascii_case("info"))
        .count();
    if alerts == 0 {
        format!("{} observations, no alerts", total)
    } else {
        format!("{} observations, {} require attention", total, alerts)
    }
}

fn validate_healthcheck_url(url: &str) -> Result<()> {
    let url = url.trim();
    if url.is_empty() {
        return Err(anyhow!("healthcheck url is empty"));
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(anyhow!(
            "healthcheck url must start with http:// or https://"
        ));
    }
    if url.chars().any(char::is_control) || url.chars().any(char::is_whitespace) {
        return Err(anyhow!("healthcheck url contains invalid characters"));
    }

    let host = extract_url_host(url).ok_or_else(|| anyhow!("failed parsing healthcheck host"))?;
    if host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case("::1")
        || host.starts_with("127.")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("172.16.")
        || host.ends_with(".local")
    {
        return Err(anyhow!(
            "healthcheck url host '{}' is blocked by sandbox policy",
            host
        ));
    }

    Ok(())
}

fn extract_url_host(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split('/').next().unwrap_or(rest);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = if authority.starts_with('[') {
        authority
            .split(']')
            .next()
            .map(|v| v.trim_start_matches('[').to_string())?
    } else {
        authority
            .split(':')
            .next()
            .map(str::to_string)
            .unwrap_or_default()
    };
    let host = host.trim().to_string();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn classify_risk(action: &str, observations: &[OodaObservation]) -> RiskLevel {
    let normalized = action.trim().to_ascii_lowercase();
    if normalized.contains("purchase")
        || normalized.contains("payment")
        || normalized.contains("delete")
        || normalized.contains("self-update")
    {
        return RiskLevel::Critical;
    }

    if normalized.contains("deploy")
        || normalized.contains("restart")
        || normalized.contains("email")
        || normalized.contains("shutdown")
    {
        return RiskLevel::High;
    }

    if observations
        .iter()
        .any(|obs| obs.severity.eq_ignore_ascii_case("error"))
    {
        return RiskLevel::Medium;
    }

    RiskLevel::Low
}

fn requires_human_approval(action: &str, risk: &RiskLevel, auto_allow_actions: &[String]) -> bool {
    let normalized = action.to_ascii_lowercase();
    if is_auto_allowed(&normalized, auto_allow_actions) {
        return false;
    }

    if *risk >= RiskLevel::High {
        return true;
    }

    normalized.contains("purchase")
        || normalized.contains("email")
        || normalized.contains("deploy")
        || normalized.contains("self-update")
}

fn is_auto_allowed(action: &str, auto_allow_actions: &[String]) -> bool {
    for pattern in auto_allow_actions {
        let value = pattern.trim();
        if value.is_empty() {
            continue;
        }
        if value == "*" || action.contains(value) {
            return true;
        }
    }
    false
}

fn remaining_seconds_until(timestamp: &str) -> Option<u64> {
    let due = chrono::DateTime::parse_from_rfc3339(timestamp).ok()?;
    let now = Utc::now();
    let delta = due.with_timezone(&Utc) - now;
    if delta.num_milliseconds() <= 0 {
        return Some(0);
    }
    u64::try_from(delta.num_seconds()).ok()
}

fn next_approval_token() -> String {
    let seq = APPROVAL_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("pa-{:x}-{:x}", Utc::now().timestamp_millis(), seq)
}

#[cfg(test)]
mod tests {
    use super::{OodaObservation, PulseAction, PulseJobSpec, PulseRuntime};

    #[test]
    fn collect_due_jobs_returns_registered_job() {
        let mut pulse = PulseRuntime::new();
        pulse
            .register_job(PulseJobSpec {
                id: "job-a".to_string(),
                interval_secs: 1,
                action: PulseAction::EmitLog {
                    message: "hello".to_string(),
                },
                enabled: true,
            })
            .expect("register");

        std::thread::sleep(std::time::Duration::from_millis(1100));
        let due = pulse.collect_due_jobs();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, "job-a");
    }

    #[test]
    fn risky_action_requires_human_approval() {
        let mut pulse = PulseRuntime::new();
        let report = pulse.run_ooda_cycle(
            vec![OodaObservation {
                source: "monitor".to_string(),
                key: "cpu".to_string(),
                value: "95".to_string(),
                severity: "warn".to_string(),
            }],
            "deploy production",
            None,
        );
        assert!(report.approval_token.is_some());
    }

    #[test]
    fn auto_allow_skips_human_approval_for_matched_action() {
        let mut pulse = PulseRuntime::with_auto_allow_actions(vec!["deploy".to_string()]);
        let report = pulse.run_ooda_cycle(
            vec![OodaObservation {
                source: "monitor".to_string(),
                key: "cpu".to_string(),
                value: "95".to_string(),
                severity: "warn".to_string(),
            }],
            "deploy production",
            None,
        );
        assert!(report.approval_token.is_none());
    }

    #[test]
    fn add_http_healthcheck_job_registers_action() {
        let mut pulse = PulseRuntime::new();
        pulse
            .add_http_healthcheck_job(
                "hc_example",
                30,
                "https://example.com/health",
                200,
                10,
                true,
            )
            .expect("add healthcheck job");

        let status = pulse.status();
        let job = status
            .jobs
            .iter()
            .find(|job| job.id == "hc_example")
            .expect("healthcheck job");
        match &job.action {
            PulseAction::HttpHealthCheck {
                url,
                expected_status,
                timeout_secs,
            } => {
                assert_eq!(url, "https://example.com/health");
                assert_eq!(*expected_status, 200);
                assert_eq!(*timeout_secs, 10);
            }
            _ => panic!("unexpected pulse action variant"),
        }
    }

    #[test]
    fn add_http_healthcheck_job_rejects_localhost() {
        let mut pulse = PulseRuntime::new();
        let err = pulse
            .add_http_healthcheck_job("hc_local", 30, "http://localhost:8080", 200, 10, true)
            .expect_err("localhost must be blocked");
        assert!(err.to_string().contains("blocked"));
    }

    #[test]
    fn goal_is_marked_achieved_for_safe_action() {
        let mut pulse = PulseRuntime::new();
        pulse
            .add_goal("g1", "keep runtime healthy")
            .expect("goal add");

        let report = pulse.run_ooda_cycle(
            vec![OodaObservation {
                source: "monitor".to_string(),
                key: "heartbeat".to_string(),
                value: "ok".to_string(),
                severity: "info".to_string(),
            }],
            "observe only",
            Some("g1"),
        );
        assert!(report.approval_token.is_none());

        let goals = pulse.goals();
        assert_eq!(goals.len(), 1);
        assert!(goals[0].achieved);
    }

    #[test]
    fn persistence_roundtrip_restores_goals_and_pending_approvals() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_path = temp.path().join("pulse").join("state.json");

        let mut pulse = PulseRuntime::new();
        pulse.add_goal("g1", "ensure uptime").expect("add goal");
        let report = pulse.run_ooda_cycle(
            vec![OodaObservation {
                source: "monitor".to_string(),
                key: "service".to_string(),
                value: "degraded".to_string(),
                severity: "warn".to_string(),
            }],
            "deploy canary",
            Some("g1"),
        );
        assert!(report.approval_token.is_some());
        pulse
            .persist_persistent_state(&state_path)
            .expect("persist pulse");

        let mut restored = PulseRuntime::new();
        restored
            .load_persistent_state(&state_path)
            .expect("load pulse");

        let status = restored.status();
        assert_eq!(status.pending_approvals.len(), 1);
        assert_eq!(status.goals.len(), 1);
        assert_eq!(status.goals[0].id, "g1");
    }

    #[test]
    fn persistence_replays_job_runtime_counters() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_path = temp.path().join("pulse").join("state.json");

        let mut pulse = PulseRuntime::new();
        pulse
            .register_job(PulseJobSpec {
                id: "job_replay".to_string(),
                interval_secs: 60,
                action: PulseAction::EmitLog {
                    message: "hello".to_string(),
                },
                enabled: true,
            })
            .expect("register job");
        pulse
            .complete_job("job_replay", "ok", Some("done".to_string()))
            .expect("complete job");
        pulse
            .persist_persistent_state(&state_path)
            .expect("persist pulse");

        let mut restored = PulseRuntime::new();
        restored
            .register_job(PulseJobSpec {
                id: "job_replay".to_string(),
                interval_secs: 60,
                action: PulseAction::EmitLog {
                    message: "hello".to_string(),
                },
                enabled: true,
            })
            .expect("register job restored");
        restored
            .load_persistent_state(&state_path)
            .expect("load pulse");

        let status = restored.status();
        let job = status
            .jobs
            .iter()
            .find(|job| job.id == "job_replay")
            .expect("job snapshot");
        assert_eq!(job.runs, 1);
        assert_eq!(job.last_status.as_deref(), Some("ok"));
        assert_eq!(job.last_message.as_deref(), Some("done"));
    }

    #[test]
    fn persistence_restores_unregistered_job_definitions() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_path = temp.path().join("pulse").join("state.json");

        let mut pulse = PulseRuntime::new();
        pulse
            .add_http_healthcheck_job(
                "hc_example",
                30,
                "https://example.com/health",
                200,
                10,
                true,
            )
            .expect("register healthcheck job");
        pulse
            .persist_persistent_state(&state_path)
            .expect("persist pulse");

        let mut restored = PulseRuntime::new();
        restored
            .load_persistent_state(&state_path)
            .expect("load pulse");

        let status = restored.status();
        let job = status
            .jobs
            .iter()
            .find(|job| job.id == "hc_example")
            .expect("restored job");
        match &job.action {
            PulseAction::HttpHealthCheck {
                url,
                expected_status,
                timeout_secs,
            } => {
                assert_eq!(url, "https://example.com/health");
                assert_eq!(*expected_status, 200);
                assert_eq!(*timeout_secs, 10);
            }
            _ => panic!("unexpected pulse action variant"),
        }
    }

    #[test]
    fn job_lifecycle_remove_enable_disable() {
        let mut pulse = PulseRuntime::new();
        pulse
            .register_job(PulseJobSpec {
                id: "job_ops".to_string(),
                interval_secs: 30,
                action: PulseAction::EmitLog {
                    message: "ops".to_string(),
                },
                enabled: true,
            })
            .expect("register job");

        let disabled = pulse.disable_job("job_ops").expect("disable job");
        assert!(!disabled.enabled);

        let enabled = pulse.enable_job("job_ops").expect("enable job");
        assert!(enabled.enabled);

        let removed = pulse.remove_job("job_ops").expect("remove job");
        assert_eq!(removed.id, "job_ops");
        assert!(pulse.status().jobs.is_empty());
    }
}
