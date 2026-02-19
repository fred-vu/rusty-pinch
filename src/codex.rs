use std::collections::VecDeque;
use std::env;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use serde::Serialize;

use crate::config::{CodexAccountSettings, CodexSettings};

#[derive(Debug, Clone, Serialize)]
pub struct CodexTask {
    pub id: u64,
    pub purpose: String,
    pub prompt: String,
    pub queued_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodexExecution {
    pub task_id: u64,
    pub account_id: String,
    pub output: String,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub enum CodexSubmitResult {
    Executed(CodexExecution),
    Queued {
        task_id: u64,
        queue_depth: usize,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct CodexStatus {
    pub enabled: bool,
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub queue_mode_reason: Option<String>,
    pub rate_limit_threshold_percent: u8,
    pub accounts: Vec<CodexAccountSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodexAccountSnapshot {
    pub id: String,
    pub healthy: bool,
    pub used_requests: u32,
    pub max_requests: u32,
    pub remaining_percent: u8,
    pub model: Option<String>,
    pub api_key_env: Option<String>,
    pub last_error: Option<String>,
    pub last_healthcheck_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodexHealthCheck {
    pub account_id: String,
    pub healthy: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CliRunOutput {
    pub stdout: String,
    pub stderr: String,
}

pub trait CliRunner: Send + Sync {
    fn run(
        &self,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
        _timeout_secs: u64,
    ) -> Result<CliRunOutput>;
}

#[derive(Default)]
struct SystemCliRunner;

impl CliRunner for SystemCliRunner {
    fn run(
        &self,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
        _timeout_secs: u64,
    ) -> Result<CliRunOutput> {
        let mut command = Command::new(program);
        command.args(args);

        for (key, value) in envs {
            command.env(key, value);
        }

        let output = command
            .output()
            .with_context(|| format!("failed to execute codex cli command '{}'", program))?;

        if !output.status.success() {
            let code = output.status.code().unwrap_or(-1);
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let message = if !stderr.is_empty() {
                format!(
                    "codex cli exited with code {}: {}",
                    code,
                    sanitize_output(&stderr)
                )
            } else if !stdout.is_empty() {
                format!(
                    "codex cli exited with code {}: {}",
                    code,
                    sanitize_output(&stdout)
                )
            } else {
                format!("codex cli exited with code {}", code)
            };
            return Err(anyhow!(message));
        }

        Ok(CliRunOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

#[derive(Debug, Clone)]
struct CodexAccountState {
    settings: CodexAccountSettings,
    healthy: bool,
    used_requests: u32,
    last_error: Option<String>,
    window_started: Instant,
    last_healthcheck: Option<Instant>,
    last_healthcheck_at: Option<String>,
}

impl CodexAccountState {
    fn new(settings: CodexAccountSettings) -> Self {
        Self {
            settings,
            healthy: true,
            used_requests: 0,
            last_error: None,
            window_started: Instant::now(),
            last_healthcheck: None,
            last_healthcheck_at: None,
        }
    }

    fn remaining_requests(&self) -> u32 {
        self.settings
            .max_requests
            .saturating_sub(self.used_requests)
    }

    fn remaining_percent(&self) -> u8 {
        if self.settings.max_requests == 0 {
            return 0;
        }
        let remaining = self.remaining_requests();
        let pct = (u64::from(remaining) * 100) / u64::from(self.settings.max_requests);
        u8::try_from(pct).unwrap_or(0)
    }

    fn snapshot(&self) -> CodexAccountSnapshot {
        CodexAccountSnapshot {
            id: self.settings.id.clone(),
            healthy: self.healthy,
            used_requests: self.used_requests,
            max_requests: self.settings.max_requests,
            remaining_percent: self.remaining_percent(),
            model: self.settings.model.clone(),
            api_key_env: self.settings.api_key_env.clone(),
            last_error: self.last_error.clone(),
            last_healthcheck_at: self.last_healthcheck_at.clone(),
        }
    }
}

pub struct CodexOrchestrator {
    settings: CodexSettings,
    runner: Box<dyn CliRunner>,
    accounts: Vec<CodexAccountState>,
    queue: VecDeque<CodexTask>,
    next_task_id: u64,
    rr_cursor: usize,
}

impl CodexOrchestrator {
    pub fn new(settings: CodexSettings) -> Self {
        Self::with_runner(settings, Box::new(SystemCliRunner))
    }

    fn with_runner(settings: CodexSettings, runner: Box<dyn CliRunner>) -> Self {
        let accounts = settings
            .accounts
            .iter()
            .cloned()
            .map(CodexAccountState::new)
            .collect::<Vec<CodexAccountState>>();
        Self {
            settings,
            runner,
            accounts,
            queue: VecDeque::new(),
            next_task_id: 1,
            rr_cursor: 0,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.settings.enabled
    }

    pub fn status(&mut self) -> CodexStatus {
        self.maybe_reset_rate_windows();
        let _ = self.tick_health_checks();

        let queue_mode_reason = if !self.queue.is_empty() {
            Some("queue_backpressure".to_string())
        } else {
            self.queue_guard_reason().map(ToString::to_string)
        };

        let accounts = self
            .accounts
            .iter()
            .map(CodexAccountState::snapshot)
            .collect();
        CodexStatus {
            enabled: self.settings.enabled,
            queue_depth: self.queue.len(),
            queue_capacity: self.settings.queue_capacity,
            queue_mode_reason,
            rate_limit_threshold_percent: self.settings.rate_limit_threshold_percent,
            accounts,
        }
    }

    pub fn health_check(&mut self) -> Vec<CodexHealthCheck> {
        self.run_health_checks(true)
    }

    pub fn tick_health_checks(&mut self) -> Vec<CodexHealthCheck> {
        self.run_health_checks(false)
    }

    pub fn submit(&mut self, prompt: &str, purpose: &str) -> Result<CodexSubmitResult> {
        if !self.settings.enabled {
            return Err(anyhow!("codex integration is disabled"));
        }

        let normalized_prompt = prompt.trim();
        if normalized_prompt.is_empty() {
            return Err(anyhow!("codex prompt is empty"));
        }

        self.maybe_reset_rate_windows();
        let _ = self.tick_health_checks();

        let task = CodexTask {
            id: self.next_task_id,
            purpose: purpose.trim().to_string(),
            prompt: normalized_prompt.to_string(),
            queued_at: Utc::now().to_rfc3339(),
        };
        self.next_task_id = self.next_task_id.saturating_add(1);

        if self.queue.len() >= self.settings.queue_capacity {
            return Err(anyhow!(
                "codex queue is full ({}/{})",
                self.queue.len(),
                self.settings.queue_capacity
            ));
        }

        if !self.queue.is_empty() {
            self.queue.push_back(task.clone());
            return Ok(CodexSubmitResult::Queued {
                task_id: task.id,
                queue_depth: self.queue.len(),
                reason: "queue_backpressure".to_string(),
            });
        }

        if let Some(reason) = self.queue_guard_reason() {
            self.queue.push_back(task.clone());
            return Ok(CodexSubmitResult::Queued {
                task_id: task.id,
                queue_depth: self.queue.len(),
                reason: reason.to_string(),
            });
        }

        let Some(account_idx) = self.pick_account_index() else {
            self.queue.push_back(task.clone());
            return Ok(CodexSubmitResult::Queued {
                task_id: task.id,
                queue_depth: self.queue.len(),
                reason: "no_healthy_accounts".to_string(),
            });
        };

        let execution = self.execute_task(account_idx, &task)?;
        Ok(CodexSubmitResult::Executed(execution))
    }

    pub fn drain_once(&mut self) -> Option<Result<CodexExecution>> {
        if self.queue.is_empty() {
            return None;
        }

        self.maybe_reset_rate_windows();
        let _ = self.tick_health_checks();

        if self.queue_guard_reason().is_some() {
            return None;
        }

        let account_idx = self.pick_account_index()?;
        let task = self.queue.pop_front()?;

        match self.execute_task(account_idx, &task) {
            Ok(exec) => Some(Ok(exec)),
            Err(err) => {
                self.queue.push_front(task);
                Some(Err(err))
            }
        }
    }

    pub fn reset_rate_windows(&mut self) {
        for account in &mut self.accounts {
            account.used_requests = 0;
            account.window_started = Instant::now();
        }
    }

    pub fn queue_depth(&self) -> usize {
        self.queue.len()
    }

    fn run_health_checks(&mut self, force: bool) -> Vec<CodexHealthCheck> {
        if !self.settings.enabled || self.accounts.is_empty() {
            return Vec::new();
        }

        let mut checks = Vec::new();
        for account in &mut self.accounts {
            if !force {
                if let Some(last) = account.last_healthcheck {
                    if last.elapsed() < Duration::from_secs(self.settings.healthcheck_interval_secs)
                    {
                        continue;
                    }
                }
            }

            account.last_healthcheck = Some(Instant::now());
            account.last_healthcheck_at = Some(Utc::now().to_rfc3339());

            let envs = match build_account_env(account) {
                Ok(envs) => envs,
                Err(err) => {
                    let message = err.to_string();
                    account.healthy = false;
                    account.last_error = Some(message.clone());
                    checks.push(CodexHealthCheck {
                        account_id: account.settings.id.clone(),
                        healthy: false,
                        message: Some(message),
                    });
                    continue;
                }
            };

            let args = self.settings.healthcheck_args.clone();
            match self.runner.run(
                &self.settings.cli_bin,
                &args,
                &envs,
                self.settings.timeout_secs,
            ) {
                Ok(_) => {
                    account.healthy = true;
                    account.last_error = None;
                    checks.push(CodexHealthCheck {
                        account_id: account.settings.id.clone(),
                        healthy: true,
                        message: None,
                    });
                }
                Err(err) => {
                    let message = err.to_string();
                    account.healthy = false;
                    account.last_error = Some(message.clone());
                    checks.push(CodexHealthCheck {
                        account_id: account.settings.id.clone(),
                        healthy: false,
                        message: Some(message),
                    });
                }
            }
        }

        checks
    }

    fn maybe_reset_rate_windows(&mut self) {
        let window = Duration::from_secs(self.settings.rate_window_secs.max(1));
        for account in &mut self.accounts {
            if account.window_started.elapsed() >= window {
                account.used_requests = 0;
                account.window_started = Instant::now();
                if account.last_error.as_deref() == Some("rate_limit_guard") {
                    account.last_error = None;
                    account.healthy = true;
                }
            }
        }
    }

    fn queue_guard_reason(&self) -> Option<&'static str> {
        if self.accounts.is_empty() {
            return Some("no_accounts");
        }

        let mut healthy_count = 0usize;
        let mut min_remaining = u8::MAX;
        for account in &self.accounts {
            if !account.healthy {
                continue;
            }
            healthy_count = healthy_count.saturating_add(1);
            min_remaining = min_remaining.min(account.remaining_percent());
        }

        if healthy_count == 0 {
            return Some("no_healthy_accounts");
        }

        if min_remaining <= self.settings.rate_limit_threshold_percent {
            return Some("rate_limit_guard");
        }

        None
    }

    fn pick_account_index(&mut self) -> Option<usize> {
        if self.accounts.is_empty() {
            return None;
        }

        let len = self.accounts.len();
        for offset in 0..len {
            let idx = (self.rr_cursor + offset) % len;
            let account = &self.accounts[idx];
            if !account.healthy || account.remaining_requests() == 0 {
                continue;
            }

            self.rr_cursor = (idx + 1) % len;
            return Some(idx);
        }

        None
    }

    fn execute_task(&mut self, account_idx: usize, task: &CodexTask) -> Result<CodexExecution> {
        let account = self
            .accounts
            .get_mut(account_idx)
            .ok_or_else(|| anyhow!("invalid codex account index {}", account_idx))?;
        let envs = build_account_env(account)?;
        let args = build_exec_args(&self.settings, account, &task.prompt);

        let started = Instant::now();
        let run = self.runner.run(
            &self.settings.cli_bin,
            &args,
            &envs,
            self.settings.timeout_secs,
        );
        let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

        match run {
            Ok(output) => {
                account.used_requests = account.used_requests.saturating_add(1);
                account.healthy = true;
                account.last_error = None;

                let text = output.stdout.trim();
                let fallback = output.stderr.trim();
                let merged = if !text.is_empty() {
                    text.to_string()
                } else if !fallback.is_empty() {
                    fallback.to_string()
                } else {
                    "<empty codex output>".to_string()
                };

                Ok(CodexExecution {
                    task_id: task.id,
                    account_id: account.settings.id.clone(),
                    output: merged,
                    latency_ms,
                })
            }
            Err(err) => {
                account.healthy = false;
                account.last_error = Some(err.to_string());
                Err(anyhow!(
                    "codex task {} failed on account '{}': {}",
                    task.id,
                    account.settings.id,
                    err
                ))
            }
        }
    }
}

fn build_exec_args(
    settings: &CodexSettings,
    account: &CodexAccountState,
    prompt: &str,
) -> Vec<String> {
    let mut args = settings.cli_args.clone();

    let model = account
        .settings
        .model
        .as_ref()
        .cloned()
        .or_else(|| settings.default_model.clone());
    if let Some(model) = model {
        if !model.trim().is_empty() {
            if settings.model_flag.trim().is_empty() {
                args.push(model);
            } else {
                args.push(settings.model_flag.clone());
                args.push(model);
            }
        }
    }

    if settings.prompt_flag.trim().is_empty() {
        args.push(prompt.to_string());
    } else {
        args.push(settings.prompt_flag.clone());
        args.push(prompt.to_string());
    }

    args
}

fn build_account_env(account: &CodexAccountState) -> Result<Vec<(String, String)>> {
    let mut envs = Vec::new();
    if let Some(env_name) = &account.settings.api_key_env {
        let value = env::var(env_name)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow!("required env '{}' is missing for codex account", env_name))?;
        envs.push((env_name.clone(), value));
    }
    Ok(envs)
}

fn sanitize_output(raw: &str) -> String {
    raw.chars()
        .filter(|ch| !ch.is_control() || *ch == '\n' || *ch == '\t')
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::{
        CliRunOutput, CliRunner, CodexAccountSettings, CodexOrchestrator, CodexSettings,
        CodexSubmitResult,
    };
    use anyhow::{anyhow, Result};

    #[derive(Default)]
    struct FakeRunnerState {
        responses: VecDeque<Result<CliRunOutput>>,
        calls: Vec<Vec<String>>,
    }

    #[derive(Clone, Default)]
    struct FakeRunner {
        state: Arc<Mutex<FakeRunnerState>>,
    }

    impl FakeRunner {
        fn push_ok(&self, stdout: &str) {
            let mut state = self.state.lock().expect("lock fake runner");
            state.responses.push_back(Ok(CliRunOutput {
                stdout: stdout.to_string(),
                stderr: String::new(),
            }));
        }

        fn push_err(&self, message: &str) {
            let mut state = self.state.lock().expect("lock fake runner");
            state.responses.push_back(Err(anyhow!(message.to_string())));
        }
    }

    impl CliRunner for FakeRunner {
        fn run(
            &self,
            _program: &str,
            args: &[String],
            _envs: &[(String, String)],
            _timeout_secs: u64,
        ) -> Result<CliRunOutput> {
            let mut state = self.state.lock().expect("lock fake runner");
            state.calls.push(args.to_vec());
            state.responses.pop_front().unwrap_or_else(|| {
                Ok(CliRunOutput {
                    stdout: "ok".to_string(),
                    stderr: String::new(),
                })
            })
        }
    }

    fn settings(max_requests: u32) -> CodexSettings {
        CodexSettings {
            enabled: true,
            cli_bin: "codex".to_string(),
            cli_args: vec!["run".to_string()],
            prompt_flag: "--prompt".to_string(),
            model_flag: "--model".to_string(),
            timeout_secs: 10,
            queue_capacity: 16,
            rate_limit_threshold_percent: 25,
            rate_window_secs: 3600,
            healthcheck_interval_secs: 3600,
            healthcheck_args: vec!["--version".to_string()],
            default_model: Some("gpt-5-codex".to_string()),
            accounts: vec![CodexAccountSettings {
                id: "a1".to_string(),
                api_key_env: None,
                max_requests,
                model: None,
            }],
        }
    }

    #[test]
    fn queues_when_rate_limit_reaches_threshold() {
        let runner = FakeRunner::default();
        let mut codex = CodexOrchestrator::with_runner(settings(4), Box::new(runner));

        let r1 = codex.submit("a", "test").expect("submit #1");
        let r2 = codex.submit("b", "test").expect("submit #2");
        let r3 = codex.submit("c", "test").expect("submit #3");
        let r4 = codex.submit("d", "test").expect("submit #4");

        assert!(matches!(r1, CodexSubmitResult::Executed(_)));
        assert!(matches!(r2, CodexSubmitResult::Executed(_)));
        assert!(matches!(r3, CodexSubmitResult::Executed(_)));
        assert!(matches!(r4, CodexSubmitResult::Queued { .. }));
        assert_eq!(codex.queue_depth(), 1);
    }

    #[test]
    fn drain_executes_queued_work_after_rate_window_reset() {
        let runner = FakeRunner::default();
        runner.push_ok("ok-health");
        runner.push_ok("result-a");
        runner.push_ok("result-b");
        runner.push_ok("result-c");
        runner.push_ok("result-d");

        let mut codex = CodexOrchestrator::with_runner(settings(4), Box::new(runner));
        let _ = codex.submit("a", "test").expect("submit #1");
        let _ = codex.submit("b", "test").expect("submit #2");
        let _ = codex.submit("c", "test").expect("submit #3");
        let queued = codex.submit("d", "test").expect("submit #4");
        assert!(matches!(queued, CodexSubmitResult::Queued { .. }));

        codex.reset_rate_windows();
        let drained = codex
            .drain_once()
            .expect("queued work should exist")
            .expect("drain should succeed");
        assert_eq!(drained.output, "result-d");
        assert_eq!(codex.queue_depth(), 0);
    }

    #[test]
    fn health_check_marks_account_unhealthy_on_failure() {
        let runner = FakeRunner::default();
        runner.push_err("unreachable");
        let mut codex = CodexOrchestrator::with_runner(settings(10), Box::new(runner));

        let checks = codex.health_check();
        assert_eq!(checks.len(), 1);
        assert!(!checks[0].healthy);

        let status = codex.status();
        assert_eq!(status.accounts.len(), 1);
        assert!(!status.accounts[0].healthy);
        assert!(status.accounts[0]
            .last_error
            .as_deref()
            .is_some_and(|v| v.contains("unreachable")));
    }
}
