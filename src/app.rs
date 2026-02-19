use std::env;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use serde_json::json;

use crate::bus::{MessageBus, OverflowPolicy};
use crate::codex::{CodexOrchestrator, CodexSubmitResult};
use crate::config::{DoctorReport, Settings};
use crate::evolution::{
    BlueGreenApplyReport, ChecksumManifestProvenance, EvolutionActiveSlotIntegrityReport,
    EvolutionApplyFailureCircuitReport, EvolutionManager, SkillEvolutionReport,
};
use crate::prompt::PromptBuilder;
use crate::provider;
use crate::pulse::{OodaObservation, PulseAction, PulseRuntime};
use crate::session::SessionStore;
use crate::skills::SkillManager;
use crate::telemetry::{TelemetryStore, TurnRecord};
use crate::tools::{parse_tool_invocation, ToolContext, ToolRegistry, ToolSpec};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

pub struct RustyPinchApp {
    settings: Settings,
    sessions: SessionStore,
    bus: MessageBus,
    prompt: PromptBuilder,
    tools: ToolRegistry,
    skills: SkillManager,
    evolution: EvolutionManager,
    pulse: PulseRuntime,
    pulse_state_file: PathBuf,
    telemetry: TelemetryStore,
    codex: Option<CodexOrchestrator>,
}

impl RustyPinchApp {
    pub fn new(settings: Settings) -> Result<Self> {
        let capacity = env::var("RUSTY_PINCH_BUS_CAPACITY")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(100);
        let overflow = env::var("RUSTY_PINCH_BUS_OVERFLOW")
            .map(|v| OverflowPolicy::from_env(&v))
            .unwrap_or(OverflowPolicy::DropOldest);

        let sessions = SessionStore::new(settings.data_dir.join("sessions"))?;
        let mut telemetry = TelemetryStore::new(settings.telemetry_file.clone())?;
        let skills = SkillManager::new(settings.workspace.join("skills"))?;
        match skills.sync_from_assets(PathBuf::from("assets").join("skills")) {
            Ok(copied) => {
                if copied > 0 {
                    eprintln!(
                        "{{\"event\":\"skills_assets_synced\",\"copied\":{},\"source\":\"assets/skills\",\"destination\":{}}}",
                        copied,
                        serde_json::to_string(&skills.skills_dir().display().to_string())
                            .unwrap_or_else(|_| "\"<encode-error>\"".to_string())
                    );
                }
            }
            Err(err) => {
                eprintln!(
                    "{{\"event\":\"skills_assets_sync_error\",\"message\":{}}}",
                    serde_json::to_string(&err.to_string())
                        .unwrap_or_else(|_| "\"<encode-error>\"".to_string())
                );
            }
        }
        let evolution = EvolutionManager::new(&settings.workspace)?
            .with_lock_policy(
                settings
                    .evolution
                    .lock_stale_after_secs
                    .filter(|value| *value > 0),
                settings.evolution.auto_recover_stale_lock,
            )
            .with_active_slot_signing_policy(
                settings.evolution.active_slot_signing_key_id.as_deref(),
                settings.evolution.active_slot_signing_key.as_deref(),
                settings.evolution.require_signed_active_slot,
            )
            .with_staged_manifest_age_policy(
                settings
                    .evolution
                    .max_staged_manifest_age_secs
                    .filter(|value| *value > 0),
            )
            .with_apply_failure_policy(
                settings
                    .evolution
                    .max_consecutive_apply_failures
                    .filter(|value| *value > 0),
            );
        let mut pulse =
            PulseRuntime::with_auto_allow_actions(settings.pulse.auto_allow_actions.clone());
        pulse.register_default_jobs(settings.codex.enabled)?;
        let pulse_state_file = settings.workspace.join("pulse").join("state.json");
        pulse.load_persistent_state(&pulse_state_file)?;
        let mut codex = if settings.codex.enabled {
            Some(CodexOrchestrator::new(settings.codex.clone()))
        } else {
            None
        };
        if let Err(err) = telemetry.record_pulse_status(&pulse.status()) {
            eprintln!("{{\"event\":\"telemetry_error\",\"message\":\"{}\"}}", err);
        }
        if let Some(codex_runtime) = codex.as_mut() {
            let status = codex_runtime.status();
            if let Err(err) = telemetry.record_codex_status(&status) {
                eprintln!("{{\"event\":\"telemetry_error\",\"message\":\"{}\"}}", err);
            }
        }
        match evolution.active_slot_integrity_status() {
            Ok(report) => {
                if let Err(err) = telemetry.record_evolution_active_slot_integrity(&report) {
                    eprintln!("{{\"event\":\"telemetry_error\",\"message\":\"{}\"}}", err);
                }
            }
            Err(err) => {
                eprintln!(
                    "{{\"event\":\"telemetry_error\",\"message\":\"failed to inspect active-slot integrity: {}\"}}",
                    err
                );
            }
        }
        match evolution.apply_failure_circuit_status() {
            Ok(report) => {
                if let Err(err) = telemetry.record_evolution_failure_circuit(&report) {
                    eprintln!("{{\"event\":\"telemetry_error\",\"message\":\"{}\"}}", err);
                }
            }
            Err(err) => {
                eprintln!(
                    "{{\"event\":\"telemetry_error\",\"message\":\"failed to inspect evolution failure circuit: {}\"}}",
                    err
                );
            }
        }

        Ok(Self {
            settings,
            sessions,
            bus: MessageBus::new(capacity, overflow),
            prompt: PromptBuilder::default(),
            tools: ToolRegistry::with_defaults(),
            skills,
            evolution,
            pulse,
            pulse_state_file,
            telemetry,
            codex,
        })
    }

    pub fn doctor(&self) -> DoctorReport {
        self.settings.doctor_report()
    }

    pub fn list_tools(&self) -> Vec<ToolSpec> {
        self.tools.list()
    }

    pub fn run_tool(&mut self, session_id: &str, name: &str, args: &str) -> Result<String> {
        let input = if args.trim().is_empty() {
            format!("/tool {}", name.trim())
        } else {
            format!("/tool {} {}", name.trim(), args.trim())
        };
        self.process_turn(session_id, &input)
    }

    pub fn process_turn(&mut self, session_id: &str, user_input: &str) -> Result<String> {
        let request_id = next_request_id();

        if let Some(tool_call) = parse_tool_invocation(user_input) {
            let tool_name = tool_call.name.trim().to_string();
            let tool_command = format_tool_command(&tool_name, &tool_call.args);
            let user_chars = tool_command.chars().count();

            let result = self.execute_tool_turn(session_id, &tool_name, &tool_call.args);
            return match result {
                Ok(response) => {
                    self.record_turn(TurnRecord {
                        timestamp: Utc::now().to_rfc3339(),
                        request_id,
                        session_id: session_id.to_string(),
                        path: "tool".to_string(),
                        status: "ok".to_string(),
                        provider: self.settings.provider.clone(),
                        model: self.settings.model.clone(),
                        tool_name: non_empty(tool_name),
                        attempts: None,
                        latency_ms: None,
                        user_chars,
                        response_chars: response.chars().count(),
                        error: None,
                    });
                    Ok(response)
                }
                Err(err) => {
                    let message = err.to_string();
                    self.record_turn(TurnRecord {
                        timestamp: Utc::now().to_rfc3339(),
                        request_id: request_id.clone(),
                        session_id: session_id.to_string(),
                        path: "tool".to_string(),
                        status: "error".to_string(),
                        provider: self.settings.provider.clone(),
                        model: self.settings.model.clone(),
                        tool_name: non_empty(tool_name),
                        attempts: None,
                        latency_ms: None,
                        user_chars,
                        response_chars: 0,
                        error: Some(message.clone()),
                    });
                    Err(anyhow!("request_id={}: {}", request_id, message))
                }
            };
        }

        let history = match self.sessions.load_history(session_id) {
            Ok(history) => history,
            Err(err) => {
                let message = format!("failed loading session history: {}", err);
                self.record_turn(TurnRecord {
                    timestamp: Utc::now().to_rfc3339(),
                    request_id: request_id.clone(),
                    session_id: session_id.to_string(),
                    path: "provider".to_string(),
                    status: "error".to_string(),
                    provider: self.settings.provider.clone(),
                    model: self.settings.model.clone(),
                    tool_name: None,
                    attempts: None,
                    latency_ms: None,
                    user_chars: user_input.chars().count(),
                    response_chars: 0,
                    error: Some(message.clone()),
                });
                return Err(anyhow!("request_id={}: {}", request_id, message));
            }
        };
        let prompt = self.prompt.build(
            &self.settings.provider,
            &self.settings.model,
            "You are Rusty Pinch, a pragmatic Rust-first assistant.",
            session_id,
            user_input,
        );

        let (response, provider_attempts, provider_latency_ms) =
            if self.settings.provider == "codex" {
                let purpose = format!("provider_turn:{}", session_id);
                let submit_result = {
                    let codex = match self.codex_mut() {
                        Ok(codex) => codex,
                        Err(err) => {
                            let message = err.to_string();
                            self.record_turn(TurnRecord {
                                timestamp: Utc::now().to_rfc3339(),
                                request_id: request_id.clone(),
                                session_id: session_id.to_string(),
                                path: "provider".to_string(),
                                status: "error".to_string(),
                                provider: self.settings.provider.clone(),
                                model: self.settings.model.clone(),
                                tool_name: None,
                                attempts: None,
                                latency_ms: None,
                                user_chars: user_input.chars().count(),
                                response_chars: 0,
                                error: Some(message.clone()),
                            });
                            return Err(anyhow!("request_id={}: {}", request_id, message));
                        }
                    };
                    codex.submit(&prompt, &purpose)
                };

                if let Some(codex_runtime) = self.codex.as_mut() {
                    let status = codex_runtime.status();
                    self.record_codex_status_snapshot(&status);
                }

                match submit_result {
                    Ok(CodexSubmitResult::Executed(exec)) => {
                        (exec.output, Some(1), Some(exec.latency_ms))
                    }
                    Ok(CodexSubmitResult::Queued {
                        task_id,
                        queue_depth,
                        reason,
                    }) => (
                        format!(
                            "[codex:queued] task_id={} queue_depth={} reason={}",
                            task_id, queue_depth, reason
                        ),
                        Some(0),
                        None,
                    ),
                    Err(err) => {
                        let message = err.to_string();
                        self.record_turn(TurnRecord {
                            timestamp: Utc::now().to_rfc3339(),
                            request_id: request_id.clone(),
                            session_id: session_id.to_string(),
                            path: "provider".to_string(),
                            status: "error".to_string(),
                            provider: self.settings.provider.clone(),
                            model: self.settings.model.clone(),
                            tool_name: None,
                            attempts: Some(1),
                            latency_ms: None,
                            user_chars: user_input.chars().count(),
                            response_chars: 0,
                            error: Some(message.clone()),
                        });
                        return Err(anyhow!("request_id={}: {}", request_id, message));
                    }
                }
            } else {
                let completion = match provider::chat_completion_with_metrics(
                    &self.settings,
                    &history,
                    &prompt,
                    user_input,
                ) {
                    Ok(response) => response,
                    Err(err) => {
                        let message = err.to_string();
                        self.record_turn(TurnRecord {
                            timestamp: Utc::now().to_rfc3339(),
                            request_id: request_id.clone(),
                            session_id: session_id.to_string(),
                            path: "provider".to_string(),
                            status: "error".to_string(),
                            provider: self.settings.provider.clone(),
                            model: self.settings.model.clone(),
                            tool_name: None,
                            attempts: Some(err.metrics.attempts),
                            latency_ms: Some(err.metrics.latency_ms),
                            user_chars: user_input.chars().count(),
                            response_chars: 0,
                            error: Some(message.clone()),
                        });
                        return Err(anyhow!("request_id={}: {}", request_id, message));
                    }
                };
                (
                    completion.content,
                    Some(completion.metrics.attempts),
                    Some(completion.metrics.latency_ms),
                )
            };

        if let Err(err) = self
            .sessions
            .append_message(session_id, "user", user_input)
            .context("failed saving user message")
        {
            let message = err.to_string();
            self.record_turn(TurnRecord {
                timestamp: Utc::now().to_rfc3339(),
                request_id: request_id.clone(),
                session_id: session_id.to_string(),
                path: "provider".to_string(),
                status: "error".to_string(),
                provider: self.settings.provider.clone(),
                model: self.settings.model.clone(),
                tool_name: None,
                attempts: provider_attempts,
                latency_ms: provider_latency_ms,
                user_chars: user_input.chars().count(),
                response_chars: 0,
                error: Some(message.clone()),
            });
            return Err(anyhow!("request_id={}: {}", request_id, message));
        }

        if let Err(err) = self
            .sessions
            .append_message(session_id, "assistant", &response)
            .context("failed saving assistant message")
        {
            let message = err.to_string();
            self.record_turn(TurnRecord {
                timestamp: Utc::now().to_rfc3339(),
                request_id: request_id.clone(),
                session_id: session_id.to_string(),
                path: "provider".to_string(),
                status: "error".to_string(),
                provider: self.settings.provider.clone(),
                model: self.settings.model.clone(),
                tool_name: None,
                attempts: provider_attempts,
                latency_ms: provider_latency_ms,
                user_chars: user_input.chars().count(),
                response_chars: 0,
                error: Some(message.clone()),
            });
            return Err(anyhow!("request_id={}: {}", request_id, message));
        }

        let _ = self.bus.publish(format!("in:{}", user_input));
        let _ = self.bus.publish(format!("out:{}", response));

        self.record_turn(TurnRecord {
            timestamp: Utc::now().to_rfc3339(),
            request_id,
            session_id: session_id.to_string(),
            path: "provider".to_string(),
            status: "ok".to_string(),
            provider: self.settings.provider.clone(),
            model: self.settings.model.clone(),
            tool_name: None,
            attempts: provider_attempts,
            latency_ms: provider_latency_ms,
            user_chars: user_input.chars().count(),
            response_chars: response.chars().count(),
            error: None,
        });

        Ok(response)
    }

    fn execute_tool_turn(&mut self, session_id: &str, name: &str, args: &str) -> Result<String> {
        if name.trim().is_empty() {
            return Err(anyhow!(
                "tool command missing name. usage: /tool <name> [args]"
            ));
        }

        let ctx = ToolContext {
            session_id,
            sessions: &self.sessions,
            provider: &self.settings.provider,
            model: &self.settings.model,
        };
        let output = self.tools.execute(name, &ctx, args)?;
        let response = format!("[tool:{}]\n{}", name.trim(), output);
        let user_command = format_tool_command(name, args);

        self.sessions
            .append_message(session_id, "user", &user_command)
            .context("failed saving user tool command")?;
        self.sessions
            .append_message(session_id, "assistant", &response)
            .context("failed saving assistant tool response")?;

        let _ = self
            .bus
            .publish(format!("tool:{}:{}", name.trim(), args.trim()));
        let _ = self
            .bus
            .publish(format!("tool_out:{}:{}", name.trim(), output));
        Ok(response)
    }

    pub fn session_history_json(&self, session_id: &str) -> Result<String> {
        let history = self.sessions.load_history(session_id)?;
        Ok(serde_json::to_string_pretty(&history).context("failed to serialize history")?)
    }

    pub fn stats_json(&self) -> Result<String> {
        let bus = self.bus.stats();
        let prompt = self.prompt.stats();
        let telemetry = self.telemetry.snapshot();
        let payload = json!({
            "bus": {
                "published": bus.published,
                "consumed": bus.consumed,
                "dropped": bus.dropped,
                "depth": bus.depth
            },
            "prompt_cache": {
                "hits": prompt.hits,
                "misses": prompt.misses
            },
            "telemetry": {
                "file": self.telemetry.path().display().to_string(),
                "schema_version": telemetry.schema_version,
                "updated_at": telemetry.updated_at,
                "total_turns": telemetry.total_turns,
                "ok_turns": telemetry.ok_turns,
                "error_turns": telemetry.error_turns,
                "provider_turns": telemetry.provider_turns,
                "tool_turns": telemetry.tool_turns,
                "skill_turns": telemetry.skill_turns,
                "total_provider_attempts": telemetry.total_provider_attempts,
                "codex": telemetry.codex,
                "pulse": telemetry.pulse,
                "evolution": telemetry.evolution
            },
            "last_turn": telemetry.last_turn
        });

        Ok(serde_json::to_string_pretty(&payload).context("failed to encode stats")?)
    }

    pub fn codex_status_json(&mut self) -> Result<String> {
        let codex = self.codex_mut()?;
        let status = codex.status();
        self.record_codex_status_snapshot(&status);
        Ok(serde_json::to_string_pretty(&json!({
            "enabled": status.enabled,
            "queue_depth": status.queue_depth,
            "queue_capacity": status.queue_capacity,
            "queue_mode_reason": status.queue_mode_reason,
            "rate_limit_threshold_percent": status.rate_limit_threshold_percent,
            "accounts": status.accounts,
        }))
        .context("failed to encode codex status")?)
    }

    pub fn codex_healthcheck_json(&mut self) -> Result<String> {
        let checks = {
            let codex = self.codex_mut()?;
            codex.health_check()
        };
        let status = {
            let codex = self.codex_mut()?;
            codex.status()
        };
        self.record_codex_status_snapshot(&status);
        Ok(serde_json::to_string_pretty(&json!({
            "checks": checks
        }))
        .context("failed to encode codex health checks")?)
    }

    pub fn codex_generate_json(&mut self, prompt: &str, purpose: &str) -> Result<String> {
        let result = {
            let codex = self.codex_mut()?;
            codex.submit(prompt, purpose)?
        };
        let status = {
            let codex = self.codex_mut()?;
            codex.status()
        };
        self.record_codex_status_snapshot(&status);
        let payload = match result {
            CodexSubmitResult::Executed(exec) => json!({
                "status": "executed",
                "task_id": exec.task_id,
                "account_id": exec.account_id,
                "latency_ms": exec.latency_ms,
                "output": exec.output
            }),
            CodexSubmitResult::Queued {
                task_id,
                queue_depth,
                reason,
            } => json!({
                "status": "queued",
                "task_id": task_id,
                "queue_depth": queue_depth,
                "reason": reason
            }),
        };
        Ok(serde_json::to_string_pretty(&payload)
            .context("failed to encode codex generate result")?)
    }

    pub fn codex_drain_once_json(&mut self) -> Result<String> {
        let payload = match {
            let codex = self.codex_mut()?;
            codex.drain_once()
        } {
            None => json!({
                "status": "noop",
                "message": "queue is empty or throttled by rate-limit guard"
            }),
            Some(Ok(exec)) => json!({
                "status": "executed",
                "task_id": exec.task_id,
                "account_id": exec.account_id,
                "latency_ms": exec.latency_ms,
                "output": exec.output
            }),
            Some(Err(err)) => json!({
                "status": "error",
                "message": err.to_string()
            }),
        };
        let status = {
            let codex = self.codex_mut()?;
            codex.status()
        };
        self.record_codex_status_snapshot(&status);
        Ok(
            serde_json::to_string_pretty(&payload)
                .context("failed to encode codex drain result")?,
        )
    }

    pub fn skills_list_json(&self) -> Result<String> {
        let skills = self.skills.list_skills()?;
        Ok(serde_json::to_string_pretty(&json!({
            "skills_dir": self.skills.skills_dir().display().to_string(),
            "skills": skills
        }))
        .context("failed to encode skills list")?)
    }

    pub fn skills_dry_run_json(&self, skill_name: &str) -> Result<String> {
        self.skills.dry_run(skill_name)?;
        Ok(serde_json::to_string_pretty(&json!({
            "status": "ok",
            "skill": skill_name.trim()
        }))
        .context("failed to encode skills dry-run result")?)
    }

    pub fn skills_run_json(
        &mut self,
        session_id: &str,
        skill_name: &str,
        args: &str,
    ) -> Result<String> {
        let request_id = next_request_id();
        let skill_name = skill_name.trim().to_string();
        let user_chars = args.chars().count();

        let output = match self.skills.run(&skill_name, args) {
            Ok(output) => output,
            Err(err) => {
                let message = err.to_string();
                self.record_turn(TurnRecord {
                    timestamp: Utc::now().to_rfc3339(),
                    request_id: request_id.clone(),
                    session_id: session_id.to_string(),
                    path: "skill".to_string(),
                    status: "error".to_string(),
                    provider: self.settings.provider.clone(),
                    model: self.settings.model.clone(),
                    tool_name: non_empty(skill_name.clone()),
                    attempts: None,
                    latency_ms: None,
                    user_chars,
                    response_chars: 0,
                    error: Some(message.clone()),
                });
                return Err(anyhow!("request_id={}: {}", request_id, message));
            }
        };

        let response = json!({
            "status": "ok",
            "skill": skill_name.clone(),
            "output": output,
        });
        let response_text =
            serde_json::to_string_pretty(&response).context("failed to encode skill output")?;
        let user_command = format!("/skill {} {}", skill_name, args.trim());

        self.sessions
            .append_message(session_id, "user", user_command.trim())
            .context("failed saving user skill command")?;
        self.sessions
            .append_message(session_id, "assistant", &response_text)
            .context("failed saving assistant skill response")?;

        let _ = self
            .bus
            .publish(format!("skill:{}:{}", skill_name, args.trim()));
        let _ = self
            .bus
            .publish(format!("skill_out:{}:{}", skill_name, output));

        self.record_turn(TurnRecord {
            timestamp: Utc::now().to_rfc3339(),
            request_id,
            session_id: session_id.to_string(),
            path: "skill".to_string(),
            status: "ok".to_string(),
            provider: self.settings.provider.clone(),
            model: self.settings.model.clone(),
            tool_name: non_empty(skill_name),
            attempts: None,
            latency_ms: None,
            user_chars,
            response_chars: response_text.chars().count(),
            error: None,
        });

        Ok(response_text)
    }

    pub fn pulse_status_json(&self) -> Result<String> {
        let status = self.pulse.status();
        Ok(serde_json::to_string_pretty(&status).context("failed to encode pulse status")?)
    }

    pub fn pulse_jobs_json(&self) -> Result<String> {
        let status = self.pulse.status();
        Ok(serde_json::to_string_pretty(&json!({
            "jobs": status.jobs
        }))
        .context("failed to encode pulse jobs")?)
    }

    pub fn pulse_add_http_healthcheck_job_json(
        &mut self,
        id: &str,
        interval_secs: u64,
        url: &str,
        expected_status: u16,
        timeout_secs: u64,
        enabled: bool,
    ) -> Result<String> {
        self.pulse.add_http_healthcheck_job(
            id,
            interval_secs,
            url,
            expected_status,
            timeout_secs,
            enabled,
        )?;
        self.persist_pulse_state()?;
        Ok(serde_json::to_string_pretty(&json!({
            "status": "ok",
            "job_id": id.trim(),
            "action": "http_healthcheck",
            "interval_secs": interval_secs,
            "url": url.trim(),
            "expected_status": expected_status,
            "timeout_secs": timeout_secs.max(1),
            "enabled": enabled
        }))
        .context("failed to encode pulse add-job result")?)
    }

    pub fn pulse_remove_job_json(&mut self, id: &str) -> Result<String> {
        let removed = self.pulse.remove_job(id)?;
        self.persist_pulse_state()?;
        Ok(serde_json::to_string_pretty(&json!({
            "status": "ok",
            "action": "removed",
            "job": removed
        }))
        .context("failed to encode pulse remove-job result")?)
    }

    pub fn pulse_enable_job_json(&mut self, id: &str) -> Result<String> {
        let job = self.pulse.enable_job(id)?;
        self.persist_pulse_state()?;
        Ok(serde_json::to_string_pretty(&json!({
            "status": "ok",
            "action": "enabled",
            "job": job
        }))
        .context("failed to encode pulse enable-job result")?)
    }

    pub fn pulse_disable_job_json(&mut self, id: &str) -> Result<String> {
        let job = self.pulse.disable_job(id)?;
        self.persist_pulse_state()?;
        Ok(serde_json::to_string_pretty(&json!({
            "status": "ok",
            "action": "disabled",
            "job": job
        }))
        .context("failed to encode pulse disable-job result")?)
    }

    pub fn pulse_tick_json(&mut self) -> Result<String> {
        let due_jobs = self.pulse.collect_due_jobs();
        let mut results = Vec::new();
        let mut error_jobs = 0usize;
        for job in due_jobs {
            match self.execute_pulse_action(&job.action) {
                Ok(message) => {
                    self.pulse
                        .complete_job(&job.id, "ok", Some(message.clone()))?;
                    results.push(json!({
                        "job_id": job.id,
                        "status": "ok",
                        "message": message
                    }));
                }
                Err(err) => {
                    error_jobs = error_jobs.saturating_add(1);
                    let message = err.to_string();
                    self.pulse
                        .complete_job(&job.id, "error", Some(message.clone()))?;
                    results.push(json!({
                        "job_id": job.id,
                        "status": "error",
                        "message": message
                    }));
                }
            }
        }
        if !results.is_empty() {
            self.persist_pulse_state()?;
            self.record_pulse_status_snapshot(Some((results.len(), error_jobs)));
        }

        Ok(serde_json::to_string_pretty(&json!({
            "executed_jobs": results.len(),
            "results": results
        }))
        .context("failed to encode pulse tick result")?)
    }

    pub fn pulse_add_goal_json(&mut self, id: &str, description: &str) -> Result<String> {
        self.pulse.add_goal(id, description)?;
        self.persist_pulse_state()?;
        Ok(serde_json::to_string_pretty(&json!({
            "status": "ok",
            "goal_id": id.trim()
        }))
        .context("failed to encode pulse add-goal result")?)
    }

    pub fn pulse_goals_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(&json!({
            "goals": self.pulse.goals()
        }))
        .context("failed to encode pulse goals")?)
    }

    pub fn pulse_ooda_json(
        &mut self,
        observations_json: &str,
        action: &str,
        goal_id: Option<&str>,
    ) -> Result<String> {
        let observations = if observations_json.trim().is_empty() {
            Vec::<OodaObservation>::new()
        } else {
            serde_json::from_str::<Vec<OodaObservation>>(observations_json)
                .context("failed parsing observations json")?
        };
        let report = self.pulse.run_ooda_cycle(observations, action, goal_id);
        self.persist_pulse_state()?;
        Ok(serde_json::to_string_pretty(&report).context("failed to encode ooda report")?)
    }

    pub fn pulse_approve_json(&mut self, token: &str) -> Result<String> {
        let approved = self.pulse.approve(token)?;
        self.persist_pulse_state()?;
        Ok(serde_json::to_string_pretty(&json!({
            "status": "approved",
            "approval": approved
        }))
        .context("failed to encode pulse approval result")?)
    }

    pub fn pulse_reject_json(&mut self, token: &str, reason: &str) -> Result<String> {
        let rejected = self.pulse.reject(token, reason)?;
        self.persist_pulse_state()?;
        Ok(serde_json::to_string_pretty(&json!({
            "status": "rejected",
            "approval": rejected
        }))
        .context("failed to encode pulse reject result")?)
    }

    pub fn evolution_generate_skill_json(
        &mut self,
        skill_name: &str,
        goal: &str,
    ) -> Result<String> {
        let skill_name = skill_name.trim();
        let goal = goal.trim();
        if skill_name.is_empty() {
            return Err(anyhow!("skill name is empty"));
        }
        if goal.is_empty() {
            return Err(anyhow!("goal is empty"));
        }

        let prompt = format!(
            "Write a single Rhai script for skill '{skill_name}' to achieve: {goal}. \
Return only valid Rhai code (no markdown). Include a main(args) entrypoint and use only safe helpers like log_info, time_now, http_get, http_post."
        );

        let codex_result = {
            let codex = self.codex_mut()?;
            codex.submit(&prompt, "self_evolution_generate_skill")?
        };
        let codex_status = {
            let codex = self.codex_mut()?;
            codex.status()
        };
        self.record_codex_status_snapshot(&codex_status);

        match codex_result {
            CodexSubmitResult::Queued {
                task_id,
                queue_depth,
                reason,
            } => Ok(serde_json::to_string_pretty(&json!({
                "status": "queued",
                "task_id": task_id,
                "queue_depth": queue_depth,
                "reason": reason
            }))
            .context("failed to encode queued evolution result")?),
            CodexSubmitResult::Executed(exec) => {
                let script = extract_code_block(&exec.output);
                let report =
                    self.evolution
                        .stage_and_promote_skill(&self.skills, skill_name, &script)?;
                self.record_evolution_skill_snapshot(&report);
                Ok(serde_json::to_string_pretty(&json!({
                    "status": "executed",
                    "task_id": exec.task_id,
                    "account_id": exec.account_id,
                    "latency_ms": exec.latency_ms,
                    "generation_prompt": prompt,
                    "evolution_report": report
                }))
                .context("failed to encode evolution result")?)
            }
        }
    }

    pub fn evolution_stage_update_json(
        &self,
        artifact_path: &str,
        current_binary_path: Option<&str>,
        current_version: Option<&str>,
        artifact_version: Option<&str>,
        artifact_sha256: Option<&str>,
        artifact_sha256_sums_file: Option<&str>,
        artifact_sha256_sums_signature_file: Option<&str>,
        artifact_sha256_entry: Option<&str>,
    ) -> Result<String> {
        let artifact = std::path::PathBuf::from(artifact_path.trim());
        if artifact_path.trim().is_empty() {
            return Err(anyhow!("artifact path is empty"));
        }
        let mut artifact_sha256 = artifact_sha256
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        let mut checksum_manifest_provenance: Option<ChecksumManifestProvenance> = None;
        let artifact_sha256_sums_file = artifact_sha256_sums_file
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let artifact_sha256_sums_signature_file = artifact_sha256_sums_signature_file
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(std::path::PathBuf::from);
        let artifact_sha256_entry = artifact_sha256_entry
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let current_version = current_version
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let artifact_version = artifact_version
            .map(str::trim)
            .filter(|value| !value.is_empty());

        if artifact_sha256.is_some() && artifact_sha256_sums_file.is_some() {
            return Err(anyhow!(
                "provide either --artifact-sha256 or --artifact-sha256-sums-file, not both"
            ));
        }
        if current_version.is_some() ^ artifact_version.is_some() {
            return Err(anyhow!(
                "--current-version and --artifact-version must be provided together"
            ));
        }
        if artifact_sha256_sums_signature_file.is_some() && artifact_sha256_sums_file.is_none() {
            return Err(anyhow!(
                "--artifact-sha256-sums-signature-file requires --artifact-sha256-sums-file"
            ));
        }

        if let Some(sums_file) = artifact_sha256_sums_file {
            let resolved = self
                .evolution
                .resolve_artifact_sha256_from_sums_with_provenance(
                    &artifact,
                    &std::path::PathBuf::from(sums_file),
                    artifact_sha256_entry,
                    self.settings.evolution.trusted_sha256sums_sha256.as_deref(),
                    artifact_sha256_sums_signature_file.as_deref(),
                    self.settings
                        .evolution
                        .trusted_sha256sums_ed25519_public_key
                        .as_deref(),
                    self.settings.evolution.require_sha256sums_signature,
                )?;
            artifact_sha256 = Some(resolved.artifact_sha256);
            checksum_manifest_provenance = Some(resolved.checksum_manifest);
        }

        if self.settings.evolution.require_stage_artifact_sha256 && artifact_sha256.is_none() {
            return Err(anyhow!(
                "evolution stage-update is blocked by policy. Re-run with --artifact-sha256 or set RUSTY_PINCH_EVOLUTION_REQUIRE_STAGE_ARTIFACT_SHA256=false"
            ));
        }

        let current_binary = if let Some(path) = current_binary_path {
            std::path::PathBuf::from(path.trim())
        } else {
            std::env::current_exe().context("failed resolving current executable path")?
        };
        let plan = self
            .evolution
            .plan_blue_green_update(&current_binary, &artifact)?;
        self.evolution.stage_blue_green_update(
            &plan,
            self.settings.evolution.manifest_signing_key_id.as_deref(),
            self.settings.evolution.manifest_signing_key.as_deref(),
            artifact_sha256.as_deref(),
            checksum_manifest_provenance,
            current_version,
            artifact_version,
            self.settings.evolution.require_non_rollback_version,
        )?;

        Ok(serde_json::to_string_pretty(&json!({
            "status": "staged",
            "plan": plan
        }))
        .context("failed to encode evolution update plan")?)
    }

    pub fn evolution_apply_staged_update_json(
        &mut self,
        healthcheck_args: &str,
        healthcheck_timeout_secs: u64,
        confirm: bool,
    ) -> Result<String> {
        if self.settings.evolution.require_apply_confirm && !confirm {
            return Err(anyhow!(
                "evolution apply is blocked by policy. Re-run with --confirm or set RUSTY_PINCH_EVOLUTION_REQUIRE_APPLY_CONFIRM=false"
            ));
        }
        let args = parse_whitespace_args(healthcheck_args);
        let apply_result = self.evolution.apply_staged_update(
            &args,
            healthcheck_timeout_secs,
            &self.settings.evolution.manifest_signing_keys,
            self.settings.evolution.require_manifest_signature,
            self.settings
                .evolution
                .require_verified_stage_artifact_sha256,
            self.settings
                .evolution
                .require_signed_checksum_manifest_provenance,
            self.settings.evolution.trusted_sha256sums_sha256.as_deref(),
            self.settings
                .evolution
                .trusted_sha256sums_ed25519_public_key
                .as_deref(),
            self.settings.evolution.require_non_rollback_version,
        );
        self.refresh_evolution_active_slot_integrity_snapshot();
        self.refresh_evolution_failure_circuit_snapshot();
        let report = apply_result?;
        self.record_evolution_apply_snapshot(&report);
        Ok(serde_json::to_string_pretty(&json!({
            "status": report.status,
            "report": report
        }))
        .context("failed to encode evolution apply result")?)
    }

    pub fn evolution_audit_verify_json(&self) -> Result<String> {
        let report = self.evolution.verify_audit_log()?;
        Ok(serde_json::to_string_pretty(&json!({
            "status": "ok",
            "report": report
        }))
        .context("failed to encode evolution audit verify result")?)
    }

    pub fn evolution_lock_status_json(&self) -> Result<String> {
        let report = self.evolution.lock_status()?;
        Ok(serde_json::to_string_pretty(&json!({
            "status": "ok",
            "report": report
        }))
        .context("failed to encode evolution lock status result")?)
    }

    pub fn evolution_force_unlock_json(&self, confirm: bool) -> Result<String> {
        if !confirm {
            return Err(anyhow!(
                "evolution force-unlock requires explicit confirmation. Re-run with --confirm"
            ));
        }
        let report = self.evolution.force_unlock()?;
        Ok(serde_json::to_string_pretty(&json!({
            "status": "ok",
            "report": report
        }))
        .context("failed to encode evolution force-unlock result")?)
    }

    pub fn evolution_recovery_status_json(&self) -> Result<String> {
        let report = self.evolution.recovery_status()?;
        Ok(serde_json::to_string_pretty(&json!({
            "status": "ok",
            "report": report
        }))
        .context("failed to encode evolution recovery status result")?)
    }

    pub fn evolution_active_slot_status_json(&mut self) -> Result<String> {
        let report = self.evolution.active_slot_integrity_status()?;
        self.record_evolution_active_slot_integrity_snapshot(&report);
        Ok(serde_json::to_string_pretty(&json!({
            "status": "ok",
            "report": report
        }))
        .context("failed to encode evolution active-slot status result")?)
    }

    pub fn evolution_failure_circuit_status_json(&mut self) -> Result<String> {
        let report = self.evolution.apply_failure_circuit_status()?;
        self.record_evolution_failure_circuit_snapshot(&report);
        Ok(serde_json::to_string_pretty(&json!({
            "status": "ok",
            "report": report
        }))
        .context("failed to encode evolution failure-circuit status result")?)
    }

    pub fn evolution_failure_circuit_reset_json(&mut self, confirm: bool) -> Result<String> {
        if !confirm {
            return Err(anyhow!(
                "evolution failure-circuit-reset requires explicit confirmation. Re-run with --confirm"
            ));
        }
        let report = self.evolution.reset_apply_failure_circuit()?;
        self.record_evolution_failure_circuit_snapshot(&report);
        Ok(serde_json::to_string_pretty(&json!({
            "status": "ok",
            "report": report
        }))
        .context("failed to encode evolution failure-circuit reset result")?)
    }

    fn codex_mut(&mut self) -> Result<&mut CodexOrchestrator> {
        self.codex
            .as_mut()
            .ok_or_else(|| anyhow!("codex integration is disabled"))
    }

    fn persist_pulse_state(&mut self) -> Result<()> {
        self.pulse
            .persist_persistent_state(&self.pulse_state_file)?;
        self.record_pulse_status_snapshot(None);
        Ok(())
    }

    fn record_codex_status_snapshot(&mut self, status: &crate::codex::CodexStatus) {
        if let Err(err) = self.telemetry.record_codex_status(status) {
            eprintln!("{{\"event\":\"telemetry_error\",\"message\":\"{}\"}}", err);
        }
    }

    fn record_pulse_status_snapshot(&mut self, tick_result: Option<(usize, usize)>) {
        let status = self.pulse.status();
        let result = match tick_result {
            Some((executed, errors)) => self.telemetry.record_pulse_tick(&status, executed, errors),
            None => self.telemetry.record_pulse_status(&status),
        };
        if let Err(err) = result {
            eprintln!("{{\"event\":\"telemetry_error\",\"message\":\"{}\"}}", err);
        }
    }

    fn record_evolution_skill_snapshot(&mut self, report: &SkillEvolutionReport) {
        if let Err(err) = self.telemetry.record_evolution_skill(report) {
            eprintln!("{{\"event\":\"telemetry_error\",\"message\":\"{}\"}}", err);
        }
    }

    fn record_evolution_apply_snapshot(&mut self, report: &BlueGreenApplyReport) {
        if let Err(err) = self.telemetry.record_evolution_apply(report) {
            eprintln!("{{\"event\":\"telemetry_error\",\"message\":\"{}\"}}", err);
        }
    }

    fn record_evolution_active_slot_integrity_snapshot(
        &mut self,
        report: &EvolutionActiveSlotIntegrityReport,
    ) {
        if let Err(err) = self
            .telemetry
            .record_evolution_active_slot_integrity(report)
        {
            eprintln!("{{\"event\":\"telemetry_error\",\"message\":\"{}\"}}", err);
        }
    }

    fn refresh_evolution_active_slot_integrity_snapshot(&mut self) {
        match self.evolution.active_slot_integrity_status() {
            Ok(report) => self.record_evolution_active_slot_integrity_snapshot(&report),
            Err(err) => eprintln!(
                "{{\"event\":\"telemetry_error\",\"message\":\"failed to inspect active-slot integrity: {}\"}}",
                err
            ),
        }
    }

    fn record_evolution_failure_circuit_snapshot(
        &mut self,
        report: &EvolutionApplyFailureCircuitReport,
    ) {
        if let Err(err) = self.telemetry.record_evolution_failure_circuit(report) {
            eprintln!("{{\"event\":\"telemetry_error\",\"message\":\"{}\"}}", err);
        }
    }

    fn refresh_evolution_failure_circuit_snapshot(&mut self) {
        match self.evolution.apply_failure_circuit_status() {
            Ok(report) => self.record_evolution_failure_circuit_snapshot(&report),
            Err(err) => eprintln!(
                "{{\"event\":\"telemetry_error\",\"message\":\"failed to inspect evolution failure circuit: {}\"}}",
                err
            ),
        }
    }

    fn execute_pulse_action(&mut self, action: &PulseAction) -> Result<String> {
        match action {
            PulseAction::EmitLog { message } => {
                eprintln!(
                    "{{\"event\":\"pulse_action\",\"type\":\"emit_log\",\"message\":{}}}",
                    serde_json::to_string(message)
                        .unwrap_or_else(|_| "\"<encode-error>\"".to_string())
                );
                Ok("log emitted".to_string())
            }
            PulseAction::CodexHealthCheck => {
                let checks = {
                    let codex = self.codex_mut()?;
                    codex.health_check()
                };
                let status = {
                    let codex = self.codex_mut()?;
                    codex.status()
                };
                self.record_codex_status_snapshot(&status);
                Ok(format!("codex health checks executed: {}", checks.len()))
            }
            PulseAction::CodexDrainQueueOne => {
                let result = {
                    let codex = self.codex_mut()?;
                    codex.drain_once()
                };
                let status = {
                    let codex = self.codex_mut()?;
                    codex.status()
                };
                self.record_codex_status_snapshot(&status);
                match result {
                    None => Ok("codex queue not drained (empty or throttled)".to_string()),
                    Some(Ok(exec)) => Ok(format!(
                        "codex task {} executed on {}",
                        exec.task_id, exec.account_id
                    )),
                    Some(Err(err)) => Err(err),
                }
            }
            PulseAction::HttpHealthCheck {
                url,
                expected_status,
                timeout_secs,
            } => run_http_healthcheck_action(url, *expected_status, *timeout_secs),
        }
    }

    fn record_turn(&mut self, record: TurnRecord) {
        let payload = json!({
            "event": "turn",
            "timestamp": &record.timestamp,
            "request_id": &record.request_id,
            "session_id": &record.session_id,
            "path": &record.path,
            "status": &record.status,
            "provider": &record.provider,
            "model": &record.model,
            "tool_name": &record.tool_name,
            "attempts": record.attempts,
            "latency_ms": record.latency_ms,
            "user_chars": record.user_chars,
            "response_chars": record.response_chars,
            "error": &record.error,
        });

        if let Ok(line) = serde_json::to_string(&payload) {
            eprintln!("{}", line);
        }

        if let Err(err) = self.telemetry.record_turn(record) {
            eprintln!("{{\"event\":\"telemetry_error\",\"message\":\"{}\"}}", err);
        }
    }
}

fn next_request_id() -> String {
    let epoch_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let seq = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("rp-{:x}-{:x}", epoch_ms, seq)
}

fn format_tool_command(name: &str, args: &str) -> String {
    let tool = name.trim();
    if tool.is_empty() {
        return "/tool".to_string();
    }
    if args.trim().is_empty() {
        format!("/tool {}", tool)
    } else {
        format!("/tool {} {}", tool, args.trim())
    }
}

fn non_empty(value: String) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn extract_code_block(raw: &str) -> String {
    let trimmed = raw.trim();
    if !trimmed.contains("```") {
        return trimmed.to_string();
    }

    let mut lines = trimmed.lines();
    let first = lines.next().unwrap_or_default().trim().to_string();
    if !first.starts_with("```") {
        return trimmed.to_string();
    }

    let mut collected = Vec::new();
    for line in lines {
        if line.trim().starts_with("```") {
            break;
        }
        collected.push(line);
    }
    if collected.is_empty() {
        trimmed.to_string()
    } else {
        collected.join("\n").trim().to_string()
    }
}

fn parse_whitespace_args(raw: &str) -> Vec<String> {
    raw.split_whitespace()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn run_http_healthcheck_action(
    url: &str,
    expected_status: u16,
    timeout_secs: u64,
) -> Result<String> {
    let timeout_secs = timeout_secs.max(1);
    let output = Command::new("curl")
        .arg("-sS")
        .arg("-o")
        .arg("/dev/null")
        .arg("-w")
        .arg("%{http_code}")
        .arg("-m")
        .arg(timeout_secs.to_string())
        .arg(url)
        .output()
        .with_context(|| format!("failed running healthcheck curl for {}", url))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let status = stdout.parse::<u16>().ok().unwrap_or(0);

    if !output.status.success() {
        return Err(anyhow!(
            "http healthcheck failed for {}: curl_exit={:?}, http_status={}, stderr={}",
            url,
            output.status.code(),
            status,
            if stderr.is_empty() {
                "<empty>"
            } else {
                stderr.as_str()
            }
        ));
    }

    if status != expected_status {
        return Err(anyhow!(
            "http healthcheck failed for {}: expected {}, got {}",
            url,
            expected_status,
            status
        ));
    }

    Ok(format!(
        "http healthcheck ok: url={}, status={}",
        url, status
    ))
}
