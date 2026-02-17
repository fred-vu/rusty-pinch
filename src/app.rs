use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use serde_json::json;

use crate::bus::{MessageBus, OverflowPolicy};
use crate::config::{DoctorReport, Settings};
use crate::prompt::PromptBuilder;
use crate::provider;
use crate::session::SessionStore;
use crate::telemetry::{TelemetryStore, TurnRecord};
use crate::tools::{parse_tool_invocation, ToolContext, ToolRegistry, ToolSpec};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

pub struct RustyPinchApp {
    settings: Settings,
    sessions: SessionStore,
    bus: MessageBus,
    prompt: PromptBuilder,
    tools: ToolRegistry,
    telemetry: TelemetryStore,
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
        let telemetry = TelemetryStore::new(settings.telemetry_file.clone())?;

        Ok(Self {
            settings,
            sessions,
            bus: MessageBus::new(capacity, overflow),
            prompt: PromptBuilder::default(),
            tools: ToolRegistry::with_defaults(),
            telemetry,
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
        let provider_metrics = completion.metrics;
        let response = completion.content;

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
                attempts: Some(provider_metrics.attempts),
                latency_ms: Some(provider_metrics.latency_ms),
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
                attempts: Some(provider_metrics.attempts),
                latency_ms: Some(provider_metrics.latency_ms),
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
            attempts: Some(provider_metrics.attempts),
            latency_ms: Some(provider_metrics.latency_ms),
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
                "total_provider_attempts": telemetry.total_provider_attempts
            },
            "last_turn": telemetry.last_turn
        });

        Ok(serde_json::to_string_pretty(&payload).context("failed to encode stats")?)
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
