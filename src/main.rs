use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};

use rusty_pinch::app::RustyPinchApp;
use rusty_pinch::channels;
use rusty_pinch::config::Settings;
use rusty_pinch::monitor::{self, MonitorOptions};
use rusty_pinch::observability::ObservabilityGuard;

#[derive(Parser, Debug)]
#[command(name = "rusty-pinch")]
#[command(about = "Rusty Pinch clean Rust package", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Validate runtime config and API key loading.
    Doctor,
    /// Run one message turn.
    Run {
        #[arg(long, default_value = "default")]
        session: String,
        #[arg(long)]
        message: String,
    },
    /// Deterministic local tool commands.
    Tools {
        #[command(subcommand)]
        command: ToolCommands,
    },
    /// Rhai skill runtime commands.
    Skills {
        #[command(subcommand)]
        command: SkillCommands,
    },
    /// Run channel listeners (Telegram / WhatsApp bridge).
    Channels {
        #[command(subcommand)]
        command: ChannelCommands,
    },
    /// Start interactive REPL loop.
    Repl {
        #[arg(long, default_value = "default")]
        session: String,
    },
    /// Show current session history as JSON.
    Session {
        #[arg(long, default_value = "default")]
        session: String,
    },
    /// Print internal bus/prompt stats.
    Stats,
    /// Live TUI monitor for app/process/host/storage metrics.
    Monitor {
        /// Optional explicit PID to monitor.
        #[arg(long, value_parser = parse_positive_i32)]
        pid: Option<i32>,
        /// Substring match used to discover target process from /proc/*/cmdline.
        #[arg(long, default_value = "rusty-pinch")]
        process_match: String,
        /// Refresh interval in milliseconds.
        #[arg(long, default_value_t = 1000, value_parser = parse_positive_u64)]
        interval_ms: u64,
        /// Refresh storage size scan every N ticks.
        #[arg(
            long,
            default_value_t = 10,
            value_parser = parse_positive_u64
        )]
        storage_refresh_ticks: u64,
        /// Render one snapshot then exit.
        #[arg(long, default_value_t = false)]
        once: bool,
    },
    /// Codex CLI integration (account pool, queue, health checks).
    Codex {
        #[command(subcommand)]
        command: CodexCommands,
    },
    /// Pulse scheduler + OODA loop commands.
    Pulse {
        #[command(subcommand)]
        command: PulseCommands,
    },
    /// Self-evolution and update pipeline commands.
    Evolution {
        #[command(subcommand)]
        command: EvolutionCommands,
    },
}

#[derive(Subcommand, Debug)]
enum ToolCommands {
    /// List built-in tools in deterministic order.
    List,
    /// Run one local tool command without LLM call.
    Run {
        #[arg(long, default_value = "default")]
        session: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "")]
        args: String,
    },
}

#[derive(Subcommand, Debug)]
enum SkillCommands {
    /// List available Rhai skills in workspace.
    List,
    /// Compile-check a skill without executing it.
    DryRun {
        #[arg(long)]
        name: String,
    },
    /// Execute a skill and persist output in the session log.
    Run {
        #[arg(long, default_value = "default")]
        session: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "")]
        args: String,
    },
}

#[derive(Subcommand, Debug)]
enum ChannelCommands {
    /// Start Telegram long-polling listener.
    Telegram {
        /// Stop after N processed inbound messages (for smoke testing).
        #[arg(long, value_parser = parse_positive_usize)]
        max_messages: Option<usize>,
    },
    /// Start WhatsApp bridge websocket listener.
    Whatsapp {
        /// Stop after N processed inbound messages (for smoke testing).
        #[arg(long, value_parser = parse_positive_usize)]
        max_messages: Option<usize>,
    },
}

#[derive(Subcommand, Debug)]
enum CodexCommands {
    /// Print codex account and queue status.
    Status,
    /// Force codex account health checks.
    Healthcheck,
    /// Submit one codex generation request.
    Generate {
        #[arg(long)]
        prompt: String,
        #[arg(long, default_value = "general")]
        purpose: String,
    },
    /// Drain one queued codex task if allowed.
    DrainOne,
}

#[derive(Subcommand, Debug)]
enum PulseCommands {
    /// Show pulse scheduler jobs, goals, and pending approvals.
    Status,
    /// Manage pulse scheduler jobs.
    Job {
        #[command(subcommand)]
        command: PulseJobCommands,
    },
    /// Execute due scheduled jobs once.
    Tick,
    /// Run one OODA cycle.
    Ooda {
        /// Action proposal evaluated by OODA.
        #[arg(long)]
        action: String,
        /// JSON array of observations.
        #[arg(long, default_value = "[]")]
        observations: String,
        /// Optional goal id to mark achieved when action is approved.
        #[arg(long)]
        goal: Option<String>,
    },
    /// Add or inspect pulse goals.
    Goal {
        #[command(subcommand)]
        command: PulseGoalCommands,
    },
    /// Approve a pending risky action token.
    Approve {
        #[arg(long)]
        token: String,
    },
    /// Reject a pending risky action token.
    Reject {
        #[arg(long)]
        token: String,
        #[arg(long, default_value = "rejected by operator")]
        reason: String,
    },
}

#[derive(Subcommand, Debug)]
enum PulseGoalCommands {
    /// Add a tracked goal.
    Add {
        #[arg(long)]
        id: String,
        #[arg(long)]
        description: String,
    },
    /// List tracked goals.
    List,
}

#[derive(Subcommand, Debug)]
enum PulseJobCommands {
    /// List registered jobs.
    List,
    /// Register an external HTTP health probe job.
    AddHttpHealthcheck {
        #[arg(long)]
        id: String,
        #[arg(long, value_parser = parse_positive_u64)]
        interval_secs: u64,
        #[arg(long)]
        url: String,
        #[arg(long, default_value_t = 200, value_parser = parse_http_status_code)]
        expected_status: u16,
        #[arg(long, default_value_t = 20, value_parser = parse_positive_u64)]
        timeout_secs: u64,
        #[arg(long, default_value_t = true)]
        enabled: bool,
    },
    /// Remove a registered job.
    Remove {
        #[arg(long)]
        id: String,
    },
    /// Enable a registered job.
    Enable {
        #[arg(long)]
        id: String,
    },
    /// Disable a registered job.
    Disable {
        #[arg(long)]
        id: String,
    },
}

#[derive(Subcommand, Debug)]
enum EvolutionCommands {
    /// Ask Codex to generate a new Rhai skill, then stage+promote if validation passes.
    GenerateSkill {
        #[arg(long)]
        name: String,
        #[arg(long)]
        goal: String,
    },
    /// Stage a blue/green binary update plan from a built artifact.
    StageUpdate {
        #[arg(long)]
        artifact: String,
        #[arg(long)]
        current_binary: Option<String>,
        /// Optional current binary version used for anti-rollback policy checks.
        #[arg(long)]
        current_version: Option<String>,
        /// Optional artifact version used for anti-rollback policy checks.
        #[arg(long)]
        artifact_version: Option<String>,
        /// Optional expected SHA-256 checksum for release provenance verification.
        #[arg(long)]
        artifact_sha256: Option<String>,
        /// Optional checksum manifest file (sha256sum format) used to resolve artifact checksum.
        #[arg(long)]
        artifact_sha256_sums_file: Option<String>,
        /// Optional detached Ed25519 signature file for checksum manifest verification.
        #[arg(long)]
        artifact_sha256_sums_signature_file: Option<String>,
        /// Optional entry name inside checksum manifest (default: artifact filename).
        #[arg(long)]
        artifact_sha256_entry: Option<String>,
    },
    /// Apply staged update, run health check, and rollback automatically on failure.
    ApplyStagedUpdate {
        /// Optional health check args passed to staged binary (default: "doctor").
        #[arg(long, default_value = "doctor")]
        healthcheck_args: String,
        /// Health check timeout in seconds before forced kill and rollback.
        #[arg(long, default_value_t = 30, value_parser = parse_positive_u64)]
        healthcheck_timeout_secs: u64,
        /// Explicit confirmation required by default policy for self-update apply.
        #[arg(long, default_value_t = false)]
        confirm: bool,
    },
    /// Verify the evolution rollout audit log hash chain.
    AuditVerify,
    /// Inspect evolution lock status and stale-lock diagnostics.
    LockStatus,
    /// Inspect staged apply checkpoint/recovery diagnostics.
    RecoveryStatus,
    /// Inspect active-slot marker integrity/signature diagnostics.
    ActiveSlotStatus,
    /// Inspect evolution apply-failure circuit breaker status.
    FailureCircuitStatus,
    /// Reset evolution apply-failure circuit breaker state.
    FailureCircuitReset {
        /// Explicit confirmation required to reset failure circuit state.
        #[arg(long, default_value_t = false)]
        confirm: bool,
    },
    /// Remove evolution operation lock file manually.
    ForceUnlock {
        /// Explicit confirmation required for force unlock.
        #[arg(long, default_value_t = false)]
        confirm: bool,
    },
}

fn main() -> Result<()> {
    let _observability = ObservabilityGuard::init();
    let cli = Cli::parse();
    let settings = Settings::load()?;
    let channel_settings = settings.clone();
    let mut app = RustyPinchApp::new(settings)?;

    match cli.command.unwrap_or(Commands::Doctor) {
        Commands::Doctor => {
            let report = app.doctor();
            println!("Rusty Pinch Doctor");
            println!("provider: {}", report.provider);
            println!("model: {}", report.model);
            println!(
                "api_base: {}",
                report.api_base.unwrap_or_else(|| "<unset>".to_string())
            );
            println!("data_dir: {}", report.data_dir.display());
            println!("workspace: {}", report.workspace.display());
            println!("telemetry_file: {}", report.telemetry_file.display());
            println!("request_timeout_secs: {}", report.request_timeout_secs);
            println!("request_retries: {}", report.request_retries);
            println!("retry_backoff_ms: {}", report.retry_backoff_ms);
            println!("retry_max_backoff_ms: {}", report.retry_max_backoff_ms);
            println!("api_key_loaded: {}", report.key_present);
            println!("telegram_enabled: {}", report.telegram_enabled);
            println!(
                "telegram_allow_from_count: {}",
                report.telegram_allow_from_count
            );
            println!("whatsapp_enabled: {}", report.whatsapp_enabled);
            println!(
                "whatsapp_allow_from_count: {}",
                report.whatsapp_allow_from_count
            );
            println!("codex_enabled: {}", report.codex_enabled);
            println!("codex_accounts_count: {}", report.codex_accounts_count);
            println!("codex_queue_capacity: {}", report.codex_queue_capacity);
            println!(
                "codex_rate_limit_threshold_percent: {}",
                report.codex_rate_limit_threshold_percent
            );
            println!(
                "pulse_auto_allow_actions_count: {}",
                report.pulse_auto_allow_actions_count
            );
            println!(
                "evolution_require_apply_confirm: {}",
                report.evolution_require_apply_confirm
            );
            println!(
                "evolution_require_stage_artifact_sha256: {}",
                report.evolution_require_stage_artifact_sha256
            );
            println!(
                "evolution_require_verified_stage_artifact_sha256: {}",
                report.evolution_require_verified_stage_artifact_sha256
            );
            println!(
                "evolution_require_signed_checksum_manifest_provenance: {}",
                report.evolution_require_signed_checksum_manifest_provenance
            );
            println!(
                "evolution_require_non_rollback_version: {}",
                report.evolution_require_non_rollback_version
            );
            println!(
                "evolution_trusted_sha256sums_sha256_loaded: {}",
                report.evolution_trusted_sha256sums_sha256_loaded
            );
            println!(
                "evolution_trusted_sha256sums_ed25519_public_key_loaded: {}",
                report.evolution_trusted_sha256sums_ed25519_public_key_loaded
            );
            println!(
                "evolution_require_sha256sums_signature: {}",
                report.evolution_require_sha256sums_signature
            );
            println!(
                "evolution_manifest_signing_key_id: {}",
                report
                    .evolution_manifest_signing_key_id
                    .clone()
                    .unwrap_or_else(|| "<unset>".to_string())
            );
            println!(
                "evolution_manifest_signing_key_loaded: {}",
                report.evolution_manifest_signing_key_loaded
            );
            println!(
                "evolution_manifest_signing_keys_count: {}",
                report.evolution_manifest_signing_keys_count
            );
            println!(
                "evolution_require_manifest_signature: {}",
                report.evolution_require_manifest_signature
            );
            println!(
                "evolution_active_slot_signing_key_id: {}",
                report
                    .evolution_active_slot_signing_key_id
                    .clone()
                    .unwrap_or_else(|| "<unset>".to_string())
            );
            println!(
                "evolution_active_slot_signing_key_loaded: {}",
                report.evolution_active_slot_signing_key_loaded
            );
            println!(
                "evolution_require_signed_active_slot: {}",
                report.evolution_require_signed_active_slot
            );
            println!(
                "evolution_max_staged_manifest_age_secs: {}",
                report
                    .evolution_max_staged_manifest_age_secs
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "<disabled>".to_string())
            );
            println!(
                "evolution_max_consecutive_apply_failures: {}",
                report
                    .evolution_max_consecutive_apply_failures
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "<disabled>".to_string())
            );
            println!(
                "evolution_lock_stale_after_secs: {}",
                report
                    .evolution_lock_stale_after_secs
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "<disabled>".to_string())
            );
            println!(
                "evolution_auto_recover_stale_lock: {}",
                report.evolution_auto_recover_stale_lock
            );
            if report.warnings.is_empty() {
                println!("status: ok");
            } else {
                println!("status: warning");
                for warning in report.warnings {
                    println!("- {}", warning);
                }
            }
        }
        Commands::Run { session, message } => {
            let response = app.process_turn(&session, &message)?;
            println!("{}", response);
        }
        Commands::Tools { command } => match command {
            ToolCommands::List => {
                for spec in app.list_tools() {
                    println!(
                        "{} - {}\n  usage: {}",
                        spec.name, spec.description, spec.usage
                    );
                }
            }
            ToolCommands::Run {
                session,
                name,
                args,
            } => {
                let response = app.run_tool(&session, &name, &args)?;
                println!("{}", response);
            }
        },
        Commands::Skills { command } => match command {
            SkillCommands::List => {
                println!("{}", app.skills_list_json()?);
            }
            SkillCommands::DryRun { name } => {
                println!("{}", app.skills_dry_run_json(&name)?);
            }
            SkillCommands::Run {
                session,
                name,
                args,
            } => {
                println!("{}", app.skills_run_json(&session, &name, &args)?);
            }
        },
        Commands::Channels { command } => match command {
            ChannelCommands::Telegram { max_messages } => {
                let options = build_channel_options(max_messages)?;
                channels::run_telegram_polling(&mut app, &channel_settings, &options)?
            }
            ChannelCommands::Whatsapp { max_messages } => {
                let options = build_channel_options(max_messages)?;
                channels::run_whatsapp_bridge(&mut app, &channel_settings, &options)?
            }
        },
        Commands::Repl { session } => repl_loop(&mut app, &session)?,
        Commands::Session { session } => {
            println!("{}", app.session_history_json(&session)?);
        }
        Commands::Stats => {
            println!("{}", app.stats_json()?);
        }
        Commands::Monitor {
            pid,
            process_match,
            interval_ms,
            storage_refresh_ticks,
            once,
        } => {
            let options = MonitorOptions {
                pid,
                process_match,
                interval_ms,
                once,
                storage_refresh_ticks,
            };
            monitor::run_tui_monitor(&channel_settings, options)?;
        }
        Commands::Codex { command } => match command {
            CodexCommands::Status => {
                println!("{}", app.codex_status_json()?);
            }
            CodexCommands::Healthcheck => {
                println!("{}", app.codex_healthcheck_json()?);
            }
            CodexCommands::Generate { prompt, purpose } => {
                println!("{}", app.codex_generate_json(&prompt, &purpose)?);
            }
            CodexCommands::DrainOne => {
                println!("{}", app.codex_drain_once_json()?);
            }
        },
        Commands::Pulse { command } => match command {
            PulseCommands::Status => {
                println!("{}", app.pulse_status_json()?);
            }
            PulseCommands::Job { command } => match command {
                PulseJobCommands::List => {
                    println!("{}", app.pulse_jobs_json()?);
                }
                PulseJobCommands::AddHttpHealthcheck {
                    id,
                    interval_secs,
                    url,
                    expected_status,
                    timeout_secs,
                    enabled,
                } => {
                    println!(
                        "{}",
                        app.pulse_add_http_healthcheck_job_json(
                            &id,
                            interval_secs,
                            &url,
                            expected_status,
                            timeout_secs,
                            enabled,
                        )?
                    );
                }
                PulseJobCommands::Remove { id } => {
                    println!("{}", app.pulse_remove_job_json(&id)?);
                }
                PulseJobCommands::Enable { id } => {
                    println!("{}", app.pulse_enable_job_json(&id)?);
                }
                PulseJobCommands::Disable { id } => {
                    println!("{}", app.pulse_disable_job_json(&id)?);
                }
            },
            PulseCommands::Tick => {
                println!("{}", app.pulse_tick_json()?);
            }
            PulseCommands::Ooda {
                action,
                observations,
                goal,
            } => {
                println!(
                    "{}",
                    app.pulse_ooda_json(&observations, &action, goal.as_deref())?
                );
            }
            PulseCommands::Goal { command } => match command {
                PulseGoalCommands::Add { id, description } => {
                    println!("{}", app.pulse_add_goal_json(&id, &description)?);
                }
                PulseGoalCommands::List => {
                    println!("{}", app.pulse_goals_json()?);
                }
            },
            PulseCommands::Approve { token } => {
                println!("{}", app.pulse_approve_json(&token)?);
            }
            PulseCommands::Reject { token, reason } => {
                println!("{}", app.pulse_reject_json(&token, &reason)?);
            }
        },
        Commands::Evolution { command } => match command {
            EvolutionCommands::GenerateSkill { name, goal } => {
                println!("{}", app.evolution_generate_skill_json(&name, &goal)?);
            }
            EvolutionCommands::StageUpdate {
                artifact,
                current_binary,
                current_version,
                artifact_version,
                artifact_sha256,
                artifact_sha256_sums_file,
                artifact_sha256_sums_signature_file,
                artifact_sha256_entry,
            } => {
                println!(
                    "{}",
                    app.evolution_stage_update_json(
                        &artifact,
                        current_binary.as_deref(),
                        current_version.as_deref(),
                        artifact_version.as_deref(),
                        artifact_sha256.as_deref(),
                        artifact_sha256_sums_file.as_deref(),
                        artifact_sha256_sums_signature_file.as_deref(),
                        artifact_sha256_entry.as_deref(),
                    )?
                );
            }
            EvolutionCommands::ApplyStagedUpdate {
                healthcheck_args,
                healthcheck_timeout_secs,
                confirm,
            } => {
                println!(
                    "{}",
                    app.evolution_apply_staged_update_json(
                        &healthcheck_args,
                        healthcheck_timeout_secs,
                        confirm,
                    )?
                );
            }
            EvolutionCommands::AuditVerify => {
                println!("{}", app.evolution_audit_verify_json()?);
            }
            EvolutionCommands::LockStatus => {
                println!("{}", app.evolution_lock_status_json()?);
            }
            EvolutionCommands::RecoveryStatus => {
                println!("{}", app.evolution_recovery_status_json()?);
            }
            EvolutionCommands::ActiveSlotStatus => {
                println!("{}", app.evolution_active_slot_status_json()?);
            }
            EvolutionCommands::FailureCircuitStatus => {
                println!("{}", app.evolution_failure_circuit_status_json()?);
            }
            EvolutionCommands::FailureCircuitReset { confirm } => {
                println!("{}", app.evolution_failure_circuit_reset_json(confirm)?);
            }
            EvolutionCommands::ForceUnlock { confirm } => {
                println!("{}", app.evolution_force_unlock_json(confirm)?);
            }
        },
    }

    Ok(())
}

fn build_channel_options(max_messages: Option<usize>) -> Result<channels::ChannelRunOptions> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let signal_flag = Arc::clone(&shutdown);
    ctrlc::set_handler(move || {
        signal_flag.store(true, Ordering::SeqCst);
        eprintln!(
            "{{\"event\":\"channel_signal\",\"signal\":\"interrupt\",\"action\":\"graceful_stop\"}}"
        );
    })?;

    Ok(channels::ChannelRunOptions {
        max_messages,
        shutdown: Some(shutdown),
    })
}

fn parse_positive_usize(value: &str) -> std::result::Result<usize, String> {
    let parsed = value
        .trim()
        .parse::<usize>()
        .map_err(|_| format!("invalid positive integer: {value}"))?;
    if parsed == 0 {
        return Err("value must be >= 1".to_string());
    }
    Ok(parsed)
}

fn parse_positive_u64(value: &str) -> std::result::Result<u64, String> {
    let parsed = value
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("invalid positive integer: {value}"))?;
    if parsed == 0 {
        return Err("value must be >= 1".to_string());
    }
    Ok(parsed)
}

fn parse_positive_i32(value: &str) -> std::result::Result<i32, String> {
    let parsed = value
        .trim()
        .parse::<i32>()
        .map_err(|_| format!("invalid positive integer: {value}"))?;
    if parsed <= 0 {
        return Err("value must be >= 1".to_string());
    }
    Ok(parsed)
}

fn parse_http_status_code(value: &str) -> std::result::Result<u16, String> {
    let parsed = value
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("invalid HTTP status code: {value}"))?;
    if !(100..=599).contains(&parsed) {
        return Err("http status code must be in 100..=599".to_string());
    }
    Ok(parsed)
}

fn repl_loop(app: &mut RustyPinchApp, session: &str) -> Result<()> {
    println!("Rusty Pinch REPL. Type 'exit' to stop.");

    loop {
        print!("> ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let input = input.trim();
        if input.is_empty() {
            continue;
        }
        if input.eq_ignore_ascii_case("exit") || input.eq_ignore_ascii_case("quit") {
            println!("Bye.");
            break;
        }

        let response = app.process_turn(session, input)?;
        println!("{}", response);
    }

    Ok(())
}
