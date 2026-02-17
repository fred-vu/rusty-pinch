use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};

use rusty_pinch::app::RustyPinchApp;
use rusty_pinch::channels;
use rusty_pinch::config::Settings;
use rusty_pinch::monitor::{self, MonitorOptions};

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

fn main() -> Result<()> {
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
