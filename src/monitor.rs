use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};

use crate::config::Settings;
use crate::telemetry::TelemetrySnapshot;

#[derive(Debug, Clone)]
pub struct MonitorOptions {
    pub pid: Option<i32>,
    pub process_match: String,
    pub interval_ms: u64,
    pub once: bool,
    pub storage_refresh_ticks: u64,
}

#[derive(Debug, Clone, Copy)]
struct CpuSample {
    proc_jiffies: u64,
    total_jiffies: u64,
}

#[derive(Debug, Clone)]
struct ProcessMetrics {
    pid: i32,
    command: String,
    cpu_percent: Option<f64>,
    rss_bytes: Option<u64>,
    vms_bytes: Option<u64>,
    read_bytes: Option<u64>,
    write_bytes: Option<u64>,
    fd_count: Option<usize>,
}

#[derive(Debug, Clone)]
struct HostMetrics {
    mem_total_bytes: Option<u64>,
    mem_available_bytes: Option<u64>,
    swap_total_bytes: Option<u64>,
    swap_free_bytes: Option<u64>,
    load_1m: Option<f64>,
    load_5m: Option<f64>,
    load_15m: Option<f64>,
    cpu_cores: usize,
}

#[derive(Debug, Clone)]
struct FsUsage {
    total_bytes: Option<u64>,
    used_bytes: Option<u64>,
    avail_bytes: Option<u64>,
    used_percent: Option<String>,
}

#[derive(Debug, Clone)]
struct StorageMetrics {
    data_dir: PathBuf,
    workspace_dir: PathBuf,
    data_dir_size_bytes: Option<u64>,
    workspace_dir_size_bytes: Option<u64>,
    fs_usage: FsUsage,
}

pub fn run_tui_monitor(settings: &Settings, options: MonitorOptions) -> Result<()> {
    if options.interval_ms == 0 {
        return Err(anyhow!("interval must be > 0"));
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let signal_flag = Arc::clone(&shutdown);
    ctrlc::set_handler(move || {
        signal_flag.store(true, Ordering::SeqCst);
    })
    .context("failed to register Ctrl+C handler for monitor")?;

    let mut selected_pid = options.pid;
    let mut prev_cpu_sample: Option<CpuSample> = None;
    let mut last_storage: Option<StorageMetrics> = None;
    let refresh_every = options.storage_refresh_ticks.max(1);

    let mut tick: u64 = 0;
    loop {
        if shutdown.load(Ordering::Relaxed) {
            render_exit_message();
            break;
        }

        if selected_pid.is_none() {
            selected_pid = find_matching_pid(&options.process_match);
        }

        let host = read_host_metrics();
        let telemetry = load_telemetry_snapshot(&settings.telemetry_file).ok();

        let process = match selected_pid {
            Some(pid) => match read_process_metrics(pid, &host, prev_cpu_sample) {
                Ok((metrics, next_sample)) => {
                    prev_cpu_sample = Some(next_sample);
                    Some(metrics)
                }
                Err(_) => {
                    selected_pid = find_matching_pid(&options.process_match);
                    prev_cpu_sample = None;
                    None
                }
            },
            None => None,
        };

        let storage = if tick % refresh_every == 0 || last_storage.is_none() {
            let fresh = read_storage_metrics(&settings.data_dir, &settings.workspace);
            last_storage = Some(fresh.clone());
            fresh
        } else {
            last_storage
                .as_ref()
                .cloned()
                .unwrap_or_else(|| read_storage_metrics(&settings.data_dir, &settings.workspace))
        };

        render_dashboard(
            &options,
            settings,
            telemetry.as_ref(),
            process.as_ref(),
            &host,
            &storage,
        )?;

        if options.once {
            break;
        }

        tick = tick.saturating_add(1);
        thread::sleep(Duration::from_millis(options.interval_ms));
    }

    Ok(())
}

fn render_dashboard(
    options: &MonitorOptions,
    settings: &Settings,
    telemetry: Option<&TelemetrySnapshot>,
    process: Option<&ProcessMetrics>,
    host: &HostMetrics,
    storage: &StorageMetrics,
) -> Result<()> {
    print!("\x1B[2J\x1B[H");

    println!("Rusty Pinch Monitor (TUI)");
    println!("time: {}", now_epoch_secs());
    println!(
        "interval: {} ms | match: '{}' | press Ctrl+C to exit",
        options.interval_ms, options.process_match
    );
    println!();

    println!("[APP]");
    println!("provider: {}", settings.provider);
    println!("model: {}", settings.model);
    println!("telemetry_file: {}", settings.telemetry_file.display());

    match telemetry {
        Some(value) => {
            println!(
                "turns: total={} ok={} error={} provider={} tool={}",
                value.total_turns,
                value.ok_turns,
                value.error_turns,
                value.provider_turns,
                value.tool_turns
            );
            println!("last_update: {}", value.updated_at);
            if let Some(last) = &value.last_turn {
                println!(
                    "last_turn: request_id={} path={} status={} session={}",
                    last.request_id, last.path, last.status, last.session_id
                );
            } else {
                println!("last_turn: <none>");
            }
        }
        None => {
            println!("telemetry: unavailable");
        }
    }

    println!();
    println!("[PROCESS]");
    match process {
        Some(proc_metrics) => {
            println!("pid: {}", proc_metrics.pid);
            println!("command: {}", proc_metrics.command);
            println!(
                "cpu: {} | rss: {} | vms: {}",
                proc_metrics
                    .cpu_percent
                    .map(|v| format!("{v:.2}%"))
                    .unwrap_or_else(|| "n/a".to_string()),
                proc_metrics
                    .rss_bytes
                    .map(format_bytes)
                    .unwrap_or_else(|| "n/a".to_string()),
                proc_metrics
                    .vms_bytes
                    .map(format_bytes)
                    .unwrap_or_else(|| "n/a".to_string())
            );
            println!(
                "io: read={} write={} | fd_count={}",
                proc_metrics
                    .read_bytes
                    .map(format_bytes)
                    .unwrap_or_else(|| "n/a".to_string()),
                proc_metrics
                    .write_bytes
                    .map(format_bytes)
                    .unwrap_or_else(|| "n/a".to_string()),
                proc_metrics
                    .fd_count
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "n/a".to_string())
            );
        }
        None => {
            println!("process: not found (waiting for matching pid)");
        }
    }

    println!();
    println!("[HOST]");
    println!(
        "loadavg: {} {} {} | cpu_cores: {}",
        host.load_1m
            .map(|v| format!("{v:.2}"))
            .unwrap_or_else(|| "n/a".to_string()),
        host.load_5m
            .map(|v| format!("{v:.2}"))
            .unwrap_or_else(|| "n/a".to_string()),
        host.load_15m
            .map(|v| format!("{v:.2}"))
            .unwrap_or_else(|| "n/a".to_string()),
        host.cpu_cores
    );

    let mem_total = host
        .mem_total_bytes
        .map(format_bytes)
        .unwrap_or_else(|| "n/a".to_string());
    let mem_avail = host
        .mem_available_bytes
        .map(format_bytes)
        .unwrap_or_else(|| "n/a".to_string());
    let mem_used = match (host.mem_total_bytes, host.mem_available_bytes) {
        (Some(total), Some(avail)) => Some(total.saturating_sub(avail)),
        _ => None,
    };
    println!(
        "memory: used={} total={} available={}",
        mem_used
            .map(format_bytes)
            .unwrap_or_else(|| "n/a".to_string()),
        mem_total,
        mem_avail
    );
    let swap_total = host
        .swap_total_bytes
        .map(format_bytes)
        .unwrap_or_else(|| "n/a".to_string());
    let swap_free = host
        .swap_free_bytes
        .map(format_bytes)
        .unwrap_or_else(|| "n/a".to_string());
    let swap_used = match (host.swap_total_bytes, host.swap_free_bytes) {
        (Some(total), Some(free)) => Some(total.saturating_sub(free)),
        _ => None,
    };
    println!(
        "swap: used={} total={} free={}",
        swap_used
            .map(format_bytes)
            .unwrap_or_else(|| "n/a".to_string()),
        swap_total,
        swap_free
    );

    println!();
    println!("[STORAGE]");
    println!("data_dir: {}", storage.data_dir.display());
    println!("workspace: {}", storage.workspace_dir.display());
    println!(
        "dir_size: data={} workspace={}",
        storage
            .data_dir_size_bytes
            .map(format_bytes)
            .unwrap_or_else(|| "n/a".to_string()),
        storage
            .workspace_dir_size_bytes
            .map(format_bytes)
            .unwrap_or_else(|| "n/a".to_string())
    );
    println!(
        "filesystem: used={} total={} avail={} use%={}",
        storage
            .fs_usage
            .used_bytes
            .map(format_bytes)
            .unwrap_or_else(|| "n/a".to_string()),
        storage
            .fs_usage
            .total_bytes
            .map(format_bytes)
            .unwrap_or_else(|| "n/a".to_string()),
        storage
            .fs_usage
            .avail_bytes
            .map(format_bytes)
            .unwrap_or_else(|| "n/a".to_string()),
        storage
            .fs_usage
            .used_percent
            .clone()
            .unwrap_or_else(|| "n/a".to_string())
    );

    io::stdout()
        .flush()
        .context("failed flushing monitor output")
}

fn render_exit_message() {
    println!("\nmonitor stopped");
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_telemetry_snapshot(path: &Path) -> Result<TelemetrySnapshot> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed reading telemetry file {}", path.display()))?;
    serde_json::from_str::<TelemetrySnapshot>(&raw)
        .with_context(|| format!("failed parsing telemetry file {}", path.display()))
}

fn find_matching_pid(pattern: &str) -> Option<i32> {
    let entries = fs::read_dir("/proc").ok()?;
    let mut matches: Vec<i32> = Vec::new();
    let self_pid = i32::try_from(std::process::id()).ok();

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };

        if Some(pid) == self_pid {
            continue;
        }

        let cmdline_path = format!("/proc/{pid}/cmdline");
        let Ok(raw) = fs::read(&cmdline_path) else {
            continue;
        };

        if raw.is_empty() {
            continue;
        }

        let cmd = raw
            .split(|b| *b == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect::<Vec<String>>()
            .join(" ");

        if cmd.contains(pattern) {
            matches.push(pid);
        }
    }

    matches.sort_unstable();
    matches.into_iter().next()
}

fn read_process_metrics(
    pid: i32,
    host: &HostMetrics,
    previous: Option<CpuSample>,
) -> Result<(ProcessMetrics, CpuSample)> {
    let proc_stat = read_proc_stat(pid)?;
    let total_jiffies = read_total_jiffies()?;

    let cpu_sample = CpuSample {
        proc_jiffies: proc_stat.proc_jiffies,
        total_jiffies,
    };

    let cpu_percent = previous.and_then(|prev| {
        let proc_delta = cpu_sample.proc_jiffies.saturating_sub(prev.proc_jiffies);
        let total_delta = cpu_sample.total_jiffies.saturating_sub(prev.total_jiffies);
        if total_delta == 0 {
            return None;
        }

        let cores = host.cpu_cores.max(1) as f64;
        Some(((proc_delta as f64 / total_delta as f64) * 100.0 * cores).clamp(0.0, 999.0))
    });

    let status = read_key_value_file(Path::new(&format!("/proc/{pid}/status")))?;
    let io = read_key_value_file(Path::new(&format!("/proc/{pid}/io"))).unwrap_or_default();

    let command = read_cmdline(pid).unwrap_or_else(|| "<unknown>".to_string());
    let rss_bytes = status.get("VmRSS").and_then(|v| parse_kib_value(v));
    let vms_bytes = status.get("VmSize").and_then(|v| parse_kib_value(v));
    let read_bytes = io
        .get("read_bytes")
        .and_then(|v| v.trim().parse::<u64>().ok());
    let write_bytes = io
        .get("write_bytes")
        .and_then(|v| v.trim().parse::<u64>().ok());
    let fd_count = fs::read_dir(format!("/proc/{pid}/fd"))
        .ok()
        .map(|iter| iter.count());

    let metrics = ProcessMetrics {
        pid,
        command,
        cpu_percent,
        rss_bytes,
        vms_bytes,
        read_bytes,
        write_bytes,
        fd_count,
    };

    Ok((metrics, cpu_sample))
}

fn read_cmdline(pid: i32) -> Option<String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let cmd = raw
        .split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect::<Vec<String>>()
        .join(" ");
    if cmd.trim().is_empty() {
        None
    } else {
        Some(cmd)
    }
}

fn read_proc_stat(pid: i32) -> Result<ProcStat> {
    let path = format!("/proc/{pid}/stat");
    let raw = fs::read_to_string(&path).with_context(|| format!("failed reading {path}"))?;

    let (_, tail) = raw
        .rsplit_once(')')
        .ok_or_else(|| anyhow!("unexpected /proc stat format"))?;
    let fields = tail.split_whitespace().collect::<Vec<&str>>();

    if fields.len() < 22 {
        return Err(anyhow!("unexpected /proc stat field count"));
    }

    let utime = fields
        .get(11)
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| anyhow!("invalid utime field"))?;
    let stime = fields
        .get(12)
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| anyhow!("invalid stime field"))?;

    Ok(ProcStat {
        proc_jiffies: utime.saturating_add(stime),
    })
}

fn read_total_jiffies() -> Result<u64> {
    let raw = fs::read_to_string("/proc/stat").context("failed reading /proc/stat")?;
    let Some(first) = raw.lines().next() else {
        return Err(anyhow!("/proc/stat is empty"));
    };

    let parts = first.split_whitespace().collect::<Vec<&str>>();
    if parts.is_empty() || parts[0] != "cpu" {
        return Err(anyhow!("unexpected /proc/stat format"));
    }

    let sum = parts
        .iter()
        .skip(1)
        .filter_map(|v| v.parse::<u64>().ok())
        .sum::<u64>();
    Ok(sum)
}

fn read_host_metrics() -> HostMetrics {
    let meminfo = read_key_value_file(Path::new("/proc/meminfo")).unwrap_or_default();
    let loadavg_raw = fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let load_parts = loadavg_raw.split_whitespace().collect::<Vec<&str>>();

    HostMetrics {
        mem_total_bytes: meminfo.get("MemTotal").and_then(|v| parse_kib_value(v)),
        mem_available_bytes: meminfo.get("MemAvailable").and_then(|v| parse_kib_value(v)),
        swap_total_bytes: meminfo.get("SwapTotal").and_then(|v| parse_kib_value(v)),
        swap_free_bytes: meminfo.get("SwapFree").and_then(|v| parse_kib_value(v)),
        load_1m: load_parts.first().and_then(|v| v.parse::<f64>().ok()),
        load_5m: load_parts.get(1).and_then(|v| v.parse::<f64>().ok()),
        load_15m: load_parts.get(2).and_then(|v| v.parse::<f64>().ok()),
        cpu_cores: count_cpu_cores(),
    }
}

fn count_cpu_cores() -> usize {
    let Ok(raw) = fs::read_to_string("/proc/stat") else {
        return 1;
    };

    let mut count = 0usize;
    for line in raw.lines() {
        if line.starts_with("cpu") {
            let bytes = line.as_bytes();
            if bytes.len() > 3 && bytes[3].is_ascii_digit() {
                count = count.saturating_add(1);
            }
        }
    }

    count.max(1)
}

fn read_storage_metrics(data_dir: &Path, workspace_dir: &Path) -> StorageMetrics {
    let fs_usage = read_fs_usage(data_dir).unwrap_or(FsUsage {
        total_bytes: None,
        used_bytes: None,
        avail_bytes: None,
        used_percent: None,
    });

    StorageMetrics {
        data_dir: data_dir.to_path_buf(),
        workspace_dir: workspace_dir.to_path_buf(),
        data_dir_size_bytes: dir_size(data_dir).ok(),
        workspace_dir_size_bytes: dir_size(workspace_dir).ok(),
        fs_usage,
    }
}

fn read_fs_usage(path: &Path) -> Result<FsUsage> {
    let output = Command::new("df")
        .arg("-B1")
        .arg("--output=size,used,avail,pcent")
        .arg(path)
        .output()
        .with_context(|| format!("failed running df for {}", path.display()))?;

    if !output.status.success() {
        return Err(anyhow!("df command failed"));
    }

    let raw = String::from_utf8(output.stdout).context("df output is non-utf8")?;
    let lines = raw.lines().collect::<Vec<&str>>();
    if lines.len() < 2 {
        return Err(anyhow!("unexpected df output"));
    }

    let cols = lines[1].split_whitespace().collect::<Vec<&str>>();
    if cols.len() < 4 {
        return Err(anyhow!("unexpected df columns"));
    }

    Ok(FsUsage {
        total_bytes: cols[0].parse::<u64>().ok(),
        used_bytes: cols[1].parse::<u64>().ok(),
        avail_bytes: cols[2].parse::<u64>().ok(),
        used_percent: Some(cols[3].to_string()),
    })
}

fn dir_size(path: &Path) -> Result<u64> {
    if !path.exists() {
        return Ok(0);
    }

    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("failed reading metadata for {}", path.display()))?;

    if meta.file_type().is_file() {
        return Ok(meta.len());
    }

    if !meta.file_type().is_dir() {
        return Ok(0);
    }

    let mut total = 0u64;
    for entry in fs::read_dir(path).with_context(|| format!("failed reading {}", path.display()))? {
        let entry = entry.with_context(|| format!("failed reading entry in {}", path.display()))?;
        total = total.saturating_add(dir_size(&entry.path())?);
    }

    Ok(total)
}

fn read_key_value_file(path: &Path) -> Result<HashMap<String, String>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed reading key-value file {}", path.display()))?;
    let mut out = HashMap::new();

    for line in raw.lines() {
        if let Some((key, value)) = line.split_once(':') {
            out.insert(key.trim().to_string(), value.trim().to_string());
        } else if let Some((key, value)) = line.split_once(' ') {
            if !key.trim().is_empty() && !value.trim().is_empty() {
                out.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }

    Ok(out)
}

fn parse_kib_value(raw: &str) -> Option<u64> {
    let first = raw.split_whitespace().next()?;
    let value = first.parse::<u64>().ok()?;
    Some(value.saturating_mul(1024))
}

fn format_bytes(value: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;

    let v = value as f64;
    if v >= TB {
        return format!("{:.2} TiB", v / TB);
    }
    if v >= GB {
        return format!("{:.2} GiB", v / GB);
    }
    if v >= MB {
        return format!("{:.2} MiB", v / MB);
    }
    if v >= KB {
        return format!("{:.2} KiB", v / KB);
    }
    format!("{} B", value)
}

struct ProcStat {
    proc_jiffies: u64,
}

#[cfg(test)]
mod tests {
    use super::{format_bytes, parse_kib_value};

    #[test]
    fn parse_kib_value_converts_to_bytes() {
        let got = parse_kib_value("2048 kB");
        assert_eq!(got, Some(2 * 1024 * 1024));
    }

    #[test]
    fn format_bytes_human_readable() {
        assert_eq!(format_bytes(512), "512 B");
        assert!(format_bytes(1024 * 1024).contains("MiB"));
    }
}
