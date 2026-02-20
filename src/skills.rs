use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use rhai::{Dynamic, Engine, EvalAltResult, Scope, AST};
use serde::Serialize;

const DEFAULT_MAX_SCRIPT_BYTES: usize = 128 * 1024;
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 20;

#[derive(Debug, Clone, Serialize)]
pub struct SkillSpec {
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub modified_at: Option<String>,
}

pub struct SkillManager {
    skills_dir: PathBuf,
    engine: Engine,
    max_script_bytes: usize,
}

impl SkillManager {
    pub fn new(skills_dir: impl AsRef<Path>) -> Result<Self> {
        let http_timeout_secs = env::var("RUSTY_PINCH_SKILL_HTTP_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_HTTP_TIMEOUT_SECS);
        Self::with_limits(skills_dir, DEFAULT_MAX_SCRIPT_BYTES, http_timeout_secs)
    }

    pub fn with_limits(
        skills_dir: impl AsRef<Path>,
        max_script_bytes: usize,
        http_timeout_secs: u64,
    ) -> Result<Self> {
        let skills_dir = skills_dir.as_ref().to_path_buf();
        fs::create_dir_all(&skills_dir)
            .with_context(|| format!("failed creating skills dir {}", skills_dir.display()))?;

        let mut engine = Engine::new();
        configure_engine(&mut engine, http_timeout_secs.max(1));

        Ok(Self {
            skills_dir,
            engine,
            max_script_bytes: max_script_bytes.max(1024),
        })
    }

    pub fn skills_dir(&self) -> &Path {
        &self.skills_dir
    }

    pub fn sync_from_assets(&self, assets_dir: impl AsRef<Path>) -> Result<usize> {
        let assets_dir = assets_dir.as_ref();
        if !assets_dir.exists() {
            return Ok(0);
        }
        if !assets_dir.is_dir() {
            return Err(anyhow!(
                "assets skills path is not a directory: {}",
                assets_dir.display()
            ));
        }

        let mut copied = 0usize;
        for entry in fs::read_dir(assets_dir)
            .with_context(|| format!("failed reading assets skills dir {}", assets_dir.display()))?
        {
            let entry = entry.with_context(|| {
                format!(
                    "failed reading entry in assets skills dir {}",
                    assets_dir.display()
                )
            })?;
            let source = entry.path();
            if source.extension().and_then(|v| v.to_str()) != Some("rhai") {
                continue;
            }

            let stem = source
                .file_stem()
                .and_then(|v| v.to_str())
                .ok_or_else(|| anyhow!("invalid asset skill filename '{}'", source.display()))?;
            let skill_name = normalize_skill_name(stem)?;
            let destination = self.skills_dir.join(format!("{}.rhai", skill_name));
            if destination.exists() {
                if should_refresh_existing_asset_skill(&skill_name, &destination)? {
                    fs::copy(&source, &destination).with_context(|| {
                        format!(
                            "failed refreshing asset skill '{}' at '{}'",
                            source.display(),
                            destination.display()
                        )
                    })?;
                    copied = copied.saturating_add(1);
                }
                continue;
            }

            fs::copy(&source, &destination).with_context(|| {
                format!(
                    "failed copying asset skill '{}' to '{}'",
                    source.display(),
                    destination.display()
                )
            })?;
            copied = copied.saturating_add(1);
        }

        Ok(copied)
    }

    pub fn list_skills(&self) -> Result<Vec<SkillSpec>> {
        let mut skills = Vec::new();
        for entry in fs::read_dir(&self.skills_dir)
            .with_context(|| format!("failed reading {}", self.skills_dir.display()))?
        {
            let entry = entry.with_context(|| {
                format!("failed reading entry in {}", self.skills_dir.display())
            })?;
            let path = entry.path();
            if path.extension().and_then(|v| v.to_str()) != Some("rhai") {
                continue;
            }

            let name = path
                .file_stem()
                .and_then(|v| v.to_str())
                .unwrap_or_default()
                .to_string();
            if name.is_empty() {
                continue;
            }

            let metadata = entry
                .metadata()
                .with_context(|| format!("failed reading metadata for {}", path.display()))?;
            let modified_at = metadata
                .modified()
                .ok()
                .map(DateTime::<Utc>::from)
                .map(|dt| dt.to_rfc3339());

            skills.push(SkillSpec {
                name,
                path: path.display().to_string(),
                size_bytes: metadata.len(),
                modified_at,
            });
        }

        skills.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(skills)
    }

    pub fn dry_run(&self, skill_name: &str) -> Result<()> {
        let script = self.load_script(skill_name)?;
        self.compile(&script)
            .with_context(|| format!("skill '{}' failed dry run", skill_name))?;
        Ok(())
    }

    pub fn dry_run_source(&self, script: &str) -> Result<()> {
        if script.trim().is_empty() {
            return Err(anyhow!("skill script is empty"));
        }
        if script.len() > self.max_script_bytes {
            return Err(anyhow!(
                "skill script exceeds size limit ({} bytes)",
                self.max_script_bytes
            ));
        }
        self.compile(script)
            .context("skill source failed dry-run compile")?;
        Ok(())
    }

    pub fn run(&self, skill_name: &str, args: &str) -> Result<String> {
        let script = self.load_script(skill_name)?;
        let ast = self
            .compile(&script)
            .with_context(|| format!("skill '{}' failed compile", skill_name))?;

        let args = args.trim();
        let mut scope = Scope::new();

        if !args.is_empty() {
            match self
                .engine
                .call_fn::<Dynamic>(&mut scope, &ast, "main", (args.to_string(),))
            {
                Ok(value) => return Ok(dynamic_to_text(value)),
                Err(err) => {
                    if !is_main_signature_mismatch(&err) {
                        return Err(anyhow!("skill '{}' execution failed: {}", skill_name, err));
                    }
                }
            }
        }

        let value = self
            .engine
            .call_fn::<Dynamic>(&mut scope, &ast, "main", ())
            .map_err(|err| anyhow!("skill '{}' execution failed: {}", skill_name, err))?;
        Ok(dynamic_to_text(value))
    }

    pub fn write_skill(&self, skill_name: &str, script: &str) -> Result<PathBuf> {
        let name = normalize_skill_name(skill_name)?;
        if script.trim().is_empty() {
            return Err(anyhow!("skill script is empty"));
        }
        if script.len() > self.max_script_bytes {
            return Err(anyhow!(
                "skill script exceeds size limit ({} bytes)",
                self.max_script_bytes
            ));
        }

        let path = self.skills_dir.join(format!("{}.rhai", name));
        fs::write(&path, script).with_context(|| format!("failed writing {}", path.display()))?;
        Ok(path)
    }

    fn compile(&self, script: &str) -> Result<AST> {
        self.engine
            .compile(script)
            .map_err(|err| anyhow!("rhai compile error: {}", err))
    }

    fn load_script(&self, skill_name: &str) -> Result<String> {
        let name = normalize_skill_name(skill_name)?;
        let path = self.skills_dir.join(format!("{}.rhai", name));
        let metadata = fs::metadata(&path)
            .with_context(|| format!("skill '{}' not found at {}", name, path.display()))?;
        let size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        if size > self.max_script_bytes {
            return Err(anyhow!(
                "skill '{}' exceeds size limit ({} bytes > {})",
                name,
                size,
                self.max_script_bytes
            ));
        }

        fs::read_to_string(&path).with_context(|| format!("failed reading {}", path.display()))
    }
}

fn configure_engine(engine: &mut Engine, http_timeout_secs: u64) {
    engine.set_max_operations(100_000);
    engine.set_max_call_levels(32);
    engine.set_max_expr_depths(64, 32);
    engine.set_max_string_size(128 * 1024);
    engine.set_max_array_size(4096);
    engine.set_max_map_size(256);
    engine.on_print(|text| {
        eprintln!(
            "{{\"event\":\"skill_print\",\"timestamp\":\"{}\",\"message\":{}}}",
            Utc::now().to_rfc3339(),
            serde_json::to_string(text).unwrap_or_else(|_| "\"<encode-error>\"".to_string())
        );
    });

    engine.register_fn("time_now", || Utc::now().to_rfc3339());
    engine.register_fn("log_info", |message: &str| {
        eprintln!(
            "{{\"event\":\"skill_log\",\"level\":\"info\",\"timestamp\":\"{}\",\"message\":{}}}",
            Utc::now().to_rfc3339(),
            serde_json::to_string(message).unwrap_or_else(|_| "\"<encode-error>\"".to_string())
        );
    });

    engine.register_fn(
        "http_get",
        move |url: &str| -> std::result::Result<String, Box<EvalAltResult>> {
            safe_http_request("GET", url, None, http_timeout_secs)
                .map_err(|err| err.to_string().into())
        },
    );

    engine.register_fn(
        "http_post",
        move |url: &str, body: &str| -> std::result::Result<String, Box<EvalAltResult>> {
            safe_http_request("POST", url, Some(body), http_timeout_secs)
                .map_err(|err| err.to_string().into())
        },
    );
}

fn safe_http_request(
    method: &str,
    url: &str,
    body: Option<&str>,
    timeout_secs: u64,
) -> Result<String> {
    validate_url(url)?;

    let mut cmd = Command::new("curl");
    cmd.arg("-sS")
        .arg("--fail-with-body")
        .arg("-m")
        .arg(timeout_secs.to_string())
        .arg("-X")
        .arg(method)
        .arg(url);

    if let Some(body) = body {
        cmd.arg("-H")
            .arg("Content-Type: application/json")
            .arg("-d")
            .arg(body);
    }

    let started = std::time::Instant::now();
    let output = cmd
        .output()
        .with_context(|| format!("failed executing curl for {}", url))?;
    let elapsed =
        Duration::from_millis(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let code = output.status.code().unwrap_or(-1);
        return Err(anyhow!(
            "http {} failed (code={} latency_ms={}): {} {}",
            method,
            code,
            elapsed.as_millis(),
            summarize_text(&stderr),
            summarize_text(&stdout)
        ));
    }

    let body = String::from_utf8(output.stdout).context("http response was not utf8")?;
    Ok(body)
}

fn validate_url(url: &str) -> Result<()> {
    let url = url.trim();
    if url.is_empty() {
        return Err(anyhow!("url is empty"));
    }
    if url.chars().count() > 2048 {
        return Err(anyhow!("url too long"));
    }
    if url.chars().any(char::is_control) || url.chars().any(char::is_whitespace) {
        return Err(anyhow!("url contains invalid characters"));
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(anyhow!("only http/https urls are allowed"));
    }

    let host = extract_host(url).ok_or_else(|| anyhow!("failed parsing url host"))?;
    let blocked = host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case("::1")
        || host.starts_with("127.")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("172.16.")
        || host.ends_with(".local");
    if blocked {
        return Err(anyhow!("url host '{}' is blocked by sandbox policy", host));
    }

    Ok(())
}

fn extract_host(url: &str) -> Option<String> {
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

fn normalize_skill_name(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("skill name is empty"));
    }

    let trimmed = trimmed.strip_suffix(".rhai").unwrap_or(trimmed);
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

fn should_refresh_existing_asset_skill(skill_name: &str, destination: &Path) -> Result<bool> {
    if skill_name != "weather" {
        return Ok(false);
    }

    let script = fs::read_to_string(destination)
        .with_context(|| format!("failed reading existing skill '{}'", destination.display()))?;
    let legacy_signatures = [
        "return location.replace(\" \", \"+\");",
        "return \"London\";",
        "// WEATHER_SKILL_VERSION=1",
    ];
    Ok(legacy_signatures
        .iter()
        .any(|signature| script.contains(signature)))
}

fn is_main_signature_mismatch(error: &EvalAltResult) -> bool {
    let text = error.to_string();
    text.contains("Function not found")
        && (text.contains("main (string)") || text.contains("main (&str)") || text.contains("main"))
}

fn dynamic_to_text(value: Dynamic) -> String {
    if value.is_unit() {
        return String::new();
    }
    if value.is::<String>() {
        return value.cast::<String>();
    }
    value.to_string()
}

fn summarize_text(raw: &str) -> String {
    let cleaned = raw
        .chars()
        .filter(|ch| !ch.is_control() || *ch == '\n' || *ch == '\t')
        .collect::<String>()
        .trim()
        .to_string();
    if cleaned.is_empty() {
        return String::new();
    }
    if cleaned.chars().count() <= 200 {
        return cleaned;
    }
    let prefix = cleaned.chars().take(200).collect::<String>();
    format!("{}...", prefix)
}

#[cfg(test)]
mod tests {
    use super::SkillManager;

    #[test]
    fn run_skill_with_args_works() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = SkillManager::new(dir.path()).expect("manager");
        manager
            .write_skill(
                "echoer",
                r#"
fn main(args) {
    log_info("skill-start");
    return "echo:" + args;
}
"#,
            )
            .expect("write skill");

        let out = manager.run("echoer", "hello").expect("run skill");
        assert_eq!(out, "echo:hello");
    }

    #[test]
    fn dry_run_rejects_syntax_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = SkillManager::new(dir.path()).expect("manager");
        manager
            .write_skill(
                "broken",
                r#"
fn main() {
    let x = ;
}
"#,
            )
            .expect("write skill");

        let err = manager.dry_run("broken").expect_err("must fail");
        assert!(!err.to_string().trim().is_empty());
    }

    #[test]
    fn sandbox_blocks_localhost_http() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = SkillManager::new(dir.path()).expect("manager");
        manager
            .write_skill(
                "blocked_http",
                r#"
fn main() {
    return http_get("http://localhost:8080");
}
"#,
            )
            .expect("write skill");

        let err = manager
            .run("blocked_http", "")
            .expect_err("localhost should be blocked");
        assert!(err.to_string().contains("blocked"));
    }

    #[test]
    fn sync_from_assets_copies_missing_skills() {
        let dir = tempfile::tempdir().expect("tempdir");
        let workspace_skills = dir.path().join("workspace-skills");
        let assets_skills = dir.path().join("assets-skills");
        std::fs::create_dir_all(&assets_skills).expect("create assets dir");
        std::fs::write(
            assets_skills.join("weather.rhai"),
            r#"
fn main() {
    return "weather-ok";
}
"#,
        )
        .expect("write asset weather");

        let manager = SkillManager::new(&workspace_skills).expect("manager");
        let copied = manager
            .sync_from_assets(&assets_skills)
            .expect("sync from assets");
        assert_eq!(copied, 1);

        let out = manager.run("weather", "").expect("run weather");
        assert_eq!(out, "weather-ok");
    }

    #[test]
    fn sync_from_assets_does_not_overwrite_existing_workspace_skill() {
        let dir = tempfile::tempdir().expect("tempdir");
        let workspace_skills = dir.path().join("workspace-skills");
        let assets_skills = dir.path().join("assets-skills");
        std::fs::create_dir_all(&assets_skills).expect("create assets dir");
        std::fs::write(
            assets_skills.join("weather.rhai"),
            r#"
fn main() {
    return "from-assets";
}
"#,
        )
        .expect("write asset weather");

        let manager = SkillManager::new(&workspace_skills).expect("manager");
        manager
            .write_skill(
                "weather",
                r#"
fn main() {
    return "from-workspace";
}
"#,
            )
            .expect("write workspace weather");

        let copied = manager
            .sync_from_assets(&assets_skills)
            .expect("sync from assets");
        assert_eq!(copied, 0);

        let out = manager.run("weather", "").expect("run weather");
        assert_eq!(out, "from-workspace");
    }

    #[test]
    fn sync_from_assets_refreshes_legacy_weather_skill() {
        let dir = tempfile::tempdir().expect("tempdir");
        let workspace_skills = dir.path().join("workspace-skills");
        let assets_skills = dir.path().join("assets-skills");
        std::fs::create_dir_all(&assets_skills).expect("create assets dir");
        std::fs::write(
            assets_skills.join("weather.rhai"),
            r#"
fn main() {
    return "fixed-weather";
}
"#,
        )
        .expect("write asset weather");

        let manager = SkillManager::new(&workspace_skills).expect("manager");
        manager
            .write_skill(
                "weather",
                r#"
fn normalize_location(raw_location) {
    let location = raw_location;
    return location.replace(" ", "+");
}

fn main() {
    return normalize_location("London");
}
"#,
            )
            .expect("write workspace weather");

        let copied = manager
            .sync_from_assets(&assets_skills)
            .expect("sync from assets");
        assert_eq!(copied, 1);

        let out = manager.run("weather", "").expect("run weather");
        assert_eq!(out, "fixed-weather");
    }
}
