use std::collections::BTreeMap;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use serde_json::json;

use crate::session::SessionStore;
use crate::skills::SkillManager;

type ToolExec = for<'a> fn(&ToolContext<'a>, &str) -> Result<String>;

const MAX_TOOL_NAME_CHARS: usize = 64;
const MAX_TOOL_ARGS_CHARS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub usage: String,
}

pub struct ToolContext<'a> {
    pub session_id: &'a str,
    pub sessions: &'a SessionStore,
    pub provider: &'a str,
    pub model: &'a str,
    pub skills: Option<&'a SkillManager>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInvocation {
    pub name: String,
    pub args: String,
}

struct ToolEntry {
    spec: ToolSpec,
    execute: ToolExec,
}

#[derive(Debug, Clone, Copy)]
pub struct ToolGuardrails {
    pub max_tool_name_chars: usize,
    pub max_tool_args_chars: usize,
}

impl Default for ToolGuardrails {
    fn default() -> Self {
        Self {
            max_tool_name_chars: MAX_TOOL_NAME_CHARS,
            max_tool_args_chars: MAX_TOOL_ARGS_CHARS,
        }
    }
}

pub struct ToolRegistry {
    entries: BTreeMap<String, ToolEntry>,
    guardrails: ToolGuardrails,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            guardrails: ToolGuardrails::default(),
        }
    }
}

impl ToolRegistry {
    pub fn with_defaults() -> Self {
        let mut registry = Self::default();
        registry.register(
            "model_info",
            "Show current runtime provider/model info.",
            "/tool model_info",
            model_info_tool,
        );
        registry.register(
            "session_tail",
            "Show latest messages from current session.",
            "/tool session_tail [count]",
            session_tail_tool,
        );
        registry.register(
            "time_now",
            "Show current UTC timestamp in RFC3339.",
            "/tool time_now",
            time_now_tool,
        );
        registry.register(
            "skill_list",
            "List installed runtime skills.",
            "/tool skill_list",
            skill_list_tool,
        );
        registry.register(
            "skill_run",
            "Run a runtime skill. Args: <skill_name> [skill_args]",
            "/tool skill_run <skill_name> [skill_args]",
            skill_run_tool,
        );
        registry
    }

    pub fn list(&self) -> Vec<ToolSpec> {
        self.entries
            .values()
            .map(|entry| entry.spec.clone())
            .collect()
    }

    pub fn execute(&self, name: &str, ctx: &ToolContext<'_>, args: &str) -> Result<String> {
        let key = validate_tool_name(name, self.guardrails.max_tool_name_chars)?;
        validate_tool_args(args, self.guardrails.max_tool_args_chars)?;

        let entry = self.entries.get(key).ok_or_else(|| {
            let available = self
                .entries
                .keys()
                .map(|v| v.as_str())
                .collect::<Vec<&str>>()
                .join(", ");
            anyhow!("unknown tool '{}'. available: {}", key, available)
        })?;

        (entry.execute)(ctx, args)
            .with_context(|| format!("tool '{}' execution failed", entry.spec.name))
    }

    fn register(&mut self, name: &str, description: &str, usage: &str, execute: ToolExec) {
        let key = name.trim().to_string();
        let entry = ToolEntry {
            spec: ToolSpec {
                name: key.clone(),
                description: description.to_string(),
                usage: usage.to_string(),
            },
            execute,
        };
        self.entries.insert(key, entry);
    }
}

pub fn parse_tool_invocation(input: &str) -> Option<ToolInvocation> {
    let trimmed = input.trim();
    let rest = trimmed.strip_prefix("/tool")?;
    if !rest.is_empty() {
        let first = rest.chars().next()?;
        if !first.is_whitespace() {
            return None;
        }
    }
    let rest = rest.trim_start();

    if rest.is_empty() {
        return Some(ToolInvocation {
            name: String::new(),
            args: String::new(),
        });
    }

    let (name, args) = split_name_and_args(rest);
    Some(ToolInvocation {
        name: name.to_string(),
        args: args.to_string(),
    })
}

fn split_name_and_args(rest: &str) -> (&str, &str) {
    for (idx, ch) in rest.char_indices() {
        if ch.is_whitespace() {
            return (rest[..idx].trim(), rest[idx..].trim());
        }
    }
    (rest.trim(), "")
}

fn model_info_tool(ctx: &ToolContext<'_>, args: &str) -> Result<String> {
    if !args.trim().is_empty() {
        return Err(anyhow!("model_info does not accept arguments"));
    }

    Ok(format!(
        "provider={}\nmodel={}\nsession_id={}",
        ctx.provider, ctx.model, ctx.session_id
    ))
}

fn time_now_tool(_ctx: &ToolContext<'_>, args: &str) -> Result<String> {
    if !args.trim().is_empty() {
        return Err(anyhow!("time_now does not accept arguments"));
    }
    Ok(Utc::now().to_rfc3339())
}

fn session_tail_tool(ctx: &ToolContext<'_>, args: &str) -> Result<String> {
    let count = parse_positive_count(args, 5, 50)?;
    let history = ctx
        .sessions
        .load_history(ctx.session_id)
        .with_context(|| format!("failed loading session '{}'", ctx.session_id))?;

    let start = history.len().saturating_sub(count);
    let slice = &history[start..];

    let payload = json!({
        "session_id": ctx.session_id,
        "total_messages": history.len(),
        "returned_messages": slice.len(),
        "messages": slice
    });

    serde_json::to_string_pretty(&payload).context("failed encoding session_tail output")
}

fn skill_list_tool(ctx: &ToolContext<'_>, args: &str) -> Result<String> {
    if !args.trim().is_empty() {
        return Err(anyhow!("skill_list does not accept arguments"));
    }

    let skills = ctx
        .skills
        .ok_or_else(|| anyhow!("skill runtime is not available in this context"))?
        .list_skills()
        .context("failed listing skills")?;

    let names = skills
        .into_iter()
        .map(|skill| skill.name)
        .collect::<Vec<String>>();

    serde_json::to_string_pretty(&json!({ "skills": names }))
        .context("failed encoding skill_list output")
}

fn skill_run_tool(ctx: &ToolContext<'_>, args: &str) -> Result<String> {
    let (skill_name, skill_args) = split_name_and_args(args.trim());
    if skill_name.is_empty() {
        return Err(anyhow!(
            "skill_run requires skill name. usage: /tool skill_run <skill_name> [skill_args]"
        ));
    }

    let manager = ctx
        .skills
        .ok_or_else(|| anyhow!("skill runtime is not available in this context"))?;
    manager
        .run(skill_name, skill_args)
        .with_context(|| format!("failed running skill '{}'", skill_name))
}

fn parse_positive_count(raw: &str, default_value: usize, max_value: usize) -> Result<usize> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(default_value);
    }
    let value = trimmed
        .parse::<usize>()
        .map_err(|_| anyhow!("count must be a positive integer"))?;
    if value == 0 {
        return Err(anyhow!("count must be > 0"));
    }
    Ok(value.min(max_value))
}

fn validate_tool_name<'a>(name: &'a str, max_chars: usize) -> Result<&'a str> {
    let key = name.trim();
    if key.is_empty() {
        return Err(anyhow!("tool name is empty. usage: /tool <name> [args]"));
    }

    if key.chars().count() > max_chars {
        return Err(anyhow!("tool name too long (max {} characters)", max_chars));
    }

    if !key
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    {
        return Err(anyhow!(
            "invalid tool name '{}'. allowed chars: a-z, 0-9, '_' and '-'",
            key
        ));
    }

    Ok(key)
}

fn validate_tool_args(args: &str, max_chars: usize) -> Result<()> {
    if args.chars().count() > max_chars {
        return Err(anyhow!("tool args too long (max {} characters)", max_chars));
    }

    if args.chars().any(char::is_control) {
        return Err(anyhow!(
            "tool args contain control characters, which are not allowed"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_tool_invocation, ToolContext, ToolRegistry};
    use crate::session::SessionStore;
    use crate::skills::SkillManager;

    #[test]
    fn registry_list_is_deterministic() {
        let names = ToolRegistry::with_defaults()
            .list()
            .into_iter()
            .map(|spec| spec.name)
            .collect::<Vec<String>>();
        assert_eq!(
            names,
            vec![
                "model_info".to_string(),
                "session_tail".to_string(),
                "skill_list".to_string(),
                "skill_run".to_string(),
                "time_now".to_string()
            ]
        );
    }

    #[test]
    fn parse_tool_invocation_parses_name_and_args() {
        let call = parse_tool_invocation("/tool session_tail 7").expect("must parse");
        assert_eq!(call.name, "session_tail");
        assert_eq!(call.args, "7");
    }

    #[test]
    fn parse_tool_invocation_handles_missing_name() {
        let call = parse_tool_invocation("/tool   ").expect("must parse missing name");
        assert!(call.name.is_empty());
    }

    #[test]
    fn parse_tool_invocation_rejects_tool_prefix_collisions() {
        assert!(parse_tool_invocation("/toolbox model_info").is_none());
        assert!(parse_tool_invocation("/toolx").is_none());
    }

    #[test]
    fn execute_rejects_invalid_tool_name_characters() {
        let temp = tempfile::tempdir().expect("tempdir");
        let sessions = SessionStore::new(temp.path()).expect("session store");
        let ctx = ToolContext {
            session_id: "test",
            sessions: &sessions,
            provider: "local",
            model: "test-model",
            skills: None,
        };

        let err = ToolRegistry::with_defaults()
            .execute("model;info", &ctx, "")
            .expect_err("invalid name should fail");
        assert!(
            err.to_string().contains("invalid tool name"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn execute_rejects_control_characters_in_args() {
        let temp = tempfile::tempdir().expect("tempdir");
        let sessions = SessionStore::new(temp.path()).expect("session store");
        let ctx = ToolContext {
            session_id: "test",
            sessions: &sessions,
            provider: "local",
            model: "test-model",
            skills: None,
        };

        let err = ToolRegistry::with_defaults()
            .execute("session_tail", &ctx, "5\n6")
            .expect_err("control char args should fail");
        assert!(
            err.to_string().contains("control characters"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn skill_run_requires_skill_runtime_context() {
        let temp = tempfile::tempdir().expect("tempdir");
        let sessions = SessionStore::new(temp.path()).expect("session store");
        let ctx = ToolContext {
            session_id: "test",
            sessions: &sessions,
            provider: "local",
            model: "test-model",
            skills: None,
        };

        let err = ToolRegistry::with_defaults()
            .execute("skill_run", &ctx, "weather Paris")
            .expect_err("missing skill context should fail");
        let details = format!("{:#}", err);
        assert!(
            details.contains("skill runtime is not available"),
            "unexpected error: {}",
            details
        );
    }

    #[test]
    fn skill_run_executes_skill_when_runtime_is_available() {
        let temp = tempfile::tempdir().expect("tempdir");
        let sessions = SessionStore::new(temp.path()).expect("session store");
        let skills = SkillManager::new(temp.path().join("skills")).expect("skill manager");
        skills
            .write_skill(
                "echoer",
                r#"
fn main(args) {
    if args.len() == 0 { return "empty"; }
    return args;
}
"#,
            )
            .expect("write skill");
        let ctx = ToolContext {
            session_id: "test",
            sessions: &sessions,
            provider: "local",
            model: "test-model",
            skills: Some(&skills),
        };

        let out = ToolRegistry::with_defaults()
            .execute("skill_run", &ctx, "echoer hello")
            .expect("skill run should succeed");
        assert_eq!(out, "hello");
    }
}
