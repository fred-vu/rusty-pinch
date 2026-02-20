use std::fmt::{Display, Formatter};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use tracing::{debug, instrument, warn};

use crate::config::Settings;
use crate::session::Message;

const DEFAULT_SYSTEM_IDENTITY: &str = "You are Rusty Pinch, a pragmatic Rust-first assistant.";

#[derive(Debug, Clone, Copy)]
pub struct ProviderMetrics {
    pub attempts: u32,
    pub latency_ms: u64,
    pub tokens_used: u64,
}

#[derive(Debug, Clone)]
pub struct ProviderResponse {
    pub content: String,
    pub metrics: ProviderMetrics,
}

#[derive(Debug, Clone)]
pub struct ProviderFailure {
    pub metrics: ProviderMetrics,
    pub message: String,
}

impl ProviderFailure {
    fn new(message: impl Into<String>, attempts: u32, latency_ms: u64) -> Self {
        Self {
            metrics: ProviderMetrics {
                attempts,
                latency_ms,
                tokens_used: 0,
            },
            message: message.into(),
        }
    }
}

impl Display for ProviderFailure {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (attempts={}, latency_ms={})",
            self.message, self.metrics.attempts, self.metrics.latency_ms
        )
    }
}

impl std::error::Error for ProviderFailure {}

pub fn chat_completion(
    settings: &Settings,
    history: &[Message],
    session_prompt: &str,
    user_input: &str,
    request_id: &str,
    session_id: &str,
) -> Result<String> {
    let response = chat_completion_with_metrics(
        settings,
        history,
        session_prompt,
        user_input,
        request_id,
        session_id,
    )
    .map_err(|err| anyhow!("{}", err))?;
    Ok(response.content)
}

#[instrument(
    name = "provider.chat_completion",
    skip(settings, history, session_prompt, user_input),
    fields(
        request_id = request_id,
        session_id = session_id,
        provider = %settings.provider,
        model = %settings.model
    )
)]
pub fn chat_completion_with_metrics(
    settings: &Settings,
    history: &[Message],
    session_prompt: &str,
    user_input: &str,
    request_id: &str,
    session_id: &str,
) -> std::result::Result<ProviderResponse, ProviderFailure> {
    let started = Instant::now();

    if matches!(settings.provider.as_str(), "local" | "offline") {
        return Ok(ProviderResponse {
            content: local_fallback_response(settings, history.len(), user_input),
            metrics: ProviderMetrics {
                attempts: 0,
                latency_ms: elapsed_ms(started),
                tokens_used: 0,
            },
        });
    }

    if !is_openai_compatible_provider(&settings.provider) {
        return Err(ProviderFailure::new(
            format!(
                "provider '{}' is not implemented yet in rusty-pinch runtime",
                settings.provider
            ),
            0,
            elapsed_ms(started),
        ));
    }

    let api_key = settings.api_key.as_ref().ok_or_else(|| {
        ProviderFailure::new(
            format!("missing API key for provider '{}'", settings.provider),
            0,
            elapsed_ms(started),
        )
    })?;
    let api_base = settings.api_base.as_ref().ok_or_else(|| {
        ProviderFailure::new(
            format!("missing API base for provider '{}'", settings.provider),
            0,
            elapsed_ms(started),
        )
    })?;

    let payload = build_chat_payload(settings, history, session_prompt, user_input);
    let body = serde_json::to_string(&payload)
        .context("failed to encode chat payload")
        .map_err(|err| ProviderFailure::new(err.to_string(), 0, elapsed_ms(started)))?;
    let endpoint = format!("{}/chat/completions", api_base.trim_end_matches('/'));

    let total_attempts = settings.request_retries + 1;
    let mut last_error: Option<ProviderCallError> = None;

    for attempt in 0..total_attempts {
        let attempt_no = attempt + 1;
        match call_provider_once(settings, api_key, &endpoint, &body) {
            Ok(response) => {
                let elapsed = elapsed_ms(started);
                debug!(
                    attempt = attempt_no,
                    latency_ms = elapsed,
                    tokens_used = response.tokens_used,
                    "provider call succeeded"
                );
                return Ok(ProviderResponse {
                    content: response.content,
                    metrics: ProviderMetrics {
                        attempts: attempt_no,
                        latency_ms: elapsed,
                        tokens_used: response.tokens_used,
                    },
                });
            }
            Err(err) => {
                let is_last_attempt = attempt_no >= total_attempts;
                if err.class == ErrorClass::Transient && !is_last_attempt {
                    let delay_ms = compute_retry_delay_ms(
                        settings.retry_backoff_ms,
                        settings.retry_max_backoff_ms,
                        attempt,
                    );
                    warn!(
                        attempt = attempt_no,
                        total_attempts = total_attempts,
                        delay_ms = delay_ms,
                        error = %err,
                        "provider transient failure, retrying"
                    );
                    last_error = Some(err);
                    thread::sleep(Duration::from_millis(delay_ms));
                    continue;
                }

                return Err(ProviderFailure::new(
                    format!(
                        "provider call failed on attempt {}/{}: {}",
                        attempt_no, total_attempts, err
                    ),
                    attempt_no,
                    elapsed_ms(started),
                ));
            }
        }
    }

    let fallback = last_error
        .map(|e| e.to_string())
        .unwrap_or_else(|| "unknown provider failure".to_string());
    Err(ProviderFailure::new(
        format!(
            "provider call exhausted after {} attempts: {}",
            total_attempts, fallback
        ),
        total_attempts,
        elapsed_ms(started),
    ))
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn is_openai_compatible_provider(provider: &str) -> bool {
    matches!(
        provider,
        "openrouter" | "openai" | "groq" | "vllm" | "compatible"
    )
}

fn local_fallback_response(settings: &Settings, history_count: usize, user_input: &str) -> String {
    format!(
        "[Rusty Pinch:{}:{}] Received '{}'. history={} messages.",
        settings.provider, settings.model, user_input, history_count
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorClass {
    Transient,
    Permanent,
}

#[derive(Debug, Clone)]
struct ProviderCallError {
    class: ErrorClass,
    message: String,
}

struct ProviderCallSuccess {
    content: String,
    tokens_used: u64,
}

impl ProviderCallError {
    fn transient(message: impl Into<String>) -> Self {
        Self {
            class: ErrorClass::Transient,
            message: message.into(),
        }
    }

    fn permanent(message: impl Into<String>) -> Self {
        Self {
            class: ErrorClass::Permanent,
            message: message.into(),
        }
    }
}

impl Display for ProviderCallError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let class = match self.class {
            ErrorClass::Transient => "transient",
            ErrorClass::Permanent => "permanent",
        };
        write!(f, "{} error: {}", class, self.message)
    }
}

fn call_provider_once(
    settings: &Settings,
    api_key: &str,
    endpoint: &str,
    body: &str,
) -> std::result::Result<ProviderCallSuccess, ProviderCallError> {
    let mut command = Command::new("curl");
    command
        .arg("-sS")
        .arg("--fail-with-body")
        .arg("-m")
        .arg(settings.request_timeout_secs.to_string())
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-H")
        .arg(format!("Authorization: Bearer {}", api_key))
        .arg("-d")
        .arg(body)
        .arg(endpoint);

    if settings.provider == "openrouter" {
        command
            .arg("-H")
            .arg("HTTP-Referer: https://rusty-pinch.local")
            .arg("-H")
            .arg("X-Title: Rusty Pinch");
    }

    let output = command
        .output()
        .map_err(|err| ProviderCallError::transient(format!("failed to execute curl: {}", err)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let code = output.status.code();
        return Err(classify_transport_failure(code, &stderr, &stdout));
    }

    let raw = String::from_utf8(output.stdout)
        .map_err(|_| ProviderCallError::permanent("provider returned non-utf8 response"))?;
    parse_chat_response(&raw)
}

fn classify_transport_failure(
    curl_code: Option<i32>,
    stderr: &str,
    stdout: &str,
) -> ProviderCallError {
    let http_status = parse_http_status(stderr).or_else(|| parse_http_status(stdout));
    let body_message = parse_error_message(stdout);
    let body_class = body_message
        .as_ref()
        .map(|msg| classify_provider_error_message(msg));

    let class = match curl_code {
        Some(22) => classify_http_status(http_status).or(body_class),
        Some(code) if is_transient_curl_code(code) => Some(ErrorClass::Transient),
        Some(_) => body_class,
        None => Some(ErrorClass::Transient),
    }
    .unwrap_or(ErrorClass::Permanent);

    let mut details = Vec::new();
    if let Some(code) = curl_code {
        details.push(format!("curl_code={}", code));
    }
    if let Some(status) = http_status {
        details.push(format!("http_status={}", status));
    }
    if let Some(msg) = body_message {
        details.push(format!("provider_error={}", msg));
    }
    if !stderr.trim().is_empty() {
        details.push(format!("stderr={}", stderr.trim()));
    }
    if details.is_empty() {
        details.push("unknown transport failure".to_string());
    }

    let message = details.join("; ");
    match class {
        ErrorClass::Transient => ProviderCallError::transient(message),
        ErrorClass::Permanent => ProviderCallError::permanent(message),
    }
}

fn parse_http_status(text: &str) -> Option<u16> {
    let marker = "returned error:";
    let idx = text.find(marker)?;
    parse_first_u16(&text[idx + marker.len()..])
}

fn parse_first_u16(text: &str) -> Option<u16> {
    let mut start = None;
    let chars: Vec<char> = text.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if c.is_ascii_digit() {
            start = Some(i);
            break;
        }
    }
    let start = start?;
    let mut end = start;
    while end < chars.len() && chars[end].is_ascii_digit() {
        end += 1;
    }
    if end <= start {
        return None;
    }
    text[start..end].parse::<u16>().ok()
}

fn parse_error_message(raw: &str) -> Option<String> {
    let value: Value = serde_json::from_str(raw).ok()?;
    let err = value.get("error")?;
    if let Some(msg) = err.get("message").and_then(Value::as_str) {
        let trimmed = msg.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    err.as_str()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn is_transient_curl_code(code: i32) -> bool {
    matches!(code, 5 | 6 | 7 | 18 | 28 | 35 | 47 | 52 | 55 | 56)
}

fn classify_http_status(status: Option<u16>) -> Option<ErrorClass> {
    let status = status?;
    if matches!(status, 408 | 409 | 425 | 429) || status >= 500 {
        return Some(ErrorClass::Transient);
    }
    if (400..500).contains(&status) {
        return Some(ErrorClass::Permanent);
    }
    None
}

fn classify_provider_error_message(message: &str) -> ErrorClass {
    let normalized = message.to_lowercase();

    if normalized.contains("rate limit")
        || normalized.contains("temporarily")
        || normalized.contains("timeout")
        || normalized.contains("timed out")
        || normalized.contains("try again")
        || normalized.contains("overloaded")
        || normalized.contains("service unavailable")
    {
        return ErrorClass::Transient;
    }

    if normalized.contains("invalid api key")
        || normalized.contains("unauthorized")
        || normalized.contains("forbidden")
        || normalized.contains("insufficient_quota")
        || normalized.contains("invalid_request_error")
        || normalized.contains("model not found")
        || normalized.contains("no such model")
    {
        return ErrorClass::Permanent;
    }

    ErrorClass::Permanent
}

fn compute_retry_delay_ms(base_ms: u64, max_ms: u64, attempt: u32) -> u64 {
    let safe_base = base_ms.max(1);
    let shift = attempt.min(12);
    let factor = 1u64 << shift;
    let candidate = safe_base.saturating_mul(factor);
    candidate.min(max_ms.max(safe_base))
}

fn build_chat_payload(
    settings: &Settings,
    history: &[Message],
    session_prompt: &str,
    user_input: &str,
) -> Value {
    let mut messages = Vec::new();
    messages.push(json!({
        "role": "system",
        "content": format!("{}\n\n{}", DEFAULT_SYSTEM_IDENTITY, session_prompt)
    }));

    for msg in history.iter().rev().take(20).rev() {
        if !matches!(msg.role.as_str(), "user" | "assistant" | "system") {
            continue;
        }
        messages.push(json!({
            "role": msg.role,
            "content": msg.content
        }));
    }

    messages.push(json!({
        "role": "user",
        "content": user_input
    }));

    json!({
        "model": settings.model,
        "messages": messages,
        "temperature": 0.2
    })
}

fn parse_chat_response(raw: &str) -> std::result::Result<ProviderCallSuccess, ProviderCallError> {
    let data: Value = serde_json::from_str(raw)
        .map_err(|_| ProviderCallError::permanent("failed parsing provider response json"))?;

    if let Some(err_obj) = data.get("error") {
        let message = err_obj
            .get("message")
            .and_then(Value::as_str)
            .or_else(|| err_obj.as_str())
            .unwrap_or("unknown error");
        let class = classify_provider_error_message(message);
        return Err(match class {
            ErrorClass::Transient => {
                ProviderCallError::transient(format!("provider returned error: {}", message))
            }
            ErrorClass::Permanent => {
                ProviderCallError::permanent(format!("provider returned error: {}", message))
            }
        });
    }

    let choices = data
        .get("choices")
        .and_then(Value::as_array)
        .ok_or_else(|| ProviderCallError::permanent("provider response missing choices array"))?;
    let first = choices
        .first()
        .ok_or_else(|| ProviderCallError::permanent("provider response has empty choices array"))?;
    let message = first.get("message").ok_or_else(|| {
        ProviderCallError::permanent("provider response missing choices[0].message")
    })?;
    let content = message.get("content").ok_or_else(|| {
        ProviderCallError::permanent("provider response missing choices[0].message.content")
    })?;

    let parsed = extract_text_content(content)
        .ok_or_else(|| ProviderCallError::permanent("provider response content is empty"))?;
    let tokens_used = data
        .get("usage")
        .and_then(|usage| {
            usage
                .get("total_tokens")
                .and_then(Value::as_u64)
                .or_else(|| usage.get("prompt_tokens").and_then(Value::as_u64))
        })
        .unwrap_or(0);

    Ok(ProviderCallSuccess {
        content: parsed,
        tokens_used,
    })
}

fn extract_text_content(content: &Value) -> Option<String> {
    if let Some(text) = content.as_str() {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return None;
        }
        return Some(trimmed.to_string());
    }

    if let Some(parts) = content.as_array() {
        let joined = parts
            .iter()
            .filter_map(|part| {
                part.get("text")
                    .and_then(Value::as_str)
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
            })
            .collect::<Vec<String>>()
            .join("\n");
        if !joined.trim().is_empty() {
            return Some(joined);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{
        classify_provider_error_message, classify_transport_failure, compute_retry_delay_ms,
        extract_text_content, parse_chat_response, ErrorClass,
    };
    use serde_json::json;

    #[test]
    fn parse_chat_response_accepts_string_content() {
        let raw = r#"{
            "choices": [
                {"message": {"content": "hello world"}}
            ]
        }"#;
        let out = parse_chat_response(raw).expect("parse should succeed");
        assert_eq!(out.content, "hello world");
        assert_eq!(out.tokens_used, 0);
    }

    #[test]
    fn parse_chat_response_accepts_array_content() {
        let raw = r#"{
            "choices": [
                {"message": {"content": [{"type":"text","text":"line one"},{"type":"text","text":"line two"}]}}
            ]
        }"#;
        let out = parse_chat_response(raw).expect("parse should succeed");
        assert_eq!(out.content, "line one\nline two");
    }

    #[test]
    fn parse_chat_response_extracts_usage_total_tokens() {
        let raw = r#"{
            "choices": [
                {"message": {"content": "ok"}}
            ],
            "usage": {
                "prompt_tokens": 7,
                "completion_tokens": 5,
                "total_tokens": 12
            }
        }"#;
        let out = parse_chat_response(raw).expect("parse should succeed");
        assert_eq!(out.tokens_used, 12);
    }

    #[test]
    fn extract_text_content_returns_none_for_empty_value() {
        assert_eq!(extract_text_content(&json!("   ")), None);
        assert_eq!(extract_text_content(&json!([])), None);
    }

    #[test]
    fn classify_transport_failure_marks_dns_as_transient() {
        let err = classify_transport_failure(Some(6), "curl: (6) Could not resolve host", "");
        assert_eq!(err.class, ErrorClass::Transient);
    }

    #[test]
    fn classify_transport_failure_marks_http_429_as_transient() {
        let err = classify_transport_failure(
            Some(22),
            "curl: (22) The requested URL returned error: 429",
            "{\"error\":{\"message\":\"rate limit exceeded\"}}",
        );
        assert_eq!(err.class, ErrorClass::Transient);
    }

    #[test]
    fn classify_transport_failure_marks_http_401_as_permanent() {
        let err = classify_transport_failure(
            Some(22),
            "curl: (22) The requested URL returned error: 401",
            "{\"error\":{\"message\":\"invalid api key\"}}",
        );
        assert_eq!(err.class, ErrorClass::Permanent);
    }

    #[test]
    fn classify_provider_error_message_rate_limit_is_transient() {
        let class = classify_provider_error_message("Rate limit exceeded, please try again later");
        assert_eq!(class, ErrorClass::Transient);
    }

    #[test]
    fn compute_retry_delay_caps_at_max() {
        let delay = compute_retry_delay_ms(500, 1200, 4);
        assert_eq!(delay, 1200);
    }
}
