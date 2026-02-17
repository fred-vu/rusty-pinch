use std::collections::HashSet;
use std::net::TcpStream;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json::json;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{connect, Message};

use crate::app::RustyPinchApp;
use crate::config::{Settings, TelegramChannelSettings};

const TELEGRAM_MAX_MESSAGE_CHARS: usize = 3500;

#[derive(Debug, Clone, Default)]
pub struct ChannelRunOptions {
    pub max_messages: Option<usize>,
    pub shutdown: Option<Arc<AtomicBool>>,
}

impl ChannelRunOptions {
    pub fn should_stop(&self) -> bool {
        self.shutdown
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
    }
}

pub fn run_telegram_polling(
    app: &mut RustyPinchApp,
    settings: &Settings,
    options: &ChannelRunOptions,
) -> Result<()> {
    let cfg = &settings.channels.telegram;
    if !cfg.enabled {
        return Err(anyhow!(
            "telegram channel is disabled; set RUSTY_PINCH_CHANNELS_TELEGRAM_ENABLED=true"
        ));
    }

    let token = cfg.token.as_ref().ok_or_else(|| {
        anyhow!("RUSTY_PINCH_CHANNELS_TELEGRAM_TOKEN is required when telegram channel is enabled")
    })?;

    let allow_list = AllowList::new(&cfg.allow_from);
    let mut offset: i64 = 0;
    let mut progress = ChannelProgress::default();

    eprintln!(
        "{}",
        json!({
            "event": "channel_start",
            "channel": "telegram",
            "poll_timeout_secs": cfg.poll_timeout_secs,
            "poll_interval_ms": cfg.poll_interval_ms,
            "allow_from_count": cfg.allow_from.len(),
            "max_messages": options.max_messages,
        })
    );

    loop {
        if options.should_stop() {
            log_channel_stop("telegram", "signal");
            return Ok(());
        }

        match telegram_get_updates(token, cfg, offset) {
            Ok(updates) => {
                if updates.is_empty() {
                    thread::sleep(Duration::from_millis(cfg.poll_interval_ms));
                    continue;
                }

                for update in updates {
                    offset = offset.max(update.update_id + 1);

                    let Some(message) = update.message.or(update.edited_message) else {
                        continue;
                    };

                    if message.from.as_ref().is_some_and(|sender| sender.is_bot) {
                        continue;
                    }

                    let chat_id = message.chat.id.to_string();
                    let sender_id = message
                        .from
                        .as_ref()
                        .map(|sender| sender.id.to_string())
                        .unwrap_or_else(|| chat_id.clone());

                    if !allow_list.permits(&sender_id, &chat_id) {
                        continue;
                    }

                    let Some(input) = pick_text_content(&message) else {
                        continue;
                    };

                    let session_id = format!("telegram:{}", chat_id);
                    let response = match app.process_turn(&session_id, &input) {
                        Ok(output) => output,
                        Err(err) => format_runtime_error(&err),
                    };

                    if let Err(err) = telegram_send_message(token, cfg, &chat_id, &response) {
                        eprintln!(
                            "{}",
                            json!({
                                "event": "channel_send_error",
                                "channel": "telegram",
                                "chat_id": chat_id,
                                "error": err.to_string(),
                            })
                        );
                    }

                    if progress.on_processed(options) {
                        log_channel_stop("telegram", "max_messages");
                        return Ok(());
                    }
                }
            }
            Err(err) => {
                eprintln!(
                    "{}",
                    json!({
                        "event": "channel_poll_error",
                        "channel": "telegram",
                        "error": err.to_string(),
                    })
                );
                thread::sleep(Duration::from_millis(cfg.poll_interval_ms.max(500)));
            }
        }
    }
}

pub fn run_whatsapp_bridge(
    app: &mut RustyPinchApp,
    settings: &Settings,
    options: &ChannelRunOptions,
) -> Result<()> {
    let cfg = &settings.channels.whatsapp;
    if !cfg.enabled {
        return Err(anyhow!(
            "whatsapp channel is disabled; set RUSTY_PINCH_CHANNELS_WHATSAPP_ENABLED=true"
        ));
    }

    let bridge_url = cfg.bridge_url.as_ref().ok_or_else(|| {
        anyhow!(
            "RUSTY_PINCH_CHANNELS_WHATSAPP_BRIDGE_URL is required when whatsapp channel is enabled"
        )
    })?;

    let allow_list = AllowList::new(&cfg.allow_from);
    let mut progress = ChannelProgress::default();

    eprintln!(
        "{}",
        json!({
            "event": "channel_start",
            "channel": "whatsapp",
            "bridge_url": bridge_url,
            "reconnect_ms": cfg.reconnect_ms,
            "allow_from_count": cfg.allow_from.len(),
            "max_messages": options.max_messages,
        })
    );

    loop {
        if options.should_stop() {
            log_channel_stop("whatsapp", "signal");
            return Ok(());
        }

        match connect(bridge_url.as_str()) {
            Ok((mut socket, _)) => {
                let _ = set_socket_nonblocking(&mut socket, true);

                eprintln!(
                    "{}",
                    json!({
                        "event": "channel_connected",
                        "channel": "whatsapp",
                    })
                );

                loop {
                    if options.should_stop() {
                        log_channel_stop("whatsapp", "signal");
                        return Ok(());
                    }

                    let frame = match socket.read() {
                        Ok(message) => message,
                        Err(err) => {
                            if is_read_timeout(&err) {
                                thread::sleep(Duration::from_millis(100));
                                continue;
                            }

                            eprintln!(
                                "{}",
                                json!({
                                    "event": "channel_read_error",
                                    "channel": "whatsapp",
                                    "error": err.to_string(),
                                })
                            );
                            break;
                        }
                    };

                    match frame {
                        Message::Text(payload) => match parse_whatsapp_bridge_inbound(&payload) {
                            Ok(Some(inbound)) => {
                                if !allow_list.permits(&inbound.sender_id, &inbound.chat_id) {
                                    continue;
                                }

                                let session_id = format!("whatsapp:{}", inbound.chat_id);
                                let response = match app.process_turn(&session_id, &inbound.content)
                                {
                                    Ok(output) => output,
                                    Err(err) => format_runtime_error(&err),
                                };

                                let outbound = json!({
                                    "type": "message",
                                    "to": inbound.chat_id,
                                    "content": response,
                                })
                                .to_string();

                                if let Err(err) = socket.send(Message::Text(outbound.into())) {
                                    eprintln!(
                                        "{}",
                                        json!({
                                            "event": "channel_send_error",
                                            "channel": "whatsapp",
                                            "error": err.to_string(),
                                        })
                                    );
                                    break;
                                }

                                if progress.on_processed(options) {
                                    log_channel_stop("whatsapp", "max_messages");
                                    return Ok(());
                                }
                            }
                            Ok(None) => {}
                            Err(err) => {
                                eprintln!(
                                    "{}",
                                    json!({
                                        "event": "channel_parse_error",
                                        "channel": "whatsapp",
                                        "error": err.to_string(),
                                    })
                                );
                            }
                        },
                        Message::Ping(payload) => {
                            let _ = socket.send(Message::Pong(payload));
                        }
                        Message::Close(_) => {
                            break;
                        }
                        _ => {}
                    }
                }
            }
            Err(err) => {
                eprintln!(
                    "{}",
                    json!({
                        "event": "channel_connect_error",
                        "channel": "whatsapp",
                        "error": err.to_string(),
                    })
                );
            }
        }

        thread::sleep(Duration::from_millis(cfg.reconnect_ms.max(250)));
    }
}

fn set_socket_nonblocking(
    socket: &mut tungstenite::WebSocket<MaybeTlsStream<TcpStream>>,
    enabled: bool,
) -> Result<()> {
    match socket.get_mut() {
        MaybeTlsStream::Plain(stream) => stream
            .set_nonblocking(enabled)
            .context("failed to set websocket nonblocking mode"),
        _ => Ok(()),
    }
}

fn is_read_timeout(err: &tungstenite::Error) -> bool {
    match err {
        tungstenite::Error::Io(io_err) => matches!(
            io_err.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        _ => false,
    }
}

fn log_channel_stop(channel: &str, reason: &str) {
    eprintln!(
        "{}",
        json!({
            "event": "channel_stop",
            "channel": channel,
            "reason": reason,
        })
    );
}

fn format_runtime_error(err: &anyhow::Error) -> String {
    let message = err.to_string();
    format!("Rusty Pinch error: {}", truncate_for_log(&message, 600))
}

fn pick_text_content(message: &TelegramMessage) -> Option<String> {
    let text = message
        .text
        .as_deref()
        .or(message.caption.as_deref())
        .map(str::trim)?;

    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn telegram_get_updates(
    token: &str,
    cfg: &TelegramChannelSettings,
    offset: i64,
) -> Result<Vec<TelegramUpdate>> {
    let endpoint = format!(
        "https://api.telegram.org/bot{}/getUpdates?timeout={}&offset={}",
        token,
        cfg.poll_timeout_secs.max(1),
        offset
    );

    let timeout_secs = cfg.request_timeout_secs.max(cfg.poll_timeout_secs + 5);
    let output = Command::new("curl")
        .arg("-sS")
        .arg("--fail-with-body")
        .arg("-m")
        .arg(timeout_secs.to_string())
        .arg(endpoint)
        .output()
        .context("failed to execute curl for telegram getUpdates")?;

    if !output.status.success() {
        return Err(anyhow!(
            "telegram getUpdates failed: {}",
            describe_curl_failure(&output)
        ));
    }

    let raw = String::from_utf8(output.stdout).context("telegram getUpdates returned non-utf8")?;
    parse_telegram_updates(&raw)
}

fn telegram_send_message(
    token: &str,
    cfg: &TelegramChannelSettings,
    chat_id: &str,
    text: &str,
) -> Result<()> {
    let endpoint = format!("https://api.telegram.org/bot{}/sendMessage", token);

    for chunk in chunk_telegram_message(text, TELEGRAM_MAX_MESSAGE_CHARS) {
        let body = json!({
            "chat_id": chat_id,
            "text": chunk,
        })
        .to_string();

        let output = Command::new("curl")
            .arg("-sS")
            .arg("--fail-with-body")
            .arg("-m")
            .arg(cfg.request_timeout_secs.max(1).to_string())
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("-d")
            .arg(&body)
            .arg(&endpoint)
            .output()
            .context("failed to execute curl for telegram sendMessage")?;

        if !output.status.success() {
            return Err(anyhow!(
                "telegram sendMessage failed: {}",
                describe_curl_failure(&output)
            ));
        }

        let raw = String::from_utf8(output.stdout)
            .context("telegram sendMessage returned non-utf8 response")?;
        parse_telegram_api_ack(&raw)?;
    }

    Ok(())
}

fn parse_telegram_updates(raw: &str) -> Result<Vec<TelegramUpdate>> {
    let payload: TelegramUpdatesResponse =
        serde_json::from_str(raw).context("failed to decode telegram getUpdates payload")?;

    if !payload.ok {
        return Err(anyhow!(
            "telegram getUpdates returned error: {}",
            payload
                .description
                .unwrap_or_else(|| "unknown telegram error".to_string())
        ));
    }

    Ok(payload.result)
}

fn parse_telegram_api_ack(raw: &str) -> Result<()> {
    let payload: TelegramApiAck =
        serde_json::from_str(raw).context("failed to decode telegram API response")?;

    if payload.ok {
        return Ok(());
    }

    Err(anyhow!(
        "telegram API returned error: {}",
        payload
            .description
            .unwrap_or_else(|| "unknown telegram error".to_string())
    ))
}

fn parse_whatsapp_bridge_inbound(raw: &str) -> Result<Option<WhatsAppInbound>> {
    let payload: WhatsAppBridgeInbound =
        serde_json::from_str(raw).context("failed to decode whatsapp bridge payload")?;

    if payload.kind != "message" {
        return Ok(None);
    }

    let sender_id = payload
        .from
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("whatsapp bridge message is missing 'from'"))?;

    let chat_id = payload
        .chat
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| sender_id.clone());

    let content = payload
        .content
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    let Some(content) = content else {
        return Ok(None);
    };

    Ok(Some(WhatsAppInbound {
        sender_id,
        chat_id,
        content,
    }))
}

fn describe_curl_failure(output: &Output) -> String {
    let code = output
        .status
        .code()
        .map(|value| value.to_string())
        .unwrap_or_else(|| "signal".to_string());
    let stderr = truncate_for_log(&String::from_utf8_lossy(&output.stderr), 300);
    let stdout = truncate_for_log(&String::from_utf8_lossy(&output.stdout), 300);
    format!("code={} stderr={} stdout={}", code, stderr, stdout)
}

fn truncate_for_log(value: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (i, ch) in value.chars().enumerate() {
        if i >= max_chars {
            out.push_str("...");
            break;
        }
        out.push(ch);
    }
    out
}

fn chunk_telegram_message(value: &str, max_chars: usize) -> Vec<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return vec!["(empty response)".to_string()];
    }

    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut count = 0usize;

    for ch in trimmed.chars() {
        if count >= max_chars {
            chunks.push(current);
            current = String::new();
            count = 0;
        }
        current.push(ch);
        count += 1;
    }

    if !current.is_empty() {
        chunks.push(current);
    }

    chunks
}

struct AllowList {
    values: HashSet<String>,
}

impl AllowList {
    fn new(values: &[String]) -> Self {
        let values = values
            .iter()
            .map(|item| item.trim())
            .filter(|item| !item.is_empty())
            .map(ToOwned::to_owned)
            .collect::<HashSet<String>>();
        Self { values }
    }

    fn permits(&self, sender_id: &str, chat_id: &str) -> bool {
        if self.values.is_empty() {
            return true;
        }
        self.values.contains(sender_id) || self.values.contains(chat_id)
    }
}

#[derive(Debug, Default)]
struct ChannelProgress {
    processed_messages: usize,
}

impl ChannelProgress {
    fn on_processed(&mut self, options: &ChannelRunOptions) -> bool {
        self.processed_messages += 1;
        options
            .max_messages
            .is_some_and(|max| self.processed_messages >= max)
    }
}

#[derive(Debug, Deserialize)]
struct TelegramUpdatesResponse {
    ok: bool,
    #[serde(default)]
    result: Vec<TelegramUpdate>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TelegramApiAck {
    ok: bool,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TelegramUpdate {
    update_id: i64,
    #[serde(default)]
    message: Option<TelegramMessage>,
    #[serde(default)]
    edited_message: Option<TelegramMessage>,
}

#[derive(Debug, Deserialize)]
struct TelegramMessage {
    chat: TelegramChat,
    #[serde(default)]
    from: Option<TelegramUser>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    caption: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TelegramChat {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct TelegramUser {
    id: i64,
    #[serde(default)]
    is_bot: bool,
}

#[derive(Debug, Deserialize)]
struct WhatsAppBridgeInbound {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    chat: Option<String>,
    #[serde(default)]
    content: Option<String>,
}

#[derive(Debug)]
struct WhatsAppInbound {
    sender_id: String,
    chat_id: String,
    content: String,
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use super::{
        chunk_telegram_message, parse_telegram_api_ack, parse_telegram_updates,
        parse_whatsapp_bridge_inbound, ChannelProgress, ChannelRunOptions,
    };

    #[test]
    fn parse_telegram_updates_extracts_text() {
        let raw = r#"{
            "ok": true,
            "result": [
                {
                    "update_id": 99,
                    "message": {
                        "chat": {"id": 12345},
                        "from": {"id": 777, "is_bot": false},
                        "text": "hello"
                    }
                }
            ]
        }"#;

        let updates = parse_telegram_updates(raw).expect("parse updates");
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].update_id, 99);
        assert_eq!(
            updates[0].message.as_ref().and_then(|m| m.text.as_deref()),
            Some("hello")
        );
    }

    #[test]
    fn parse_telegram_updates_returns_error_on_failed_ack() {
        let raw = r#"{"ok": false, "description": "unauthorized"}"#;
        let err = parse_telegram_updates(raw).expect_err("must fail");
        assert!(err.to_string().contains("unauthorized"));
    }

    #[test]
    fn parse_telegram_api_ack_accepts_ok_response() {
        parse_telegram_api_ack(r#"{"ok": true}"#).expect("ack should pass");
    }

    #[test]
    fn parse_whatsapp_bridge_message_extracts_fields() {
        let raw = r#"{"type":"message","from":"user-1","chat":"room-9","content":"  ping  "}"#;
        let inbound = parse_whatsapp_bridge_inbound(raw)
            .expect("parse payload")
            .expect("should be message");

        assert_eq!(inbound.sender_id, "user-1");
        assert_eq!(inbound.chat_id, "room-9");
        assert_eq!(inbound.content, "ping");
    }

    #[test]
    fn parse_whatsapp_bridge_message_ignores_non_message() {
        let raw = r#"{"type":"status","content":"connected"}"#;
        let inbound = parse_whatsapp_bridge_inbound(raw).expect("parse payload");
        assert!(inbound.is_none());
    }

    #[test]
    fn telegram_chunking_keeps_message_content() {
        let input = "abcdefghij";
        let chunks = chunk_telegram_message(input, 4);
        assert_eq!(chunks, vec!["abcd", "efgh", "ij"]);
    }

    #[test]
    fn progress_stops_when_max_messages_reached() {
        let options = ChannelRunOptions {
            max_messages: Some(2),
            shutdown: None,
        };
        let mut progress = ChannelProgress::default();

        assert!(!progress.on_processed(&options));
        assert!(progress.on_processed(&options));
    }

    #[test]
    fn run_options_detect_shutdown_signal() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let options = ChannelRunOptions {
            max_messages: None,
            shutdown: Some(Arc::clone(&shutdown)),
        };

        assert!(!options.should_stop());
        shutdown.store(true, Ordering::Relaxed);
        assert!(options.should_stop());
    }
}
