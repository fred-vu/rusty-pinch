use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
pub struct SessionStore {
    root: PathBuf,
}

impl SessionStore {
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)
            .with_context(|| format!("failed to create session root {}", root.display()))?;
        Ok(Self { root })
    }

    pub fn append_message(&self, session_id: &str, role: &str, content: &str) -> Result<()> {
        let message = Message {
            role: role.to_string(),
            content: content.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        };

        let encoded =
            serde_json::to_string(&message).context("failed to encode session message")?;
        let path = self.session_file(session_id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create session dir {}", parent.display()))?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("failed to open session file {}", path.display()))?;

        writeln!(file, "{}", encoded)
            .with_context(|| format!("failed to append session file {}", path.display()))?;
        Ok(())
    }

    pub fn load_history(&self, session_id: &str) -> Result<Vec<Message>> {
        let path = self.session_file(session_id);
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .with_context(|| format!("failed to open session file {}", path.display()))?;

        let reader = BufReader::new(file);
        let mut history = Vec::new();

        for line in reader.lines() {
            let line = line.with_context(|| format!("failed to read {}", path.display()))?;
            if line.trim().is_empty() {
                continue;
            }
            let message: Message = serde_json::from_str(&line)
                .with_context(|| format!("failed to decode session entry in {}", path.display()))?;
            history.push(message);
        }

        Ok(history)
    }

    fn session_file(&self, session_id: &str) -> PathBuf {
        let safe_session = session_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>();
        self.root.join(format!("{}.jsonl", safe_session))
    }
}
