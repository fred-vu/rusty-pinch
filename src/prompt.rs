#[derive(Debug, Clone, PartialEq, Eq)]
struct StaticKey {
    provider: String,
    model: String,
    identity: String,
    capabilities: String,
}

#[derive(Debug, Default)]
pub struct PromptStats {
    pub hits: u64,
    pub misses: u64,
}

#[derive(Debug, Default)]
pub struct PromptBuilder {
    key: Option<StaticKey>,
    cached_static: String,
    stats: PromptStats,
}

impl PromptBuilder {
    pub fn build(
        &mut self,
        provider: &str,
        model: &str,
        identity: &str,
        capabilities: &str,
        session: &str,
        user_input: &str,
    ) -> String {
        let key = StaticKey {
            provider: provider.to_string(),
            model: model.to_string(),
            identity: identity.to_string(),
            capabilities: capabilities.to_string(),
        };

        let static_section = if self.key.as_ref() == Some(&key) {
            self.stats.hits += 1;
            self.cached_static.clone()
        } else {
            self.stats.misses += 1;
            let rendered = format!(
                "# Rusty Pinch\n\n{}\n\nProvider: {}\nModel: {}\n\n## Runtime Capabilities\n{}",
                identity, provider, model, capabilities
            );
            self.key = Some(key);
            self.cached_static = rendered.clone();
            rendered
        };

        format!(
            "{}\n\n## Session\n{}\n\n## User\n{}",
            static_section, session, user_input
        )
    }

    pub fn stats(&self) -> &PromptStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::PromptBuilder;

    #[test]
    fn build_includes_runtime_capabilities_section() {
        let mut builder = PromptBuilder::default();
        let prompt = builder.build(
            "openrouter",
            "openrouter/qwen/qwen3-coder",
            "You are Rusty Pinch.",
            "- tools: model_info,time_now",
            "session-1",
            "hello",
        );

        assert!(prompt.contains("## Runtime Capabilities"));
        assert!(prompt.contains("- tools: model_info,time_now"));
    }

    #[test]
    fn cache_key_changes_when_capabilities_change() {
        let mut builder = PromptBuilder::default();

        let _ = builder.build(
            "openrouter",
            "openrouter/qwen/qwen3-coder",
            "You are Rusty Pinch.",
            "- tools: model_info",
            "session-1",
            "hello",
        );
        let _ = builder.build(
            "openrouter",
            "openrouter/qwen/qwen3-coder",
            "You are Rusty Pinch.",
            "- tools: model_info",
            "session-2",
            "next",
        );
        let _ = builder.build(
            "openrouter",
            "openrouter/qwen/qwen3-coder",
            "You are Rusty Pinch.",
            "- tools: model_info,time_now",
            "session-3",
            "next",
        );

        let stats = builder.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 2);
    }
}
