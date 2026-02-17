#[derive(Debug, Clone, PartialEq, Eq)]
struct StaticKey {
    provider: String,
    model: String,
    identity: String,
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
        session: &str,
        user_input: &str,
    ) -> String {
        let key = StaticKey {
            provider: provider.to_string(),
            model: model.to_string(),
            identity: identity.to_string(),
        };

        let static_section = if self.key.as_ref() == Some(&key) {
            self.stats.hits += 1;
            self.cached_static.clone()
        } else {
            self.stats.misses += 1;
            let rendered = format!(
                "# Rusty Pinch\n\n{}\n\nProvider: {}\nModel: {}",
                identity, provider, model
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
