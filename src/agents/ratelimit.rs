//! Rate limit pattern detection

use crate::ir::{
    AgentConfig, AgentSuggestion, AgentType, Confidence, RateLimitAgentConfig, RateLimitKey,
    RateLimitRule, SentinelConfig,
};

/// Rate limit pattern detector
pub struct RateLimitDetector;

impl RateLimitDetector {
    pub fn new() -> Self {
        Self
    }

    /// Detect rate limiting patterns in configuration
    pub fn detect(&self, config: &SentinelConfig) -> Vec<AgentSuggestion> {
        let mut suggestions = Vec::new();
        let mut rules = Vec::new();
        let mut routes_with_limits = Vec::new();

        // Check route metadata for rate limit hints
        for route in &config.routes {
            if let Some(hint) = &route.metadata.rate_limit_hint {
                routes_with_limits.push(route.name.clone());

                rules.push(RateLimitRule {
                    name: format!("{}_limit", route.name),
                    key: hint.key.clone(),
                    rate: hint.requests_per_second.unwrap_or(100),
                    period_ms: 1000,
                    burst: hint.burst,
                });
            }
        }

        // If we found rate limit hints, suggest RateLimit agent
        if !rules.is_empty() {
            suggestions.push(AgentSuggestion {
                agent_type: AgentType::RateLimit,
                confidence: Confidence::High,
                reason: format!(
                    "Rate limiting detected on {} route(s)",
                    routes_with_limits.len()
                ),
                routes: routes_with_limits,
                extracted_config: Some(AgentConfig::RateLimit(RateLimitAgentConfig {
                    socket_path: "/run/sentinel/ratelimit.sock".into(),
                    limits: rules,
                    ..Default::default()
                })),
                ..Default::default()
            });
        }

        suggestions
    }
}

impl Default for RateLimitDetector {
    fn default() -> Self {
        Self::new()
    }
}
