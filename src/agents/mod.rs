//! Agent detection system
//!
//! Detects patterns in converted configurations that could benefit
//! from Sentinel's agent system (WAF, Auth, RateLimit).

mod auth;
mod ratelimit;
mod waf;

use crate::ir::{Agent, AgentConfig, AgentDetection, AgentType, Confidence, Diagnostics, SentinelConfig};
use crate::AgentMode;

pub use auth::AuthDetector;
pub use ratelimit::RateLimitDetector;
pub use waf::WafDetector;

/// Central agent detection orchestrator
pub struct AgentDetector {
    waf_detector: WafDetector,
    auth_detector: AuthDetector,
    ratelimit_detector: RateLimitDetector,
}

impl AgentDetector {
    pub fn new() -> Self {
        Self {
            waf_detector: WafDetector::new(),
            auth_detector: AuthDetector::new(),
            ratelimit_detector: RateLimitDetector::new(),
        }
    }

    /// Analyze IR and detect/suggest agents
    pub fn detect(
        &self,
        config: &mut SentinelConfig,
        diagnostics: &mut Diagnostics,
        mode: AgentMode,
    ) {
        // Collect all suggestions (including any already in diagnostics from parsing)
        let mut all_suggestions = std::mem::take(&mut diagnostics.agent_suggestions);

        // Run detectors on the converted config
        all_suggestions.extend(self.waf_detector.detect(config));
        all_suggestions.extend(self.auth_detector.detect(config));
        all_suggestions.extend(self.ratelimit_detector.detect(config));

        // Process suggestions based on mode
        match mode {
            AgentMode::Auto => {
                // Convert high-confidence suggestions to actual agents
                for suggestion in all_suggestions {
                    match suggestion.confidence {
                        Confidence::High => {
                            if let Some(agent) = suggestion_to_agent(&suggestion) {
                                // Check if agent already exists
                                if !config.agents.iter().any(|a| a.name == agent.name) {
                                    config.agents.push(agent);
                                }
                            }
                        }
                        Confidence::Medium | Confidence::Low => {
                            // Keep as suggestion
                            diagnostics.agent_suggestions.push(suggestion);
                        }
                    }
                }
            }
            AgentMode::Suggest => {
                // All stay as suggestions
                diagnostics.agent_suggestions = all_suggestions;
            }
            AgentMode::None => {
                // Discard all suggestions
            }
        }
    }
}

impl Default for AgentDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a suggestion to an actual agent
fn suggestion_to_agent(suggestion: &crate::ir::AgentSuggestion) -> Option<Agent> {
    let name = match suggestion.agent_type {
        AgentType::Waf => "waf-agent".to_string(),
        AgentType::Auth => "auth-agent".to_string(),
        AgentType::RateLimit => "ratelimit-agent".to_string(),
        AgentType::Custom => return None,
    };

    let config = suggestion.extracted_config.clone().unwrap_or_else(|| {
        match suggestion.agent_type {
            AgentType::Waf => AgentConfig::Waf(crate::ir::WafAgentConfig {
                socket_path: "/run/sentinel/waf.sock".into(),
                ..Default::default()
            }),
            AgentType::Auth => AgentConfig::Auth(crate::ir::AuthAgentConfig::default()),
            AgentType::RateLimit => AgentConfig::RateLimit(crate::ir::RateLimitAgentConfig::default()),
            AgentType::Custom => AgentConfig::Custom(crate::ir::CustomAgentConfig::default()),
        }
    });

    Some(Agent {
        name,
        agent_type: suggestion.agent_type,
        config,
        routes: suggestion.routes.clone(),
        detection: AgentDetection::Inferred {
            confidence: suggestion.confidence,
            patterns_matched: vec![suggestion.reason.clone()],
        },
        source: suggestion.source_locations.first().cloned(),
    })
}
