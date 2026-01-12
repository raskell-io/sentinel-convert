//! WAF pattern detection

use crate::ir::{
    AgentSuggestion, AgentType, Confidence, IpMatch, RouteMatcher, SentinelConfig,
    WafAction, WafRuleType, ExtractedWafRule, AgentConfig, WafAgentConfig,
};
use regex::Regex;

/// WAF pattern detector
pub struct WafDetector {
    sql_injection_patterns: Vec<Regex>,
    xss_patterns: Vec<Regex>,
}

impl WafDetector {
    pub fn new() -> Self {
        Self {
            sql_injection_patterns: vec![
                Regex::new(r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into)").unwrap(),
                Regex::new(r"(?i)(update\s+.*\s+set|delete\s+from)").unwrap(),
            ],
            xss_patterns: vec![
                Regex::new(r"(?i)(<script|javascript:|on\w+\s*=)").unwrap(),
            ],
        }
    }

    /// Detect WAF-related patterns in configuration
    pub fn detect(&self, config: &SentinelConfig) -> Vec<AgentSuggestion> {
        let mut suggestions = Vec::new();
        let mut extracted_rules = Vec::new();

        // Check for IP-based filtering in routes
        for route in &config.routes {
            for matcher in &route.matchers {
                if let RouteMatcher::SourceIp(ip_match) = matcher {
                    let rule_type = if ip_match.allow {
                        WafRuleType::IpWhitelist
                    } else {
                        WafRuleType::IpBlacklist
                    };

                    extracted_rules.push(ExtractedWafRule {
                        rule_type,
                        pattern: ip_match.cidrs.join(","),
                        action: if ip_match.allow {
                            WafAction::Allow
                        } else {
                            WafAction::Block
                        },
                        description: Some(format!(
                            "IP {} from route '{}'",
                            if ip_match.allow { "whitelist" } else { "blacklist" },
                            route.name
                        )),
                    });
                }
            }
        }

        // If we found IP rules, suggest WAF agent
        if !extracted_rules.is_empty() {
            suggestions.push(AgentSuggestion {
                agent_type: AgentType::Waf,
                confidence: if extracted_rules.len() > 3 {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                reason: format!(
                    "Found {} IP filtering rules that could be handled by WAF agent",
                    extracted_rules.len()
                ),
                extracted_config: Some(AgentConfig::Waf(WafAgentConfig {
                    socket_path: "/run/sentinel/waf.sock".into(),
                    extracted_rules,
                    ..Default::default()
                })),
                ..Default::default()
            });
        }

        suggestions
    }
}

impl Default for WafDetector {
    fn default() -> Self {
        Self::new()
    }
}
