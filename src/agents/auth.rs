//! Auth pattern detection

use crate::ir::{
    AgentConfig, AgentSuggestion, AgentType, AuthAgentConfig, AuthType, AuthTypeConfig,
    Confidence, HeaderMatch, RouteMatcher, SentinelConfig,
};
use std::collections::HashMap;

/// Auth pattern detector
pub struct AuthDetector;

impl AuthDetector {
    pub fn new() -> Self {
        Self
    }

    /// Detect auth-related patterns in configuration
    pub fn detect(&self, config: &SentinelConfig) -> Vec<AgentSuggestion> {
        let mut suggestions = Vec::new();
        let mut auth_routes: HashMap<AuthType, Vec<String>> = HashMap::new();

        // Check route metadata for auth hints
        for route in &config.routes {
            if route.metadata.requires_auth {
                auth_routes
                    .entry(AuthType::Custom)
                    .or_default()
                    .push(route.name.clone());
            }

            // Check for Authorization header matching
            for matcher in &route.matchers {
                if let RouteMatcher::Header(header_match) = matcher {
                    if header_match.name.eq_ignore_ascii_case("authorization") {
                        let auth_type = detect_auth_type_from_pattern(&header_match.pattern);
                        auth_routes
                            .entry(auth_type)
                            .or_default()
                            .push(route.name.clone());
                    }

                    // Check for API key headers
                    if header_match.name.eq_ignore_ascii_case("x-api-key")
                        || header_match.name.eq_ignore_ascii_case("api-key")
                    {
                        auth_routes
                            .entry(AuthType::ApiKey)
                            .or_default()
                            .push(route.name.clone());
                    }
                }
            }
        }

        // Create suggestions for each auth type found
        for (auth_type, routes) in auth_routes {
            if routes.is_empty() {
                continue;
            }

            suggestions.push(AgentSuggestion {
                agent_type: AgentType::Auth,
                confidence: Confidence::High,
                reason: format!(
                    "{:?} authentication detected on {} route(s)",
                    auth_type,
                    routes.len()
                ),
                routes,
                extracted_config: Some(AgentConfig::Auth(AuthAgentConfig {
                    socket_path: "/run/sentinel/auth.sock".into(),
                    auth_type,
                    type_config: match auth_type {
                        AuthType::Basic => AuthTypeConfig::Basic {
                            realm: None,
                            htpasswd_path: None,
                        },
                        AuthType::Jwt => AuthTypeConfig::Jwt {
                            issuer: None,
                            audience: None,
                            jwks_url: None,
                        },
                        AuthType::ApiKey => AuthTypeConfig::ApiKey {
                            header: Some("X-API-Key".to_string()),
                            query_param: None,
                        },
                        _ => AuthTypeConfig::Unknown,
                    },
                    ..Default::default()
                })),
                ..Default::default()
            });
        }

        suggestions
    }
}

impl Default for AuthDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Detect auth type from Authorization header pattern
fn detect_auth_type_from_pattern(pattern: &str) -> AuthType {
    let pattern_lower = pattern.to_lowercase();
    if pattern_lower.contains("bearer") {
        AuthType::Jwt
    } else if pattern_lower.contains("basic") {
        AuthType::Basic
    } else {
        AuthType::Custom
    }
}
