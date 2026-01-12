//! WAF pattern detection
//!
//! Detects security patterns in configurations that map to WAF agent functionality.

use crate::ir::{
    AgentConfig, AgentSuggestion, AgentType, Confidence, ExtractedWafRule, Filter,
    FilterConfig, RouteMatcher, SentinelConfig, WafAction, WafAgentConfig, WafRuleType,
};
use regex::Regex;
use std::collections::HashMap;

/// Common malicious User-Agent patterns
const SUSPICIOUS_USER_AGENTS: &[&str] = &[
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "zap",
    "burp",
    "havij",
    "acunetix",
    "nessus",
    "grabber",
    "w3af",
    "paros",
    "httperf",
    "loader.io",
    "python-requests",  // When explicitly blocked
    "curl/",            // When explicitly blocked
    "wget/",            // When explicitly blocked
];

/// Common path traversal patterns
const PATH_TRAVERSAL_PATTERNS: &[&str] = &[
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e/",
    r"..%2f",
    r"%2e%2e%5c",
];

/// WAF pattern detector
pub struct WafDetector {
    sql_injection_patterns: Vec<Regex>,
    xss_patterns: Vec<Regex>,
    path_traversal_patterns: Vec<Regex>,
    command_injection_patterns: Vec<Regex>,
}

impl WafDetector {
    pub fn new() -> Self {
        Self {
            sql_injection_patterns: vec![
                // Basic SQL keywords
                Regex::new(r"(?i)union\s+(all\s+)?select").unwrap(),
                Regex::new(r"(?i)select\s+.+\s+from\s+").unwrap(),
                Regex::new(r"(?i)insert\s+into\s+").unwrap(),
                Regex::new(r"(?i)update\s+.+\s+set\s+").unwrap(),
                Regex::new(r"(?i)delete\s+from\s+").unwrap(),
                Regex::new(r"(?i)drop\s+(table|database)\s+").unwrap(),
                // SQL injection techniques
                Regex::new(r"(?i)'\s*(or|and)\s+['\d]").unwrap(),
                Regex::new(r"(?i)'\s*;\s*(drop|delete|insert|update)").unwrap(),
                Regex::new(r"(?i)--\s*$").unwrap(),
                Regex::new(r"(?i)/\*.*\*/").unwrap(),
                // Function-based injection
                Regex::new(r"(?i)(sleep|benchmark|load_file|outfile)\s*\(").unwrap(),
            ],
            xss_patterns: vec![
                // Script tags
                Regex::new(r"(?i)<\s*script").unwrap(),
                Regex::new(r"(?i)</\s*script").unwrap(),
                // Event handlers
                Regex::new(r"(?i)\s+on\w+\s*=").unwrap(),
                // JavaScript protocols
                Regex::new(r"(?i)javascript\s*:").unwrap(),
                Regex::new(r"(?i)vbscript\s*:").unwrap(),
                Regex::new(r"(?i)data\s*:\s*text/html").unwrap(),
                // DOM manipulation
                Regex::new(r"(?i)document\.(cookie|write|location)").unwrap(),
                Regex::new(r"(?i)window\.(location|open)").unwrap(),
                // SVG/embedded content
                Regex::new(r"(?i)<\s*(svg|iframe|object|embed|img)\s+").unwrap(),
            ],
            path_traversal_patterns: PATH_TRAVERSAL_PATTERNS
                .iter()
                .map(|p| Regex::new(p).unwrap())
                .collect(),
            command_injection_patterns: vec![
                // Shell metacharacters
                Regex::new(r"[;&|`$]").unwrap(),
                Regex::new(r"\$\([^)]+\)").unwrap(),
                Regex::new(r"`[^`]+`").unwrap(),
                // Common commands
                Regex::new(r"(?i)(;|\|)\s*(cat|ls|id|whoami|passwd|shadow)").unwrap(),
                Regex::new(r"(?i)/bin/(sh|bash|csh|ksh)").unwrap(),
                Regex::new(r"(?i)cmd\.exe").unwrap(),
            ],
        }
    }

    /// Detect WAF-related patterns in configuration
    pub fn detect(&self, config: &SentinelConfig) -> Vec<AgentSuggestion> {
        let mut suggestions = Vec::new();
        let mut extracted_rules = Vec::new();
        let mut detection_reasons = Vec::new();

        // 1. Check for IP-based filtering in routes
        self.detect_ip_rules(config, &mut extracted_rules, &mut detection_reasons);

        // 2. Check for User-Agent blocking
        self.detect_user_agent_rules(config, &mut extracted_rules, &mut detection_reasons);

        // 3. Check for header-based security rules
        self.detect_header_security(config, &mut extracted_rules, &mut detection_reasons);

        // 4. Check for path restrictions (potential path traversal protection)
        self.detect_path_restrictions(config, &mut extracted_rules, &mut detection_reasons);

        // 5. Check filters for security-related configurations
        self.detect_security_filters(config, &mut extracted_rules, &mut detection_reasons);

        // If we found any WAF-like patterns, suggest WAF agent
        if !extracted_rules.is_empty() {
            let confidence = self.calculate_confidence(&extracted_rules);

            suggestions.push(AgentSuggestion {
                agent_type: AgentType::Waf,
                confidence,
                reason: if detection_reasons.len() == 1 {
                    detection_reasons[0].clone()
                } else {
                    format!(
                        "Found {} security patterns: {}",
                        extracted_rules.len(),
                        detection_reasons.join("; ")
                    )
                },
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

    /// Detect IP-based filtering rules
    fn detect_ip_rules(
        &self,
        config: &SentinelConfig,
        rules: &mut Vec<ExtractedWafRule>,
        reasons: &mut Vec<String>,
    ) {
        let mut ip_rule_count = 0;

        for route in &config.routes {
            for matcher in &route.matchers {
                if let RouteMatcher::SourceIp(ip_match) = matcher {
                    let rule_type = if ip_match.allow {
                        WafRuleType::IpWhitelist
                    } else {
                        WafRuleType::IpBlacklist
                    };

                    rules.push(ExtractedWafRule {
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
                    ip_rule_count += 1;
                }
            }
        }

        if ip_rule_count > 0 {
            reasons.push(format!("{} IP filtering rule(s)", ip_rule_count));
        }
    }

    /// Detect User-Agent blocking patterns
    fn detect_user_agent_rules(
        &self,
        config: &SentinelConfig,
        rules: &mut Vec<ExtractedWafRule>,
        reasons: &mut Vec<String>,
    ) {
        let mut ua_blocks = 0;

        for route in &config.routes {
            for matcher in &route.matchers {
                if let RouteMatcher::Header(header) = matcher {
                    if header.name.to_lowercase() == "user-agent" {
                        // Check if this is blocking suspicious agents
                        let pattern_lower = header.pattern.to_lowercase();
                        let is_suspicious = SUSPICIOUS_USER_AGENTS
                            .iter()
                            .any(|ua| pattern_lower.contains(*ua));

                        if is_suspicious || header.pattern.contains('!') || header.pattern.starts_with('^') {
                            rules.push(ExtractedWafRule {
                                rule_type: WafRuleType::UserAgent,
                                pattern: header.pattern.clone(),
                                action: WafAction::Block,
                                description: Some(format!(
                                    "User-Agent filter from route '{}'",
                                    route.name
                                )),
                            });
                            ua_blocks += 1;
                        }
                    }
                }
            }
        }

        if ua_blocks > 0 {
            reasons.push(format!("{} User-Agent blocking rule(s)", ua_blocks));
        }
    }

    /// Detect header-based security rules
    fn detect_header_security(
        &self,
        config: &SentinelConfig,
        rules: &mut Vec<ExtractedWafRule>,
        reasons: &mut Vec<String>,
    ) {
        let mut header_rules = 0;

        for route in &config.routes {
            for matcher in &route.matchers {
                if let RouteMatcher::Header(header) = matcher {
                    let name_lower = header.name.to_lowercase();

                    // Detect Referer validation
                    if name_lower == "referer" || name_lower == "origin" {
                        rules.push(ExtractedWafRule {
                            rule_type: WafRuleType::Referer,
                            pattern: header.pattern.clone(),
                            action: WafAction::Block,
                            description: Some(format!(
                                "{} validation from route '{}'",
                                header.name, route.name
                            )),
                        });
                        header_rules += 1;
                    }

                    // Detect Content-Type enforcement
                    if name_lower == "content-type" && header.pattern.contains("!") {
                        rules.push(ExtractedWafRule {
                            rule_type: WafRuleType::Custom("content-type-filter".into()),
                            pattern: header.pattern.clone(),
                            action: WafAction::Block,
                            description: Some(format!(
                                "Content-Type enforcement from route '{}'",
                                route.name
                            )),
                        });
                        header_rules += 1;
                    }
                }
            }
        }

        if header_rules > 0 {
            reasons.push(format!("{} header security rule(s)", header_rules));
        }
    }

    /// Detect path-based restrictions
    fn detect_path_restrictions(
        &self,
        config: &SentinelConfig,
        rules: &mut Vec<ExtractedWafRule>,
        reasons: &mut Vec<String>,
    ) {
        let mut path_rules = 0;

        // Look for common security-related path blocks
        let sensitive_paths = [
            r"/\.git",
            r"/\.env",
            r"/\.htaccess",
            r"/\.htpasswd",
            r"/wp-admin",
            r"/wp-config",
            r"/phpMyAdmin",
            r"/admin",
            r"/backup",
            r"/\.svn",
            r"/\.hg",
        ];

        for route in &config.routes {
            for matcher in &route.matchers {
                if let RouteMatcher::Path(path_match) = matcher {
                    // Check if blocking sensitive paths
                    let pattern = path_match.pattern.to_lowercase();
                    let is_sensitive = sensitive_paths
                        .iter()
                        .any(|p| pattern.contains(&p.to_lowercase()));

                    // Check for path traversal patterns
                    let has_traversal_pattern = self
                        .path_traversal_patterns
                        .iter()
                        .any(|re| re.is_match(&path_match.pattern));

                    if is_sensitive || has_traversal_pattern {
                        rules.push(ExtractedWafRule {
                            rule_type: if has_traversal_pattern {
                                WafRuleType::PathTraversal
                            } else {
                                WafRuleType::Custom("sensitive-path".into())
                            },
                            pattern: path_match.pattern.clone(),
                            action: WafAction::Block,
                            description: Some(format!(
                                "Path restriction from route '{}'",
                                route.name
                            )),
                        });
                        path_rules += 1;
                    }
                }
            }
        }

        if path_rules > 0 {
            reasons.push(format!("{} path security rule(s)", path_rules));
        }
    }

    /// Detect security-related filter configurations
    fn detect_security_filters(
        &self,
        config: &SentinelConfig,
        rules: &mut Vec<ExtractedWafRule>,
        reasons: &mut Vec<String>,
    ) {
        let mut security_header_count = 0;

        for filter in config.filters.values() {
            if let FilterConfig::Headers(headers) = &filter.config {
                // Check for security headers being set
                for header_op in &headers.response_add {
                    let name_lower = header_op.name.to_lowercase();

                    if matches!(
                        name_lower.as_str(),
                        "x-content-type-options"
                            | "x-frame-options"
                            | "x-xss-protection"
                            | "strict-transport-security"
                            | "content-security-policy"
                            | "referrer-policy"
                            | "permissions-policy"
                    ) {
                        security_header_count += 1;
                    }
                }

                // Check for Server header being removed (security practice)
                if headers.response_remove.iter().any(|h| h.to_lowercase() == "server") {
                    security_header_count += 1;
                }
            }
        }

        if security_header_count >= 3 {
            // Only mention if there are multiple security headers (indicates intentional hardening)
            reasons.push(format!(
                "{} security header configurations",
                security_header_count
            ));
        }
    }

    /// Calculate confidence based on number and type of rules
    fn calculate_confidence(&self, rules: &[ExtractedWafRule]) -> Confidence {
        let mut score = 0;

        for rule in rules {
            score += match &rule.rule_type {
                WafRuleType::IpBlacklist | WafRuleType::IpWhitelist => 2,
                WafRuleType::SqlInjection | WafRuleType::Xss => 3,
                WafRuleType::PathTraversal | WafRuleType::CommandInjection => 3,
                WafRuleType::UserAgent => 2,
                WafRuleType::Referer => 1,
                WafRuleType::RequestSize => 1,
                WafRuleType::RateLimit => 1,
                WafRuleType::HeaderInjection => 2,
                WafRuleType::Custom(_) => 1,
            };
        }

        match score {
            0..=2 => Confidence::Low,
            3..=5 => Confidence::Medium,
            _ => Confidence::High,
        }
    }

    /// Check if a string contains SQL injection patterns
    #[allow(dead_code)]
    pub fn contains_sql_injection(&self, input: &str) -> bool {
        self.sql_injection_patterns.iter().any(|re| re.is_match(input))
    }

    /// Check if a string contains XSS patterns
    #[allow(dead_code)]
    pub fn contains_xss(&self, input: &str) -> bool {
        self.xss_patterns.iter().any(|re| re.is_match(input))
    }

    /// Check if a string contains path traversal patterns
    #[allow(dead_code)]
    pub fn contains_path_traversal(&self, input: &str) -> bool {
        self.path_traversal_patterns.iter().any(|re| re.is_match(input))
    }

    /// Check if a string contains command injection patterns
    #[allow(dead_code)]
    pub fn contains_command_injection(&self, input: &str) -> bool {
        self.command_injection_patterns.iter().any(|re| re.is_match(input))
    }
}

impl Default for WafDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_injection_detection() {
        let detector = WafDetector::new();

        // Should detect
        assert!(detector.contains_sql_injection("1' OR '1'='1"));
        assert!(detector.contains_sql_injection("UNION SELECT * FROM users"));
        assert!(detector.contains_sql_injection("'; DROP TABLE users--"));
        assert!(detector.contains_sql_injection("1; DELETE FROM users"));

        // Should not detect
        assert!(!detector.contains_sql_injection("normal search query"));
        assert!(!detector.contains_sql_injection("user@example.com"));
    }

    #[test]
    fn test_xss_detection() {
        let detector = WafDetector::new();

        // Should detect
        assert!(detector.contains_xss("<script>alert('xss')</script>"));
        assert!(detector.contains_xss("<img src=x onerror=alert(1)>"));
        assert!(detector.contains_xss("javascript:alert(1)"));
        assert!(detector.contains_xss("<svg onload=alert(1)>"));

        // Should not detect
        assert!(!detector.contains_xss("normal text content"));
        assert!(!detector.contains_xss("<b>bold text</b>"));
    }

    #[test]
    fn test_path_traversal_detection() {
        let detector = WafDetector::new();

        // Should detect
        assert!(detector.contains_path_traversal("../../../etc/passwd"));
        assert!(detector.contains_path_traversal("..\\..\\windows\\system32"));
        assert!(detector.contains_path_traversal("%2e%2e%2fetc/passwd"));

        // Should not detect
        assert!(!detector.contains_path_traversal("/normal/path/to/file"));
        assert!(!detector.contains_path_traversal("./relative/path"));
    }

    #[test]
    fn test_confidence_calculation() {
        let detector = WafDetector::new();

        // Single low-value rule = Low confidence
        let low_rules = vec![ExtractedWafRule {
            rule_type: WafRuleType::Referer,
            pattern: "*.example.com".into(),
            action: WafAction::Block,
            description: None,
        }];
        assert_eq!(detector.calculate_confidence(&low_rules), Confidence::Low);

        // Multiple rules = Higher confidence
        let high_rules = vec![
            ExtractedWafRule {
                rule_type: WafRuleType::IpBlacklist,
                pattern: "1.2.3.4".into(),
                action: WafAction::Block,
                description: None,
            },
            ExtractedWafRule {
                rule_type: WafRuleType::SqlInjection,
                pattern: "union select".into(),
                action: WafAction::Block,
                description: None,
            },
            ExtractedWafRule {
                rule_type: WafRuleType::PathTraversal,
                pattern: "../".into(),
                action: WafAction::Block,
                description: None,
            },
        ];
        assert_eq!(detector.calculate_confidence(&high_rules), Confidence::High);
    }
}
