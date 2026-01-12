//! HAProxy configuration parser

use super::mapping::map_haproxy_to_ir;
use super::{Directive, HAProxyConfig, Section, SectionType};
use crate::ir::SourceFormat;
use crate::parsers::{FormatSignature, ParseContext, ParseError, ParseOutput, Parser};
use std::path::Path;

/// HAProxy configuration parser
pub struct HAProxyParser;

impl HAProxyParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse HAProxy config from content
    fn parse_content(content: &str, file: &Path) -> Result<HAProxyConfig, ParseError> {
        let mut config = HAProxyConfig::default();
        let mut current_section: Option<Section> = None;
        let mut line_num = 0;

        for line in content.lines() {
            line_num += 1;
            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Check if this is a section header
            if let Some((section_type, name)) = Self::parse_section_header(trimmed) {
                // Save previous section
                if let Some(section) = current_section.take() {
                    Self::add_section(&mut config, section);
                }

                // Start new section
                current_section = Some(Section {
                    section_type,
                    name,
                    directives: Vec::new(),
                    location: crate::ir::SourceLocation::new(file.to_path_buf(), line_num),
                });
            } else if let Some(ref mut section) = current_section {
                // Parse directive within current section
                if let Some(directive) = Self::parse_directive(trimmed, line_num, file) {
                    section.directives.push(directive);
                }
            }
            // Lines outside sections are ignored (or could be global)
        }

        // Save last section
        if let Some(section) = current_section {
            Self::add_section(&mut config, section);
        }

        Ok(config)
    }

    /// Parse a section header line
    fn parse_section_header(line: &str) -> Option<(SectionType, Option<String>)> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return None;
        }

        let section_type = match parts[0].to_lowercase().as_str() {
            "global" => SectionType::Global,
            "defaults" => SectionType::Defaults,
            "frontend" => SectionType::Frontend,
            "backend" => SectionType::Backend,
            "listen" => SectionType::Listen,
            _ => return None,
        };

        let name = parts.get(1).map(|s| s.to_string());

        Some((section_type, name))
    }

    /// Parse a directive line
    fn parse_directive(line: &str, line_num: usize, file: &Path) -> Option<Directive> {
        // Handle continuation lines (ending with \)
        let line = line.trim_end_matches('\\').trim();

        if line.is_empty() {
            return None;
        }

        // Split into parts, handling quoted strings
        let parts = Self::split_directive(line);
        if parts.is_empty() {
            return None;
        }

        let name = parts[0].clone();
        let args = parts[1..].to_vec();

        Some(Directive::new(name, line_num, file.to_path_buf()).with_args(args))
    }

    /// Split a directive line respecting quotes
    fn split_directive(line: &str) -> Vec<String> {
        let mut parts = Vec::new();
        let mut current = String::new();
        let mut in_quote = false;
        let mut quote_char = '"';

        for c in line.chars() {
            match c {
                '"' | '\'' if !in_quote => {
                    in_quote = true;
                    quote_char = c;
                }
                c if c == quote_char && in_quote => {
                    in_quote = false;
                }
                ' ' | '\t' if !in_quote => {
                    if !current.is_empty() {
                        parts.push(current.clone());
                        current.clear();
                    }
                }
                _ => {
                    current.push(c);
                }
            }
        }

        if !current.is_empty() {
            parts.push(current);
        }

        parts
    }

    /// Add a section to the config
    fn add_section(config: &mut HAProxyConfig, section: Section) {
        match section.section_type {
            SectionType::Global => config.global = Some(section),
            SectionType::Defaults => config.defaults = Some(section),
            SectionType::Frontend => config.frontends.push(section),
            SectionType::Backend => config.backends.push(section),
            SectionType::Listen => config.listens.push(section),
        }
    }
}

impl Default for HAProxyParser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser for HAProxyParser {
    fn format(&self) -> SourceFormat {
        SourceFormat::HAProxy
    }

    fn can_parse(&self, _path: &Path, content: &str) -> bool {
        // Check for HAProxy-specific patterns
        content.contains("frontend ")
            || content.contains("backend ")
            || content.contains("listen ")
            || (content.contains("global") && content.contains("defaults"))
            || content.contains("use_backend")
            || content.contains("acl ")
    }

    fn parse(&self, ctx: &mut ParseContext) -> Result<ParseOutput, ParseError> {
        // Parse content into HAProxy AST
        let haproxy_config = Self::parse_content(&ctx.content, &ctx.primary_path)?;

        // Convert to IR
        let output = map_haproxy_to_ir(haproxy_config, ctx)?;

        Ok(output)
    }

    fn extensions(&self) -> &[&str] {
        &["cfg", "haproxy", "haproxy.cfg"]
    }

    fn signatures(&self) -> &[FormatSignature] {
        &[
            FormatSignature {
                pattern: r"^\s*frontend\s+\w+",
                confidence: 0.9,
                description: "HAProxy frontend section",
            },
            FormatSignature {
                pattern: r"^\s*backend\s+\w+",
                confidence: 0.9,
                description: "HAProxy backend section",
            },
            FormatSignature {
                pattern: r"^\s*listen\s+\w+",
                confidence: 0.85,
                description: "HAProxy listen section",
            },
            FormatSignature {
                pattern: r"^\s*global\s*$",
                confidence: 0.7,
                description: "HAProxy global section",
            },
            FormatSignature {
                pattern: r"use_backend\s+\w+",
                confidence: 0.9,
                description: "HAProxy use_backend directive",
            },
            FormatSignature {
                pattern: r"^\s*acl\s+\w+\s+",
                confidence: 0.8,
                description: "HAProxy ACL definition",
            },
            FormatSignature {
                pattern: r"^\s*bind\s+[\d\.\*:]+",
                confidence: 0.75,
                description: "HAProxy bind directive",
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_section_header() {
        assert_eq!(
            HAProxyParser::parse_section_header("frontend http_front"),
            Some((SectionType::Frontend, Some("http_front".to_string())))
        );
        assert_eq!(
            HAProxyParser::parse_section_header("backend servers"),
            Some((SectionType::Backend, Some("servers".to_string())))
        );
        assert_eq!(
            HAProxyParser::parse_section_header("global"),
            Some((SectionType::Global, None))
        );
        assert_eq!(
            HAProxyParser::parse_section_header("defaults"),
            Some((SectionType::Defaults, None))
        );
    }

    #[test]
    fn test_split_directive() {
        let parts = HAProxyParser::split_directive("bind *:80");
        assert_eq!(parts, vec!["bind", "*:80"]);

        let parts = HAProxyParser::split_directive(r#"acl is_api path_beg "/api""#);
        assert_eq!(parts, vec!["acl", "is_api", "path_beg", "/api"]);

        let parts = HAProxyParser::split_directive("server web1 10.0.0.1:8080 weight 5 check");
        assert_eq!(parts, vec!["server", "web1", "10.0.0.1:8080", "weight", "5", "check"]);
    }

    #[test]
    fn test_parse_basic_config() {
        let config = r#"
global
    maxconn 4096
    log /dev/log local0

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend http_front
    bind *:80
    default_backend servers

backend servers
    balance roundrobin
    server web1 10.0.0.1:8080 weight 5 check
    server web2 10.0.0.2:8080 weight 3 check
"#;
        let result = HAProxyParser::parse_content(config, Path::new("haproxy.cfg")).unwrap();

        assert!(result.global.is_some());
        assert!(result.defaults.is_some());
        assert_eq!(result.frontends.len(), 1);
        assert_eq!(result.backends.len(), 1);

        let frontend = &result.frontends[0];
        assert_eq!(frontend.name, Some("http_front".to_string()));
        assert!(frontend.has_directive("bind"));
        assert!(frontend.has_directive("default_backend"));

        let backend = &result.backends[0];
        assert_eq!(backend.name, Some("servers".to_string()));
        assert_eq!(backend.find_all_directives("server").len(), 2);
    }
}
