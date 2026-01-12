//! Envoy configuration parser

use super::mapping::map_envoy_to_ir;
use super::EnvoyConfig;
use crate::ir::SourceFormat;
use crate::parsers::{FormatSignature, ParseContext, ParseError, ParseOutput, Parser};
use std::path::Path;

/// Envoy configuration parser
pub struct EnvoyParser;

impl EnvoyParser {
    pub fn new() -> Self {
        Self
    }

    /// Check if content looks like YAML
    fn is_yaml(content: &str) -> bool {
        // YAML typically doesn't start with { and uses indentation
        let trimmed = content.trim();
        !trimmed.starts_with('{') && (
            trimmed.contains("static_resources:") ||
            trimmed.contains("admin:") ||
            trimmed.contains("node:") ||
            content.lines().any(|line| line.starts_with("  ") || line.starts_with('\t'))
        )
    }

    /// Parse Envoy configuration
    fn parse_config(content: &str, path: &Path) -> Result<EnvoyConfig, ParseError> {
        if Self::is_yaml(content) {
            serde_yaml::from_str(content).map_err(|e| {
                let line = e.location().map(|l| l.line()).unwrap_or(0);
                ParseError::Syntax {
                    file: path.to_path_buf(),
                    line,
                    column: e.location().map(|l| l.column()),
                    message: format!("YAML parse error: {}", e),
                }
            })
        } else {
            serde_json::from_str(content).map_err(|e| {
                let line = e.line();
                ParseError::Syntax {
                    file: path.to_path_buf(),
                    line,
                    column: Some(e.column()),
                    message: format!("JSON parse error: {}", e),
                }
            })
        }
    }
}

impl Default for EnvoyParser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser for EnvoyParser {
    fn format(&self) -> SourceFormat {
        SourceFormat::Envoy
    }

    fn can_parse(&self, _path: &Path, content: &str) -> bool {
        // Check for Envoy-specific patterns
        content.contains("static_resources") ||
        content.contains("listeners:") ||
        content.contains("clusters:") ||
        content.contains("filter_chains:") ||
        content.contains("envoy.filters.network.http_connection_manager") ||
        content.contains("type.googleapis.com/envoy")
    }

    fn parse(&self, ctx: &mut ParseContext) -> Result<ParseOutput, ParseError> {
        // Parse the Envoy configuration
        let envoy_config = Self::parse_config(&ctx.content, &ctx.primary_path)?;

        // Convert to IR
        let output = map_envoy_to_ir(envoy_config, ctx)?;

        Ok(output)
    }

    fn extensions(&self) -> &[&str] {
        &["yaml", "yml", "json"]
    }

    fn signatures(&self) -> &[FormatSignature] {
        &[
            FormatSignature {
                pattern: r"static_resources\s*:",
                confidence: 0.9,
                description: "Envoy static_resources block",
            },
            FormatSignature {
                pattern: r"filter_chains\s*:",
                confidence: 0.85,
                description: "Envoy filter_chains",
            },
            FormatSignature {
                pattern: r"envoy\.filters\.network\.http_connection_manager",
                confidence: 0.95,
                description: "Envoy HTTP connection manager filter",
            },
            FormatSignature {
                pattern: r"type\.googleapis\.com/envoy",
                confidence: 0.95,
                description: "Envoy typed config URL",
            },
            FormatSignature {
                pattern: r"clusters\s*:\s*\n\s*-\s*name\s*:",
                confidence: 0.85,
                description: "Envoy clusters definition",
            },
            FormatSignature {
                pattern: r"listeners\s*:\s*\n\s*-\s*name\s*:",
                confidence: 0.85,
                description: "Envoy listeners definition",
            },
            FormatSignature {
                pattern: r"load_assignment\s*:",
                confidence: 0.8,
                description: "Envoy load assignment",
            },
            FormatSignature {
                pattern: r"virtual_hosts\s*:",
                confidence: 0.75,
                description: "Envoy virtual hosts",
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_parse() {
        let parser = EnvoyParser::new();

        assert!(parser.can_parse(
            Path::new("envoy.yaml"),
            "static_resources:\n  listeners:\n"
        ));

        assert!(parser.can_parse(
            Path::new("envoy.yaml"),
            "filter_chains:\n  - filters:\n"
        ));

        assert!(!parser.can_parse(
            Path::new("nginx.conf"),
            "server {\n  listen 80;\n}"
        ));
    }

    #[test]
    fn test_is_yaml() {
        assert!(EnvoyParser::is_yaml("static_resources:\n  listeners:\n"));
        assert!(EnvoyParser::is_yaml("  key: value\n"));
        assert!(!EnvoyParser::is_yaml("{\"static_resources\": {}}"));
    }

    #[test]
    fn test_parse_basic_yaml() {
        let yaml = r#"
static_resources:
  listeners:
    - name: listener_0
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 8080
  clusters:
    - name: backend
      type: STRICT_DNS
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: backend
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: 10.0.0.1
                      port_value: 8080
"#;

        let config = EnvoyParser::parse_config(yaml, Path::new("test.yaml")).unwrap();

        assert_eq!(config.static_resources.listeners.len(), 1);
        assert_eq!(config.static_resources.listeners[0].name, Some("listener_0".to_string()));
        assert_eq!(config.static_resources.clusters.len(), 1);
        assert_eq!(config.static_resources.clusters[0].name, Some("backend".to_string()));
    }
}
