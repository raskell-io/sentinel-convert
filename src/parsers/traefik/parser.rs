//! Traefik configuration parser

use super::mapping::map_traefik_to_ir;
use super::TraefikConfig;
use crate::ir::SourceFormat;
use crate::parsers::{FormatSignature, ParseContext, ParseError, ParseOutput, Parser};
use std::path::Path;

/// Traefik configuration parser (YAML/TOML)
pub struct TraefikParser;

impl TraefikParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse Traefik config from YAML content
    fn parse_yaml(content: &str, file: &Path) -> Result<TraefikConfig, ParseError> {
        serde_yaml::from_str(content).map_err(|e| ParseError::Syntax {
            file: file.to_path_buf(),
            line: e.location().map(|l| l.line()).unwrap_or(0),
            column: e.location().map(|l| l.column()),
            message: e.to_string(),
        })
    }

    /// Parse Traefik config from TOML content
    fn parse_toml(content: &str, file: &Path) -> Result<TraefikConfig, ParseError> {
        toml::from_str(content).map_err(|e| ParseError::Syntax {
            file: file.to_path_buf(),
            line: e.span().map(|s| content[..s.start].lines().count()).unwrap_or(0),
            column: None,
            message: e.message().to_string(),
        })
    }

    /// Detect if content is YAML or TOML
    fn is_yaml(content: &str) -> bool {
        // TOML uses = for assignment, YAML uses :
        // Check for common YAML patterns
        content.contains(": ")
            || content.trim_start().starts_with("---")
            || content.contains(":\n")
    }
}

impl Default for TraefikParser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser for TraefikParser {
    fn format(&self) -> SourceFormat {
        SourceFormat::Traefik
    }

    fn can_parse(&self, path: &Path, content: &str) -> bool {
        // Check file extension
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if matches!(ext, "yaml" | "yml" | "toml") {
                // Check for Traefik-specific content
                return content.contains("entryPoints")
                    || content.contains("entry_points")
                    || content.contains("routers")
                    || content.contains("services")
                    || content.contains("middlewares")
                    || (content.contains("http") && content.contains("loadBalancer"));
            }
        }

        // Check for Traefik patterns in content
        content.contains("entryPoints")
            || (content.contains("http:")
                && (content.contains("routers:") || content.contains("services:")))
    }

    fn parse(&self, ctx: &mut ParseContext) -> Result<ParseOutput, ParseError> {
        // Detect format and parse
        let traefik_config = if Self::is_yaml(&ctx.content) {
            Self::parse_yaml(&ctx.content, &ctx.primary_path)?
        } else {
            Self::parse_toml(&ctx.content, &ctx.primary_path)?
        };

        // Convert to IR
        let output = map_traefik_to_ir(traefik_config, ctx)?;

        Ok(output)
    }

    fn extensions(&self) -> &[&str] {
        &["yaml", "yml", "toml"]
    }

    fn signatures(&self) -> &[FormatSignature] {
        &[
            FormatSignature {
                pattern: r"entryPoints:",
                confidence: 0.9,
                description: "Traefik entryPoints section (YAML)",
            },
            FormatSignature {
                pattern: r"\[entryPoints\]",
                confidence: 0.9,
                description: "Traefik entryPoints section (TOML)",
            },
            FormatSignature {
                pattern: r"http:\s*\n\s*routers:",
                confidence: 0.85,
                description: "Traefik HTTP routers section",
            },
            FormatSignature {
                pattern: r"middlewares:\s*\n",
                confidence: 0.7,
                description: "Traefik middlewares section",
            },
            FormatSignature {
                pattern: r"loadBalancer:\s*\n\s*servers:",
                confidence: 0.85,
                description: "Traefik loadBalancer with servers",
            },
            FormatSignature {
                pattern: r#"rule:\s*["']?Host\("#,
                confidence: 0.9,
                description: "Traefik Host rule",
            },
            FormatSignature {
                pattern: r#"rule:\s*["']?PathPrefix\("#,
                confidence: 0.85,
                description: "Traefik PathPrefix rule",
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_yaml() {
        assert!(TraefikParser::is_yaml("key: value"));
        assert!(TraefikParser::is_yaml("---\nkey: value"));
        assert!(TraefikParser::is_yaml("http:\n  routers:"));
        assert!(!TraefikParser::is_yaml("[section]\nkey = value"));
    }

    #[test]
    fn test_can_parse() {
        let parser = TraefikParser::new();

        // YAML with Traefik content
        assert!(parser.can_parse(
            Path::new("traefik.yaml"),
            "http:\n  routers:\n    my-router:\n      rule: Host(`example.com`)"
        ));

        // YAML with entryPoints
        assert!(parser.can_parse(
            Path::new("config.yml"),
            "entryPoints:\n  web:\n    address: ':80'"
        ));

        // Non-Traefik YAML
        assert!(!parser.can_parse(
            Path::new("config.yaml"),
            "database:\n  host: localhost\n  port: 5432"
        ));
    }

    #[test]
    fn test_parse_basic_yaml() {
        let content = r#"
entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"

http:
  routers:
    my-router:
      rule: "Host(`example.com`)"
      service: my-service
      entryPoints:
        - websecure

  services:
    my-service:
      loadBalancer:
        servers:
          - url: "http://10.0.0.1:8080"
          - url: "http://10.0.0.2:8080"
"#;

        let config = TraefikParser::parse_yaml(content, Path::new("traefik.yaml")).unwrap();

        assert_eq!(config.entry_points.len(), 2);
        assert!(config.entry_points.contains_key("web"));
        assert!(config.entry_points.contains_key("websecure"));
        assert_eq!(config.http.routers.len(), 1);
        assert_eq!(config.http.services.len(), 1);
    }
}
