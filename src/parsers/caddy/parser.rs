//! Caddyfile parser

use super::mapping::map_caddy_to_ir;
use super::{CaddyConfig, Directive, GlobalOptions, SiteAddress, SiteBlock, Snippet};
use crate::ir::SourceFormat;
use crate::parsers::{FormatSignature, ParseContext, ParseError, ParseOutput, Parser};
use std::path::Path;

/// Caddy configuration parser (Caddyfile format)
pub struct CaddyParser;

impl CaddyParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse Caddyfile content
    fn parse_caddyfile(content: &str, file: &Path) -> Result<CaddyConfig, ParseError> {
        let mut config = CaddyConfig::default();
        let mut lines: Vec<(usize, &str)> = content
            .lines()
            .enumerate()
            .map(|(i, line)| (i + 1, line))
            .collect();

        let mut idx = 0;
        while idx < lines.len() {
            let (line_num, line) = lines[idx];
            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                idx += 1;
                continue;
            }

            // Global options block
            if trimmed == "{" && idx == 0 {
                let (global_opts, consumed) =
                    Self::parse_global_options(&lines[idx..], file)?;
                config.global_options = Some(global_opts);
                idx += consumed;
                continue;
            }

            // Snippet definition (starts with parentheses)
            if trimmed.starts_with('(') && trimmed.contains(')') {
                let (snippet, consumed) = Self::parse_snippet(&lines[idx..], file)?;
                config.snippets.push(snippet);
                idx += consumed;
                continue;
            }

            // Site block
            if !trimmed.is_empty() {
                let (site, consumed) = Self::parse_site_block(&lines[idx..], file)?;
                config.sites.push(site);
                idx += consumed;
                continue;
            }

            idx += 1;
        }

        Ok(config)
    }

    /// Parse global options block
    fn parse_global_options(
        lines: &[(usize, &str)],
        file: &Path,
    ) -> Result<(GlobalOptions, usize), ParseError> {
        let mut opts = GlobalOptions::default();
        let mut idx = 1; // Skip opening brace
        let mut depth = 1;

        while idx < lines.len() && depth > 0 {
            let (line_num, line) = lines[idx];
            let trimmed = line.trim();

            if trimmed == "{" {
                depth += 1;
            } else if trimmed == "}" {
                depth -= 1;
            } else if depth == 1 && !trimmed.is_empty() && !trimmed.starts_with('#') {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if !parts.is_empty() {
                    match parts[0] {
                        "admin" => opts.admin = parts.get(1).map(|s| s.to_string()),
                        "email" => opts.email = parts.get(1).map(|s| s.to_string()),
                        "default_sni" => opts.default_sni = parts.get(1).map(|s| s.to_string()),
                        "auto_https" => opts.auto_https = parts.get(1).map(|s| s.to_string()),
                        _ => {
                            let location =
                                crate::ir::SourceLocation::new(file.to_path_buf(), line_num);
                            opts.options.push(
                                Directive::new(parts[0].to_string(), location)
                                    .with_args(parts[1..].iter().map(|s| s.to_string()).collect()),
                            );
                        }
                    }
                }
            }

            idx += 1;
        }

        Ok((opts, idx))
    }

    /// Parse snippet definition
    fn parse_snippet(
        lines: &[(usize, &str)],
        file: &Path,
    ) -> Result<(Snippet, usize), ParseError> {
        let (first_line_num, first_line) = lines[0];
        let trimmed = first_line.trim();

        // Extract snippet name from (name)
        let name = trimmed
            .trim_start_matches('(')
            .split(')')
            .next()
            .unwrap_or("")
            .to_string();

        let mut directives = Vec::new();
        let mut idx = 1;
        let mut depth = 1;

        // Check if block is on same line or next
        if trimmed.ends_with('{') {
            depth = 1;
        } else if idx < lines.len() && lines[idx].1.trim() == "{" {
            idx += 1;
        }

        while idx < lines.len() && depth > 0 {
            let (line_num, line) = lines[idx];
            let trimmed = line.trim();

            if trimmed == "{" {
                depth += 1;
            } else if trimmed == "}" {
                depth -= 1;
            } else if !trimmed.is_empty() && !trimmed.starts_with('#') && depth == 1 {
                let location = crate::ir::SourceLocation::new(file.to_path_buf(), line_num);
                if let Some(directive) = Self::parse_directive_line(trimmed, location) {
                    directives.push(directive);
                }
            }

            idx += 1;
        }

        Ok((Snippet { name, directives }, idx))
    }

    /// Parse a site block
    fn parse_site_block(
        lines: &[(usize, &str)],
        file: &Path,
    ) -> Result<(SiteBlock, usize), ParseError> {
        let (first_line_num, first_line) = lines[0];
        let trimmed = first_line.trim();

        // Parse site addresses (everything before { or on single line)
        let addr_part = if trimmed.contains('{') {
            trimmed.split('{').next().unwrap_or(trimmed).trim()
        } else {
            trimmed
        };

        let addresses = Self::parse_site_addresses(addr_part);
        let location = crate::ir::SourceLocation::new(file.to_path_buf(), first_line_num);

        let mut directives = Vec::new();
        let mut idx = 0;

        // Find opening brace
        if trimmed.contains('{') {
            idx = 1;
        } else {
            // Look for opening brace on next line
            idx = 1;
            while idx < lines.len() {
                let line = lines[idx].1.trim();
                if line == "{" {
                    idx += 1;
                    break;
                } else if !line.is_empty() && !line.starts_with('#') {
                    // Single-line site block (no braces)
                    let dir_location =
                        crate::ir::SourceLocation::new(file.to_path_buf(), lines[idx].0);
                    if let Some(directive) = Self::parse_directive_line(line, dir_location) {
                        directives.push(directive);
                    }
                    return Ok((
                        SiteBlock {
                            addresses,
                            directives,
                            location,
                        },
                        idx + 1,
                    ));
                }
                idx += 1;
            }
        }

        // Parse block content
        let mut depth = 1;
        while idx < lines.len() && depth > 0 {
            let (line_num, line) = lines[idx];
            let trimmed = line.trim();

            if trimmed.ends_with('{') && !trimmed.starts_with('#') {
                // Start of nested block
                let (directive, consumed) = Self::parse_directive_block(&lines[idx..], file)?;
                directives.push(directive);
                idx += consumed;
                continue;
            } else if trimmed == "{" {
                depth += 1;
            } else if trimmed == "}" {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            } else if !trimmed.is_empty() && !trimmed.starts_with('#') && depth == 1 {
                let dir_location = crate::ir::SourceLocation::new(file.to_path_buf(), line_num);
                if let Some(directive) = Self::parse_directive_line(trimmed, dir_location) {
                    directives.push(directive);
                }
            }

            idx += 1;
        }

        Ok((
            SiteBlock {
                addresses,
                directives,
                location,
            },
            idx + 1,
        ))
    }

    /// Parse directive with block
    fn parse_directive_block(
        lines: &[(usize, &str)],
        file: &Path,
    ) -> Result<(Directive, usize), ParseError> {
        let (first_line_num, first_line) = lines[0];
        let trimmed = first_line.trim();

        // Parse directive name and args before {
        let before_brace = trimmed.trim_end_matches('{').trim();
        let (name, matcher, args) = Self::parse_directive_parts(before_brace);

        let location = crate::ir::SourceLocation::new(file.to_path_buf(), first_line_num);
        let mut directive = Directive::new(name, location).with_args(args);

        if let Some(m) = matcher {
            directive = directive.with_matcher(m);
        }

        let mut block = Vec::new();
        let mut idx = 1;
        let mut depth = 1;

        while idx < lines.len() && depth > 0 {
            let (line_num, line) = lines[idx];
            let trimmed = line.trim();

            if trimmed.ends_with('{') && !trimmed.starts_with('#') {
                let (sub_directive, consumed) = Self::parse_directive_block(&lines[idx..], file)?;
                block.push(sub_directive);
                idx += consumed;
                continue;
            } else if trimmed == "{" {
                depth += 1;
            } else if trimmed == "}" {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            } else if !trimmed.is_empty() && !trimmed.starts_with('#') && depth == 1 {
                let dir_location = crate::ir::SourceLocation::new(file.to_path_buf(), line_num);
                if let Some(sub_dir) = Self::parse_directive_line(trimmed, dir_location) {
                    block.push(sub_dir);
                }
            }

            idx += 1;
        }

        directive = directive.with_block(block);
        Ok((directive, idx + 1))
    }

    /// Parse a single directive line
    fn parse_directive_line(line: &str, location: crate::ir::SourceLocation) -> Option<Directive> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return None;
        }

        let (name, matcher, args) = Self::parse_directive_parts(trimmed);
        let mut directive = Directive::new(name, location).with_args(args);

        if let Some(m) = matcher {
            directive = directive.with_matcher(m);
        }

        Some(directive)
    }

    /// Parse directive parts (name, optional matcher, args)
    fn parse_directive_parts(line: &str) -> (String, Option<String>, Vec<String>) {
        let parts = Self::split_respecting_quotes(line);
        if parts.is_empty() {
            return (String::new(), None, Vec::new());
        }

        let first = &parts[0];

        // Check for matcher prefix (starts with @ or *)
        if first.starts_with('@') || first.starts_with('*') || first.starts_with('/') {
            // This is a matcher, next part is directive name
            if parts.len() > 1 {
                let matcher = first.clone();
                let name = parts[1].clone();
                let args = parts[2..].to_vec();
                return (name, Some(matcher), args);
            }
        }

        let name = first.clone();
        let args = parts[1..].to_vec();
        (name, None, args)
    }

    /// Split line respecting quoted strings
    fn split_respecting_quotes(line: &str) -> Vec<String> {
        let mut parts = Vec::new();
        let mut current = String::new();
        let mut in_quote = false;
        let mut quote_char = '"';

        for c in line.chars() {
            match c {
                '"' | '\'' | '`' if !in_quote => {
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

    /// Parse site addresses from address string
    fn parse_site_addresses(addr_str: &str) -> Vec<SiteAddress> {
        addr_str
            .split(',')
            .flat_map(|s| s.split_whitespace())
            .filter(|s| !s.is_empty())
            .map(Self::parse_single_address)
            .collect()
    }

    /// Parse a single site address
    fn parse_single_address(addr: &str) -> SiteAddress {
        let mut result = SiteAddress::default();

        let addr = addr.trim();

        // Check for scheme
        let (scheme, rest) = if addr.starts_with("https://") {
            (Some("https".to_string()), &addr[8..])
        } else if addr.starts_with("http://") {
            (Some("http".to_string()), &addr[7..])
        } else {
            (None, addr)
        };
        result.scheme = scheme;

        // Check for path
        let (host_port, path) = if let Some(slash_idx) = rest.find('/') {
            let path = rest[slash_idx..].to_string();
            (&rest[..slash_idx], Some(path))
        } else {
            (rest, None)
        };
        result.path = path;

        // Parse host:port
        if host_port.starts_with(':') {
            // Port only
            result.port = host_port[1..].parse().ok();
        } else if let Some(colon_idx) = host_port.rfind(':') {
            // Check if it's IPv6 or host:port
            let potential_port = &host_port[colon_idx + 1..];
            if potential_port.chars().all(|c| c.is_ascii_digit()) {
                result.host = Some(host_port[..colon_idx].to_string());
                result.port = potential_port.parse().ok();
            } else {
                result.host = Some(host_port.to_string());
            }
        } else if !host_port.is_empty() {
            result.host = Some(host_port.to_string());
        }

        result
    }
}

impl Default for CaddyParser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser for CaddyParser {
    fn format(&self) -> SourceFormat {
        SourceFormat::Caddy
    }

    fn can_parse(&self, path: &Path, content: &str) -> bool {
        // Check file name
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.to_lowercase() == "caddyfile" {
                return true;
            }
        }

        // Check for Caddy-specific patterns
        content.contains("reverse_proxy")
            || content.contains("file_server")
            || content.contains("encode gzip")
            || content.contains("encode zstd")
            || (content.contains("tls ") && content.contains("{"))
            || content.contains("handle ")
            || content.contains("handle_path ")
            || content.contains("php_fastcgi")
    }

    fn parse(&self, ctx: &mut ParseContext) -> Result<ParseOutput, ParseError> {
        let caddy_config = Self::parse_caddyfile(&ctx.content, &ctx.primary_path)?;
        let output = map_caddy_to_ir(caddy_config, ctx)?;
        Ok(output)
    }

    fn extensions(&self) -> &[&str] {
        &["caddyfile", "caddy"]
    }

    fn signatures(&self) -> &[FormatSignature] {
        &[
            FormatSignature {
                pattern: r"reverse_proxy\s+",
                confidence: 0.85,
                description: "Caddy reverse_proxy directive",
            },
            FormatSignature {
                pattern: r"file_server",
                confidence: 0.8,
                description: "Caddy file_server directive",
            },
            FormatSignature {
                pattern: r"encode\s+(gzip|zstd|br)",
                confidence: 0.85,
                description: "Caddy encode directive",
            },
            FormatSignature {
                pattern: r"handle\s+",
                confidence: 0.75,
                description: "Caddy handle directive",
            },
            FormatSignature {
                pattern: r"handle_path\s+",
                confidence: 0.8,
                description: "Caddy handle_path directive",
            },
            FormatSignature {
                pattern: r"php_fastcgi\s+",
                confidence: 0.9,
                description: "Caddy php_fastcgi directive",
            },
            FormatSignature {
                pattern: r"tls\s+internal",
                confidence: 0.85,
                description: "Caddy internal TLS",
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_address() {
        let addr = CaddyParser::parse_single_address("example.com");
        assert_eq!(addr.host, Some("example.com".to_string()));
        assert_eq!(addr.port, None);

        let addr = CaddyParser::parse_single_address(":8080");
        assert_eq!(addr.host, None);
        assert_eq!(addr.port, Some(8080));

        let addr = CaddyParser::parse_single_address("localhost:8080");
        assert_eq!(addr.host, Some("localhost".to_string()));
        assert_eq!(addr.port, Some(8080));

        let addr = CaddyParser::parse_single_address("https://example.com");
        assert_eq!(addr.scheme, Some("https".to_string()));
        assert_eq!(addr.host, Some("example.com".to_string()));

        let addr = CaddyParser::parse_single_address("example.com/api/*");
        assert_eq!(addr.host, Some("example.com".to_string()));
        assert_eq!(addr.path, Some("/api/*".to_string()));
    }

    #[test]
    fn test_split_respecting_quotes() {
        let parts = CaddyParser::split_respecting_quotes("reverse_proxy localhost:8080");
        assert_eq!(parts, vec!["reverse_proxy", "localhost:8080"]);

        let parts = CaddyParser::split_respecting_quotes(r#"header "X-Custom" "value with spaces""#);
        assert_eq!(parts, vec!["header", "X-Custom", "value with spaces"]);

        let parts = CaddyParser::split_respecting_quotes("@api path /api/*");
        assert_eq!(parts, vec!["@api", "path", "/api/*"]);
    }

    #[test]
    fn test_parse_directive_parts() {
        let (name, matcher, args) = CaddyParser::parse_directive_parts("reverse_proxy localhost:8080");
        assert_eq!(name, "reverse_proxy");
        assert_eq!(matcher, None);
        assert_eq!(args, vec!["localhost:8080"]);

        let (name, matcher, args) = CaddyParser::parse_directive_parts("@api reverse_proxy backend:8080");
        assert_eq!(name, "reverse_proxy");
        assert_eq!(matcher, Some("@api".to_string()));
        assert_eq!(args, vec!["backend:8080"]);

        let (name, matcher, args) = CaddyParser::parse_directive_parts("/api/* reverse_proxy api:8080");
        assert_eq!(name, "reverse_proxy");
        assert_eq!(matcher, Some("/api/*".to_string()));
        assert_eq!(args, vec!["api:8080"]);
    }

    #[test]
    fn test_can_parse() {
        let parser = CaddyParser::new();

        assert!(parser.can_parse(
            Path::new("Caddyfile"),
            "example.com { reverse_proxy localhost:8080 }"
        ));

        assert!(parser.can_parse(
            Path::new("config"),
            ":8080 { file_server }"
        ));

        assert!(!parser.can_parse(
            Path::new("nginx.conf"),
            "server { listen 80; }"
        ));
    }

    #[test]
    fn test_parse_basic_caddyfile() {
        let content = r#"
example.com {
    reverse_proxy localhost:8080
    encode gzip
}
"#;
        let config = CaddyParser::parse_caddyfile(content, Path::new("Caddyfile")).unwrap();

        assert_eq!(config.sites.len(), 1);
        let site = &config.sites[0];
        assert_eq!(site.addresses.len(), 1);
        assert_eq!(site.addresses[0].host, Some("example.com".to_string()));
        assert!(site.directives.iter().any(|d| d.name == "reverse_proxy"));
        assert!(site.directives.iter().any(|d| d.name == "encode"));
    }
}
