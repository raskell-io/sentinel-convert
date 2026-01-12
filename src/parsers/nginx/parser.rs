//! nginx configuration parser

use super::lexer::{tokenize, Token};
use super::mapping::map_nginx_to_ir;
use super::{Directive, NginxConfig};
use crate::ir::SourceFormat;
use crate::parsers::{FormatSignature, ParseContext, ParseError, ParseOutput, Parser};
use glob::glob;
use std::fs;
use std::path::{Path, PathBuf};

/// nginx configuration parser
pub struct NginxParser;

impl NginxParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse nginx config from tokens
    fn parse_tokens(
        tokens: &[(Token, usize)],
        file: &Path,
    ) -> Result<NginxConfig, ParseError> {
        let mut config = NginxConfig::default();
        let mut pos = 0;

        while pos < tokens.len() {
            let (directive, new_pos) = Self::parse_directive(tokens, pos, file)?;
            if let Some(d) = directive {
                config.directives.push(d);
            }
            pos = new_pos;
        }

        Ok(config)
    }

    /// Parse a single directive (simple or block)
    fn parse_directive(
        tokens: &[(Token, usize)],
        start: usize,
        file: &Path,
    ) -> Result<(Option<Directive>, usize), ParseError> {
        let mut pos = start;

        // Skip comments
        while pos < tokens.len() {
            match &tokens[pos].0 {
                Token::Comment(_) => pos += 1,
                _ => break,
            }
        }

        if pos >= tokens.len() {
            return Ok((None, pos));
        }

        // Get directive name
        let (name, line) = match &tokens[pos] {
            (Token::Identifier(name), line) => (name.clone(), *line),
            (Token::CloseBrace, _) => return Ok((None, pos)),
            (token, line) => {
                return Err(ParseError::Syntax {
                    file: file.to_path_buf(),
                    line: *line,
                    column: None,
                    message: format!("Expected directive name, got {:?}", token),
                })
            }
        };
        pos += 1;

        let mut directive = Directive::new(name, line, file.to_path_buf());
        let mut args = Vec::new();

        // Parse arguments until ; or {
        while pos < tokens.len() {
            match &tokens[pos] {
                (Token::Identifier(arg), _) | (Token::String(arg), _) | (Token::Number(arg), _) => {
                    args.push(arg.clone());
                    pos += 1;
                }
                (Token::Semicolon, _) => {
                    pos += 1;
                    directive.args = args;
                    return Ok((Some(directive), pos));
                }
                (Token::OpenBrace, _) => {
                    pos += 1;
                    directive.args = args;

                    // Parse block contents
                    let mut block = Vec::new();
                    loop {
                        if pos >= tokens.len() {
                            return Err(ParseError::Syntax {
                                file: file.to_path_buf(),
                                line,
                                column: None,
                                message: "Unexpected end of file in block".to_string(),
                            });
                        }

                        match &tokens[pos] {
                            (Token::CloseBrace, _) => {
                                pos += 1;
                                break;
                            }
                            _ => {
                                let (child, new_pos) = Self::parse_directive(tokens, pos, file)?;
                                if let Some(d) = child {
                                    block.push(d);
                                }
                                pos = new_pos;
                            }
                        }
                    }

                    directive.block = Some(block);
                    return Ok((Some(directive), pos));
                }
                (Token::Comment(_), _) => {
                    pos += 1;
                }
                (token, line) => {
                    return Err(ParseError::Syntax {
                        file: file.to_path_buf(),
                        line: *line,
                        column: None,
                        message: format!("Unexpected token {:?}", token),
                    })
                }
            }
        }

        // If we get here without ; or {, it's an error
        Err(ParseError::Syntax {
            file: file.to_path_buf(),
            line,
            column: None,
            message: "Directive not terminated with ; or {".to_string(),
        })
    }

    /// Process include directives in the parsed config
    fn process_includes(
        directives: Vec<Directive>,
        ctx: &mut ParseContext,
    ) -> Result<Vec<Directive>, ParseError> {
        if !ctx.options.follow_includes {
            return Ok(directives);
        }

        let mut result = Vec::new();

        for directive in directives {
            if directive.name == "include" {
                // Process include directive
                if let Some(pattern) = directive.first_arg() {
                    let included = Self::resolve_and_parse_include(pattern, ctx, &directive)?;
                    result.extend(included);
                }
            } else if directive.block.is_some() {
                // Recursively process block contents
                let block = directive.block.unwrap();
                let processed_block = Self::process_includes(block, ctx)?;
                let mut new_directive = Directive::new(
                    directive.name.clone(),
                    directive.location.line,
                    directive.location.file.clone(),
                );
                new_directive.args = directive.args;
                new_directive.block = Some(processed_block);
                result.push(new_directive);
            } else {
                result.push(directive);
            }
        }

        Ok(result)
    }

    /// Resolve include pattern and parse matching files
    fn resolve_and_parse_include(
        pattern: &str,
        ctx: &mut ParseContext,
        include_directive: &Directive,
    ) -> Result<Vec<Directive>, ParseError> {
        // Resolve the include path
        let resolved_pattern = if Path::new(pattern).is_absolute() {
            pattern.to_string()
        } else {
            ctx.base_dir.join(pattern).to_string_lossy().to_string()
        };

        // Expand glob pattern
        let paths = Self::expand_glob(&resolved_pattern, include_directive)?;

        if paths.is_empty() {
            // nginx silently ignores includes with no matches when using glob
            // But warn about it in strict mode
            return Ok(Vec::new());
        }

        let mut all_directives = Vec::new();

        for path in paths {
            // Check for cycles and depth
            ctx.can_include(&path)?;

            // Track this file
            ctx.processed.insert(path.clone());
            ctx.include_depth += 1;

            // Read the file
            let content = fs::read_to_string(&path).map_err(ParseError::Io)?;

            // Tokenize and parse
            let tokens = tokenize(&content).map_err(|e| ParseError::Syntax {
                file: path.clone(),
                line: 0,
                column: None,
                message: e,
            })?;

            let config = Self::parse_tokens(&tokens, &path)?;

            // Recursively process includes in the included file
            let processed = Self::process_includes(config.directives, ctx)?;
            all_directives.extend(processed);

            ctx.include_depth -= 1;
        }

        Ok(all_directives)
    }

    /// Expand glob pattern to list of file paths
    fn expand_glob(pattern: &str, directive: &Directive) -> Result<Vec<PathBuf>, ParseError> {
        // Check if pattern contains glob characters
        if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
            let mut paths: Vec<PathBuf> = glob(pattern)
                .map_err(|e| ParseError::Syntax {
                    file: directive.location.file.clone(),
                    line: directive.location.line,
                    column: None,
                    message: format!("Invalid glob pattern: {}", e),
                })?
                .filter_map(|r| r.ok())
                .filter(|p| p.is_file())
                .collect();

            // Sort for consistent ordering
            paths.sort();
            Ok(paths)
        } else {
            // Single file
            let path = PathBuf::from(pattern);
            if path.exists() {
                Ok(vec![path])
            } else {
                // nginx errors on missing non-glob includes
                Err(ParseError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Include file not found: {}", pattern),
                )))
            }
        }
    }
}

impl Default for NginxParser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser for NginxParser {
    fn format(&self) -> SourceFormat {
        SourceFormat::Nginx
    }

    fn can_parse(&self, _path: &Path, content: &str) -> bool {
        // Check for nginx-specific patterns
        content.contains("worker_processes")
            || content.contains("http {")
            || content.contains("server {")
            || content.contains("location ")
            || content.contains("upstream ")
            || content.contains("proxy_pass")
    }

    fn parse(&self, ctx: &mut ParseContext) -> Result<ParseOutput, ParseError> {
        // Mark primary file as processed (for cycle detection)
        ctx.processed.insert(ctx.primary_path.clone());

        // Tokenize
        let tokens = tokenize(&ctx.content)
            .map_err(|e| ParseError::Syntax {
                file: ctx.primary_path.clone(),
                line: 0,
                column: None,
                message: e,
            })?;

        // Parse tokens into AST
        let mut nginx_config = Self::parse_tokens(&tokens, &ctx.primary_path)?;

        // Process include directives
        nginx_config.directives = Self::process_includes(nginx_config.directives, ctx)?;

        // Convert to IR
        let output = map_nginx_to_ir(nginx_config, ctx)?;

        Ok(output)
    }

    fn extensions(&self) -> &[&str] {
        &["conf", "nginx"]
    }

    fn signatures(&self) -> &[FormatSignature] {
        &[
            FormatSignature {
                pattern: r"^\s*worker_processes\s+",
                confidence: 0.9,
                description: "nginx worker_processes directive",
            },
            FormatSignature {
                pattern: r"^\s*http\s*\{",
                confidence: 0.9,
                description: "nginx http block",
            },
            FormatSignature {
                pattern: r"server\s*\{[^}]*listen\s+\d+",
                confidence: 0.85,
                description: "nginx server block with listen",
            },
            FormatSignature {
                pattern: r"location\s+[~=^]*\s*[/\w]",
                confidence: 0.8,
                description: "nginx location directive",
            },
            FormatSignature {
                pattern: r"proxy_pass\s+https?://",
                confidence: 0.85,
                description: "nginx proxy_pass directive",
            },
            FormatSignature {
                pattern: r"upstream\s+\w+\s*\{",
                confidence: 0.9,
                description: "nginx upstream block",
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_directive() {
        let input = "worker_processes 4;";
        let tokens = tokenize(input).unwrap();
        let config = NginxParser::parse_tokens(&tokens, Path::new("test.conf")).unwrap();

        assert_eq!(config.directives.len(), 1);
        assert_eq!(config.directives[0].name, "worker_processes");
        assert_eq!(config.directives[0].args, vec!["4"]);
    }

    #[test]
    fn test_parse_block() {
        let input = r#"
            server {
                listen 80;
                server_name example.com;
            }
        "#;
        let tokens = tokenize(input).unwrap();
        let config = NginxParser::parse_tokens(&tokens, Path::new("test.conf")).unwrap();

        assert_eq!(config.directives.len(), 1);
        assert_eq!(config.directives[0].name, "server");
        assert!(config.directives[0].block.is_some());

        let block = config.directives[0].block.as_ref().unwrap();
        assert_eq!(block.len(), 2);
        assert_eq!(block[0].name, "listen");
        assert_eq!(block[1].name, "server_name");
    }

    #[test]
    fn test_parse_nested_blocks() {
        let input = r#"
            http {
                server {
                    location / {
                        proxy_pass http://backend;
                    }
                }
            }
        "#;
        let tokens = tokenize(input).unwrap();
        let config = NginxParser::parse_tokens(&tokens, Path::new("test.conf")).unwrap();

        assert_eq!(config.directives.len(), 1);
        assert_eq!(config.directives[0].name, "http");

        let http_block = config.directives[0].block.as_ref().unwrap();
        assert_eq!(http_block[0].name, "server");

        let server_block = http_block[0].block.as_ref().unwrap();
        assert_eq!(server_block[0].name, "location");

        let location_block = server_block[0].block.as_ref().unwrap();
        assert_eq!(location_block[0].name, "proxy_pass");
    }

    #[test]
    fn test_process_includes_disabled() {
        use crate::parsers::{ParseContext, ParseOptions};

        // Test that includes are skipped when follow_includes is false
        let directives = vec![
            Directive::new("worker_processes", 1, PathBuf::from("test.conf"))
                .with_args(vec!["4".to_string()]),
            Directive::new("include", 2, PathBuf::from("test.conf"))
                .with_args(vec!["/some/nonexistent/file.conf".to_string()]),
        ];

        let mut ctx = ParseContext::new(PathBuf::from("test.conf"), String::new());
        ctx.options = ParseOptions {
            follow_includes: false,
            ..Default::default()
        };

        // Should not error because includes are disabled
        let result = NginxParser::process_includes(directives.clone(), &mut ctx);
        assert!(result.is_ok());

        // The include directive should remain in the output (not expanded)
        let processed = result.unwrap();
        assert_eq!(processed.len(), 2);
        assert_eq!(processed[0].name, "worker_processes");
        assert_eq!(processed[1].name, "include");
    }

    #[test]
    fn test_glob_expansion() {
        // Test glob pattern detection
        assert!(NginxParser::expand_glob(
            "/nonexistent/*.conf",
            &Directive::new("include", 1, PathBuf::from("test.conf"))
        )
        .is_ok()); // Glob with no matches returns empty vec

        // Non-glob path that doesn't exist should error
        let result = NginxParser::expand_glob(
            "/nonexistent/specific.conf",
            &Directive::new("include", 1, PathBuf::from("test.conf")),
        );
        assert!(result.is_err());
    }
}
