//! nginx configuration parser

use super::lexer::{tokenize, Token};
use super::mapping::map_nginx_to_ir;
use super::{Directive, NginxConfig};
use crate::ir::SourceFormat;
use crate::parsers::{FormatSignature, ParseContext, ParseError, ParseOutput, Parser};
use std::path::Path;

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
        // Tokenize
        let tokens = tokenize(&ctx.content)
            .map_err(|e| ParseError::Syntax {
                file: ctx.primary_path.clone(),
                line: 0,
                column: None,
                message: e,
            })?;

        // Parse tokens into AST
        let nginx_config = Self::parse_tokens(&tokens, &ctx.primary_path)?;

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
}
