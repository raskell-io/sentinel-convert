//! Parser plugins for various reverse proxy config formats

pub mod caddy;
pub mod envoy;
pub mod haproxy;
pub mod nginx;
pub mod traefik;
// pub mod apache;

use crate::ir::{Diagnostics, SentinelConfig, SourceFormat};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error at {file}:{line}: {message}")]
    Syntax {
        file: PathBuf,
        line: usize,
        column: Option<usize>,
        message: String,
    },

    #[error("Include cycle detected: {0}")]
    IncludeCycle(PathBuf),

    #[error("Maximum include depth exceeded ({0})")]
    MaxIncludeDepth(usize),

    #[error("Unsupported directive: {0}")]
    UnsupportedDirective(String),
}

/// Result of parsing a configuration
pub struct ParseOutput {
    pub config: SentinelConfig,
    pub diagnostics: Diagnostics,
}

/// Context for parsing, handles includes and multi-file configs
pub struct ParseContext {
    /// Primary configuration file path
    pub primary_path: PathBuf,
    /// Primary file content
    pub content: String,
    /// Base directory for resolving includes
    pub base_dir: PathBuf,
    /// Already processed includes (cycle detection)
    pub processed: HashSet<PathBuf>,
    /// Parser options
    pub options: ParseOptions,
    /// Current include depth
    pub include_depth: usize,
}

impl ParseContext {
    pub fn new(path: PathBuf, content: String) -> Self {
        let base_dir = path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
        Self {
            primary_path: path,
            content,
            base_dir,
            processed: HashSet::new(),
            options: ParseOptions::default(),
            include_depth: 0,
        }
    }

    /// Resolve an include path relative to the base directory
    pub fn resolve_include(&self, path: &str) -> PathBuf {
        let path = Path::new(path);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.base_dir.join(path)
        }
    }

    /// Check if we can process this include (no cycle, within depth limit)
    pub fn can_include(&self, path: &Path) -> Result<(), ParseError> {
        if self.processed.contains(path) {
            return Err(ParseError::IncludeCycle(path.to_path_buf()));
        }
        if self.include_depth >= self.options.max_include_depth {
            return Err(ParseError::MaxIncludeDepth(self.options.max_include_depth));
        }
        Ok(())
    }
}

/// Parser options
#[derive(Debug, Clone)]
pub struct ParseOptions {
    /// Follow include directives
    pub follow_includes: bool,
    /// Maximum include depth
    pub max_include_depth: usize,
    /// Strict mode (fail on unknown directives)
    pub strict: bool,
    /// Extract comments as documentation
    pub preserve_comments: bool,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            follow_includes: true,
            max_include_depth: 10,
            strict: false,
            preserve_comments: true,
        }
    }
}

/// Trait for source format parsers
pub trait Parser: Send + Sync {
    /// Returns the source format this parser handles
    fn format(&self) -> SourceFormat;

    /// Check if this parser can handle the given file
    fn can_parse(&self, path: &Path, content: &str) -> bool;

    /// Parse the configuration and produce IR
    fn parse(&self, ctx: &mut ParseContext) -> Result<ParseOutput, ParseError>;

    /// Returns file extensions this parser handles
    fn extensions(&self) -> &[&str];

    /// Returns signature patterns for format detection
    fn signatures(&self) -> &[FormatSignature];
}

/// Signature for auto-detecting config format
#[derive(Debug, Clone)]
pub struct FormatSignature {
    /// Regex pattern to match
    pub pattern: &'static str,
    /// Confidence if matched (0.0 - 1.0)
    pub confidence: f32,
    /// Description of what this matches
    pub description: &'static str,
}

/// Parser registry for managing format parsers
pub struct ParserRegistry {
    parsers: Vec<Box<dyn Parser>>,
}

impl ParserRegistry {
    pub fn new() -> Self {
        let mut registry = Self { parsers: vec![] };

        // Register built-in parsers
        registry.register(Box::new(nginx::NginxParser::new()));
        registry.register(Box::new(haproxy::HAProxyParser::new()));
        registry.register(Box::new(traefik::TraefikParser::new()));
        registry.register(Box::new(caddy::CaddyParser::new()));
        registry.register(Box::new(envoy::EnvoyParser::new()));
        // registry.register(Box::new(apache::ApacheParser::new()));

        registry
    }

    /// Register a parser
    pub fn register(&mut self, parser: Box<dyn Parser>) {
        self.parsers.push(parser);
    }

    /// Get parser for a specific format
    pub fn get_parser(&self, format: SourceFormat) -> Option<&dyn Parser> {
        self.parsers
            .iter()
            .find(|p| p.format() == format)
            .map(|p| p.as_ref())
    }

    /// Auto-detect format and return appropriate parser
    pub fn detect_format(&self, path: &Path, content: &str) -> Option<&dyn Parser> {
        // First try by extension
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            for parser in &self.parsers {
                if parser.extensions().contains(&ext) && parser.can_parse(path, content) {
                    return Some(parser.as_ref());
                }
            }
        }

        // Then try by content signatures
        let mut best_match: Option<(&dyn Parser, f32)> = None;

        for parser in &self.parsers {
            for sig in parser.signatures() {
                if let Ok(re) = regex::Regex::new(sig.pattern) {
                    if re.is_match(content) {
                        if best_match.map_or(true, |(_, conf)| sig.confidence > conf) {
                            best_match = Some((parser.as_ref(), sig.confidence));
                        }
                    }
                }
            }
        }

        best_match.map(|(p, _)| p)
    }

    /// List all available formats
    pub fn available_formats(&self) -> Vec<SourceFormat> {
        self.parsers.iter().map(|p| p.format()).collect()
    }
}

impl Default for ParserRegistry {
    fn default() -> Self {
        Self::new()
    }
}
