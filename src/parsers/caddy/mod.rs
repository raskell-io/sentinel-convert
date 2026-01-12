//! Caddy configuration parser (Caddyfile format)

mod mapping;
mod parser;

pub use parser::CaddyParser;

use crate::ir::SourceLocation;

/// Caddyfile configuration
#[derive(Debug, Clone, Default)]
pub struct CaddyConfig {
    /// Global options block
    pub global_options: Option<GlobalOptions>,
    /// Site blocks
    pub sites: Vec<SiteBlock>,
    /// Snippet definitions
    pub snippets: Vec<Snippet>,
}

/// Global options block
#[derive(Debug, Clone, Default)]
pub struct GlobalOptions {
    /// Admin endpoint address
    pub admin: Option<String>,
    /// Email for ACME
    pub email: Option<String>,
    /// Default SNI host
    pub default_sni: Option<String>,
    /// Log configuration
    pub log: Option<LogConfig>,
    /// Auto HTTPS mode
    pub auto_https: Option<String>,
    /// Other options
    pub options: Vec<Directive>,
}

/// Log configuration
#[derive(Debug, Clone, Default)]
pub struct LogConfig {
    pub output: Option<String>,
    pub format: Option<String>,
    pub level: Option<String>,
}

/// Site block (address matcher + directives)
#[derive(Debug, Clone)]
pub struct SiteBlock {
    /// Site addresses (hosts/ports)
    pub addresses: Vec<SiteAddress>,
    /// Directives within this site
    pub directives: Vec<Directive>,
    /// Source location
    pub location: SourceLocation,
}

/// Site address (e.g., "example.com", ":8080", "localhost:8080")
#[derive(Debug, Clone)]
pub struct SiteAddress {
    /// Host (may be empty for port-only)
    pub host: Option<String>,
    /// Port (may be empty for host-only)
    pub port: Option<u16>,
    /// Protocol scheme
    pub scheme: Option<String>,
    /// Path prefix (for path-based matching)
    pub path: Option<String>,
}

impl Default for SiteAddress {
    fn default() -> Self {
        Self {
            host: None,
            port: None,
            scheme: None,
            path: None,
        }
    }
}

/// Snippet definition (reusable block)
#[derive(Debug, Clone)]
pub struct Snippet {
    pub name: String,
    pub directives: Vec<Directive>,
}

/// Caddy directive
#[derive(Debug, Clone)]
pub struct Directive {
    /// Directive name
    pub name: String,
    /// Arguments
    pub args: Vec<String>,
    /// Sub-directives (block content)
    pub block: Option<Vec<Directive>>,
    /// Matcher (if any)
    pub matcher: Option<String>,
    /// Source location
    pub location: SourceLocation,
}

impl Directive {
    pub fn new(name: String, location: SourceLocation) -> Self {
        Self {
            name,
            args: Vec::new(),
            block: None,
            matcher: None,
            location,
        }
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    pub fn with_block(mut self, block: Vec<Directive>) -> Self {
        self.block = Some(block);
        self
    }

    pub fn with_matcher(mut self, matcher: String) -> Self {
        self.matcher = Some(matcher);
        self
    }

    /// Get first argument
    pub fn first_arg(&self) -> Option<&str> {
        self.args.first().map(|s| s.as_str())
    }

    /// Check if this directive has a specific subdirective
    pub fn has_subdirective(&self, name: &str) -> bool {
        self.block
            .as_ref()
            .map(|b| b.iter().any(|d| d.name == name))
            .unwrap_or(false)
    }

    /// Get a subdirective by name
    pub fn get_subdirective(&self, name: &str) -> Option<&Directive> {
        self.block
            .as_ref()
            .and_then(|b| b.iter().find(|d| d.name == name))
    }

    /// Get all subdirectives with a specific name
    pub fn get_subdirectives(&self, name: &str) -> Vec<&Directive> {
        self.block
            .as_ref()
            .map(|b| b.iter().filter(|d| d.name == name).collect())
            .unwrap_or_default()
    }
}

/// Common Caddy directive names
pub mod directives {
    pub const REVERSE_PROXY: &str = "reverse_proxy";
    pub const FILE_SERVER: &str = "file_server";
    pub const ROOT: &str = "root";
    pub const TLS: &str = "tls";
    pub const ENCODE: &str = "encode";
    pub const HEADER: &str = "header";
    pub const REDIR: &str = "redir";
    pub const REWRITE: &str = "rewrite";
    pub const BASICAUTH: &str = "basicauth";
    pub const FORWARD_AUTH: &str = "forward_auth";
    pub const RATE_LIMIT: &str = "rate_limit";
    pub const LOG: &str = "log";
    pub const HANDLE: &str = "handle";
    pub const HANDLE_PATH: &str = "handle_path";
    pub const ROUTE: &str = "route";
    pub const RESPOND: &str = "respond";
    pub const ERROR: &str = "error";
    pub const TRY_FILES: &str = "try_files";
    pub const PHP_FASTCGI: &str = "php_fastcgi";
    pub const IMPORT: &str = "import";
    pub const VARS: &str = "vars";
    pub const MAP: &str = "map";
    pub const REQUEST_HEADER: &str = "request_header";
    pub const RESPONSE_HEADER: &str = "response_header";
    pub const URI: &str = "uri";
    pub const COPY_RESPONSE: &str = "copy_response";
    pub const COPY_RESPONSE_HEADERS: &str = "copy_response_headers";
}
