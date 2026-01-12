//! Route configuration types

use super::SourceLocation;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Route configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    /// Route name/identifier
    pub name: String,
    /// Priority (higher = matched first)
    pub priority: Option<i32>,
    /// Match conditions
    pub matchers: Vec<RouteMatcher>,
    /// Action to take when matched
    pub action: RouteAction,
    /// Middleware/filters to apply
    pub middleware: Vec<MiddlewareRef>,
    /// Route metadata
    pub metadata: RouteMetadata,
    /// Source location for diagnostics
    #[serde(skip)]
    pub source: Option<SourceLocation>,
}

impl Default for Route {
    fn default() -> Self {
        Self {
            name: String::new(),
            priority: None,
            matchers: Vec::new(),
            action: RouteAction::default(),
            middleware: Vec::new(),
            metadata: RouteMetadata::default(),
            source: None,
        }
    }
}

/// Route matching condition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RouteMatcher {
    /// Match by hostname(s)
    Host(HostMatch),
    /// Match by path
    Path(PathMatch),
    /// Match by HTTP method(s)
    Method { methods: Vec<HttpMethod> },
    /// Match by header
    Header(HeaderMatch),
    /// Match by query parameter
    Query(QueryMatch),
    /// Match by source IP/CIDR
    SourceIp(IpMatch),
    /// Logical AND of matchers
    And { matchers: Vec<RouteMatcher> },
    /// Logical OR of matchers
    Or { matchers: Vec<RouteMatcher> },
}

/// Host matching
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostMatch {
    /// Host patterns (supports wildcards: "*.example.com")
    pub patterns: Vec<String>,
    /// Whether to match exactly (no wildcards)
    pub exact: bool,
}

/// Path matching
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathMatch {
    /// Path pattern
    pub pattern: String,
    /// Match type
    pub match_type: PathMatchType,
}

/// Path match type
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathMatchType {
    #[default]
    Prefix,
    Exact,
    Regex,
    Glob,
}

/// HTTP method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Connect,
    Trace,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get => write!(f, "GET"),
            Self::Post => write!(f, "POST"),
            Self::Put => write!(f, "PUT"),
            Self::Delete => write!(f, "DELETE"),
            Self::Patch => write!(f, "PATCH"),
            Self::Head => write!(f, "HEAD"),
            Self::Options => write!(f, "OPTIONS"),
            Self::Connect => write!(f, "CONNECT"),
            Self::Trace => write!(f, "TRACE"),
        }
    }
}

/// Header matching
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeaderMatch {
    /// Header name
    pub name: String,
    /// Value pattern (regex or exact)
    pub pattern: String,
    /// Whether to use regex matching
    pub regex: bool,
}

/// Query parameter matching
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueryMatch {
    /// Parameter name
    pub name: String,
    /// Value pattern
    pub pattern: String,
    /// Whether to use regex matching
    pub regex: bool,
}

/// IP/CIDR matching
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpMatch {
    /// IP addresses or CIDR ranges
    pub cidrs: Vec<String>,
    /// Whether this is an allow (true) or deny (false) rule
    pub allow: bool,
}

/// Route action
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RouteAction {
    /// Forward to upstream
    Forward {
        upstream: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        path_rewrite: Option<PathRewrite>,
        #[serde(skip_serializing_if = "Option::is_none")]
        host_rewrite: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
    },
    /// HTTP redirect
    Redirect {
        url: String,
        #[serde(default = "default_redirect_status")]
        status_code: u16,
        #[serde(default)]
        preserve_path: bool,
    },
    /// Return fixed response
    FixedResponse {
        status_code: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        body: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        headers: Vec<(String, String)>,
    },
    /// Serve static files
    Static {
        root: PathBuf,
        #[serde(skip_serializing_if = "Option::is_none")]
        index: Option<Vec<String>>,
        #[serde(default)]
        directory_listing: bool,
    },
}

fn default_redirect_status() -> u16 {
    302
}

impl Default for RouteAction {
    fn default() -> Self {
        Self::Forward {
            upstream: String::new(),
            path_rewrite: None,
            host_rewrite: None,
            timeout_ms: None,
        }
    }
}

/// Path rewrite rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathRewrite {
    /// Pattern to match
    pub pattern: String,
    /// Replacement string
    pub replacement: String,
    /// Whether pattern is regex
    pub regex: bool,
}

/// Middleware reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiddlewareRef {
    /// Middleware/filter name
    pub name: String,
    /// Whether this middleware is required
    pub required: bool,
}

impl From<String> for MiddlewareRef {
    fn from(name: String) -> Self {
        Self {
            name,
            required: true,
        }
    }
}

impl From<&str> for MiddlewareRef {
    fn from(name: &str) -> Self {
        Self {
            name: name.to_string(),
            required: true,
        }
    }
}

/// Route metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteMetadata {
    /// Description/comment
    pub description: Option<String>,
    /// Tags for organization
    pub tags: Vec<String>,
    /// Whether this route requires authentication (detected)
    pub requires_auth: bool,
    /// Detected rate limit requirements
    pub rate_limit_hint: Option<RateLimitHint>,
}

/// Rate limit hint from detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitHint {
    /// Requests per second
    pub requests_per_second: Option<u32>,
    /// Burst size
    pub burst: Option<u32>,
    /// Rate limit key
    pub key: RateLimitKey,
}

/// Rate limit key type
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKey {
    #[default]
    SourceIp,
    Header(String),
    User,
    Global,
}
