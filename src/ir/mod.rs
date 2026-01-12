//! Intermediate Representation types for proxy configuration
//!
//! All parsers produce these IR types, enabling format-agnostic
//! agent detection and KDL emission.

mod agent;
mod filter;
mod listener;
mod route;
mod upstream;

pub use agent::*;
pub use filter::*;
pub use listener::*;
pub use route::*;
pub use upstream::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Source configuration format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceFormat {
    Nginx,
    Apache,
    HAProxy,
    Traefik,
    Caddy,
    Envoy,
}

impl std::fmt::Display for SourceFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nginx => write!(f, "nginx"),
            Self::Apache => write!(f, "apache"),
            Self::HAProxy => write!(f, "haproxy"),
            Self::Traefik => write!(f, "traefik"),
            Self::Caddy => write!(f, "caddy"),
            Self::Envoy => write!(f, "envoy"),
        }
    }
}

/// Complete conversion result
#[derive(Debug, Clone)]
pub struct ConversionResult {
    /// Source format that was parsed
    pub source_format: SourceFormat,
    /// Original file path(s)
    pub source_files: Vec<PathBuf>,
    /// The converted configuration
    pub config: SentinelConfig,
    /// Generated KDL output
    pub kdl_output: String,
    /// Conversion diagnostics
    pub diagnostics: Diagnostics,
}

/// Complete Sentinel configuration in IR form
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SentinelConfig {
    /// System/server configuration
    pub system: SystemConfig,
    /// Listeners (ports/bindings)
    pub listeners: Vec<Listener>,
    /// Routes (request routing rules)
    pub routes: Vec<Route>,
    /// Upstreams (backend pools)
    pub upstreams: HashMap<String, Upstream>,
    /// Named filters
    pub filters: HashMap<String, Filter>,
    /// Agents (WAF, auth, rate-limit, custom)
    pub agents: Vec<Agent>,
    /// Global limits
    pub limits: Option<LimitsConfig>,
    /// Cache configuration
    pub cache: Option<CacheConfig>,
    /// Observability settings
    pub observability: Option<ObservabilityConfig>,
}

/// System/server configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemConfig {
    /// Number of worker threads (0 = auto)
    pub worker_threads: Option<u32>,
    /// Maximum concurrent connections
    pub max_connections: Option<u32>,
    /// Graceful shutdown timeout in seconds
    pub graceful_shutdown_secs: Option<u32>,
}

/// Global limits configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Maximum header size in bytes
    pub max_header_size: Option<u64>,
    /// Maximum number of headers
    pub max_header_count: Option<u32>,
    /// Maximum body size in bytes
    pub max_body_size: Option<u64>,
}

/// Cache configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Whether caching is enabled
    pub enabled: bool,
    /// Cache backend type
    pub backend: CacheBackend,
    /// Maximum cache size in bytes
    pub max_size: Option<u64>,
}

/// Cache backend type
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CacheBackend {
    #[default]
    Memory,
    Disk,
    Hybrid,
}

/// Observability configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Metrics configuration
    pub metrics: Option<MetricsConfig>,
    /// Logging configuration
    pub logging: Option<LoggingConfig>,
    /// Tracing configuration
    pub tracing: Option<TracingConfig>,
}

/// Metrics configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub address: Option<String>,
    pub path: Option<String>,
}

/// Logging configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: Option<String>,
    pub format: Option<String>,
    pub access_log: Option<AccessLogConfig>,
}

/// Access log configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessLogConfig {
    pub enabled: bool,
    pub file: Option<PathBuf>,
}

/// Tracing configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TracingConfig {
    pub enabled: bool,
    pub backend: Option<String>,
    pub endpoint: Option<String>,
}

/// Conversion diagnostics and warnings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Diagnostics {
    /// Successfully converted items
    pub converted: Vec<ConvertedItem>,
    /// Items that couldn't be fully converted
    pub warnings: Vec<ConversionWarning>,
    /// Items that were completely skipped
    pub skipped: Vec<SkippedItem>,
    /// Detected patterns that suggest agent usage
    pub agent_suggestions: Vec<AgentSuggestion>,
}

/// Successfully converted item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvertedItem {
    pub item_type: String,
    pub name: String,
    pub source_location: Option<SourceLocation>,
}

/// Conversion warning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversionWarning {
    pub severity: Severity,
    pub source_location: Option<SourceLocation>,
    pub source_directive: String,
    pub message: String,
    pub suggestion: Option<String>,
}

/// Warning severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

/// Skipped item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedItem {
    pub directive: String,
    pub reason: String,
    pub source_location: Option<SourceLocation>,
}

/// Source location reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: PathBuf,
    pub line: usize,
    pub column: Option<usize>,
}

impl SourceLocation {
    pub fn new(file: PathBuf, line: usize) -> Self {
        Self {
            file,
            line,
            column: None,
        }
    }

    pub fn with_column(mut self, column: usize) -> Self {
        self.column = Some(column);
        self
    }
}

/// Agent suggestion from detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSuggestion {
    pub agent_type: AgentType,
    pub confidence: Confidence,
    pub reason: String,
    pub routes: Vec<String>,
    pub extracted_config: Option<AgentConfig>,
    pub source_locations: Vec<SourceLocation>,
}

impl Default for AgentSuggestion {
    fn default() -> Self {
        Self {
            agent_type: AgentType::Custom,
            confidence: Confidence::Low,
            reason: String::new(),
            routes: Vec::new(),
            extracted_config: None,
            source_locations: Vec::new(),
        }
    }
}

/// Detection confidence level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}
