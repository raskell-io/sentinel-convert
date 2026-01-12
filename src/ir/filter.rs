//! Filter configuration types

use super::SourceLocation;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Filter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Filter {
    /// Filter name/identifier
    pub name: String,
    /// Filter type
    pub filter_type: FilterType,
    /// Filter-specific configuration
    pub config: FilterConfig,
    /// Source location for diagnostics
    #[serde(skip)]
    pub source: Option<SourceLocation>,
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            name: String::new(),
            filter_type: FilterType::Custom,
            config: FilterConfig::Custom(HashMap::new()),
            source: None,
        }
    }
}

/// Filter type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterType {
    Headers,
    Cors,
    Compression,
    RequestId,
    Logging,
    Agent,
    Custom,
}

impl std::fmt::Display for FilterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Headers => write!(f, "headers"),
            Self::Cors => write!(f, "cors"),
            Self::Compression => write!(f, "compression"),
            Self::RequestId => write!(f, "request_id"),
            Self::Logging => write!(f, "logging"),
            Self::Agent => write!(f, "agent"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

/// Filter-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FilterConfig {
    Headers(HeadersFilterConfig),
    Cors(CorsFilterConfig),
    Compression(CompressionFilterConfig),
    RequestId(RequestIdFilterConfig),
    Logging(LoggingFilterConfig),
    Agent(AgentFilterConfig),
    Custom(HashMap<String, serde_json::Value>),
}

/// Headers filter configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeadersFilterConfig {
    /// Headers to add to requests
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_add: Vec<HeaderOperation>,
    /// Headers to remove from requests
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_remove: Vec<String>,
    /// Headers to add to responses
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_add: Vec<HeaderOperation>,
    /// Headers to remove from responses
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_remove: Vec<String>,
}

/// Header operation (set/add)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderOperation {
    /// Header name
    pub name: String,
    /// Header value
    pub value: String,
    /// Operation type (set replaces, add appends)
    #[serde(default)]
    pub operation: HeaderOperationType,
}

/// Header operation type
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HeaderOperationType {
    #[default]
    Set,
    Add,
}

/// CORS filter configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CorsFilterConfig {
    /// Allowed origins (supports wildcards)
    pub allowed_origins: Vec<String>,
    /// Allowed HTTP methods
    pub allowed_methods: Vec<String>,
    /// Allowed headers
    pub allowed_headers: Vec<String>,
    /// Headers to expose to client
    pub exposed_headers: Vec<String>,
    /// Max age for preflight cache (seconds)
    pub max_age_secs: Option<u64>,
    /// Allow credentials
    pub allow_credentials: bool,
}

/// Compression filter configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompressionFilterConfig {
    /// Compression algorithms to use
    pub algorithms: Vec<CompressionAlgorithm>,
    /// Minimum response size to compress (bytes)
    pub min_size: Option<u64>,
    /// MIME types to compress
    pub mime_types: Option<Vec<String>>,
    /// Compression level (1-9)
    pub level: Option<u8>,
}

/// Compression algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompressionAlgorithm {
    Gzip,
    Brotli,
    Zstd,
    Deflate,
}

impl std::fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gzip => write!(f, "gzip"),
            Self::Brotli => write!(f, "br"),
            Self::Zstd => write!(f, "zstd"),
            Self::Deflate => write!(f, "deflate"),
        }
    }
}

/// Request ID filter configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestIdFilterConfig {
    /// Header name for request ID
    pub header_name: Option<String>,
    /// Whether to generate if not present
    pub generate: bool,
}

/// Logging filter configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoggingFilterConfig {
    /// Log format
    pub format: Option<String>,
    /// Fields to include
    pub fields: Vec<String>,
}

/// Agent filter configuration (references an agent)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentFilterConfig {
    /// Agent name to invoke
    pub agent: String,
    /// Override timeout (ms)
    pub timeout_ms: Option<u64>,
    /// Override failure mode
    pub failure_mode: Option<super::FailureMode>,
}
