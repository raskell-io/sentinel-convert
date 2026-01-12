//! Agent configuration types

use super::{Confidence, RateLimitKey, SourceLocation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    /// Agent name/identifier
    pub name: String,
    /// Agent type
    pub agent_type: AgentType,
    /// Agent-specific configuration
    pub config: AgentConfig,
    /// Routes this agent applies to
    pub routes: Vec<String>,
    /// How this agent was detected
    pub detection: AgentDetection,
    /// Source location for diagnostics
    #[serde(skip)]
    pub source: Option<SourceLocation>,
}

impl Default for Agent {
    fn default() -> Self {
        Self {
            name: String::new(),
            agent_type: AgentType::Custom,
            config: AgentConfig::Custom(CustomAgentConfig::default()),
            routes: Vec::new(),
            detection: AgentDetection::Explicit,
            source: None,
        }
    }
}

/// Agent type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentType {
    Waf,
    Auth,
    RateLimit,
    Custom,
}

impl std::fmt::Display for AgentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Waf => write!(f, "waf"),
            Self::Auth => write!(f, "auth"),
            Self::RateLimit => write!(f, "rate-limit"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

/// Agent-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentConfig {
    Waf(WafAgentConfig),
    Auth(AuthAgentConfig),
    RateLimit(RateLimitAgentConfig),
    Custom(CustomAgentConfig),
}

/// WAF agent configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WafAgentConfig {
    /// Unix socket path
    pub socket_path: PathBuf,
    /// WAF mode
    pub mode: WafMode,
    /// Ruleset identifier
    pub ruleset: Option<String>,
    /// Paranoia level (1-4)
    pub paranoia_level: Option<u8>,
    /// Timeout in milliseconds
    pub timeout_ms: Option<u64>,
    /// Failure mode
    pub failure_mode: FailureMode,
    /// Extracted rules from source config
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extracted_rules: Vec<ExtractedWafRule>,
}

/// WAF mode
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WafMode {
    /// Detect but don't block
    #[default]
    Detection,
    /// Actively block threats
    Prevention,
}

/// Extracted WAF rule from source config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedWafRule {
    /// Rule type
    pub rule_type: WafRuleType,
    /// Pattern or value
    pub pattern: String,
    /// Action to take
    pub action: WafAction,
    /// Rule description
    pub description: Option<String>,
}

/// WAF rule type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafRuleType {
    SqlInjection,
    Xss,
    PathTraversal,
    CommandInjection,
    HeaderInjection,
    RequestSize,
    RateLimit,
    IpBlacklist,
    IpWhitelist,
    UserAgent,
    Referer,
    Custom(String),
}

/// WAF action
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WafAction {
    #[default]
    Block,
    Allow,
    Log,
    Challenge,
}

/// Auth agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAgentConfig {
    /// Unix socket path
    pub socket_path: PathBuf,
    /// Authentication type
    pub auth_type: AuthType,
    /// Type-specific configuration
    pub type_config: AuthTypeConfig,
    /// Timeout in milliseconds
    pub timeout_ms: Option<u64>,
    /// Failure mode
    pub failure_mode: FailureMode,
}

impl Default for AuthAgentConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/run/sentinel/auth.sock"),
            auth_type: AuthType::Custom,
            type_config: AuthTypeConfig::Unknown,
            timeout_ms: Some(100),
            failure_mode: FailureMode::Closed,
        }
    }
}

/// Authentication type
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    Basic,
    Jwt,
    OAuth2,
    ApiKey,
    Ldap,
    #[default]
    Custom,
}

/// Auth type-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "config_type", rename_all = "snake_case")]
pub enum AuthTypeConfig {
    Basic {
        realm: Option<String>,
        htpasswd_path: Option<PathBuf>,
    },
    Jwt {
        issuer: Option<String>,
        audience: Option<String>,
        jwks_url: Option<String>,
    },
    OAuth2 {
        provider: Option<String>,
        client_id: Option<String>,
        auth_url: Option<String>,
        token_url: Option<String>,
    },
    ApiKey {
        header: Option<String>,
        query_param: Option<String>,
    },
    Unknown,
}

impl Default for AuthTypeConfig {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Rate limit agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitAgentConfig {
    /// Unix socket path
    pub socket_path: PathBuf,
    /// Rate limit rules
    pub limits: Vec<RateLimitRule>,
    /// Timeout in milliseconds
    pub timeout_ms: Option<u64>,
    /// Failure mode
    pub failure_mode: FailureMode,
}

impl Default for RateLimitAgentConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/run/sentinel/ratelimit.sock"),
            limits: Vec::new(),
            timeout_ms: Some(50),
            failure_mode: FailureMode::Open,
        }
    }
}

/// Rate limit rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    /// Rule name
    pub name: String,
    /// Key to rate limit by
    pub key: RateLimitKey,
    /// Requests per period
    pub rate: u32,
    /// Period in milliseconds
    pub period_ms: u64,
    /// Burst size
    pub burst: Option<u32>,
}

impl Default for RateLimitRule {
    fn default() -> Self {
        Self {
            name: String::new(),
            key: RateLimitKey::SourceIp,
            rate: 100,
            period_ms: 1000,
            burst: None,
        }
    }
}

/// Custom agent configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CustomAgentConfig {
    /// Unix socket path
    pub socket_path: PathBuf,
    /// Arbitrary configuration data
    pub config_data: HashMap<String, serde_json::Value>,
    /// Timeout in milliseconds
    pub timeout_ms: Option<u64>,
    /// Failure mode
    pub failure_mode: FailureMode,
}

/// Failure mode for agents
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailureMode {
    /// Allow request if agent fails
    #[default]
    Open,
    /// Block request if agent fails
    Closed,
}

impl std::fmt::Display for FailureMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// How an agent was detected
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum AgentDetection {
    /// Explicitly configured in source
    Explicit,
    /// Detected via pattern matching
    Inferred {
        confidence: Confidence,
        patterns_matched: Vec<String>,
    },
    /// Suggested but not automatically added
    Suggested { reason: String },
}

impl Default for AgentDetection {
    fn default() -> Self {
        Self::Explicit
    }
}
