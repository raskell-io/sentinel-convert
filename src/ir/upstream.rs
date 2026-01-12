//! Upstream/backend configuration types

use super::SourceLocation;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Upstream/backend pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Upstream {
    /// Upstream name/identifier
    pub name: String,
    /// Backend endpoints
    pub endpoints: Vec<Endpoint>,
    /// Load balancing algorithm
    pub load_balancing: LoadBalancing,
    /// Health check configuration
    pub health_check: Option<HealthCheck>,
    /// Circuit breaker configuration
    pub circuit_breaker: Option<CircuitBreaker>,
    /// Connection pool settings
    pub connection_pool: Option<ConnectionPool>,
    /// Timeouts
    pub timeouts: Option<UpstreamTimeouts>,
    /// TLS settings for upstream connections
    pub tls: Option<UpstreamTls>,
    /// Source location for diagnostics
    #[serde(skip)]
    pub source: Option<SourceLocation>,
}

impl Default for Upstream {
    fn default() -> Self {
        Self {
            name: String::new(),
            endpoints: Vec::new(),
            load_balancing: LoadBalancing::default(),
            health_check: None,
            circuit_breaker: None,
            connection_pool: None,
            timeouts: None,
            tls: None,
            source: None,
        }
    }
}

/// Backend endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    /// Address in "host:port" format
    pub address: String,
    /// Weight for weighted load balancing
    pub weight: Option<u32>,
    /// Whether this is a backup server
    pub backup: bool,
    /// Slow start duration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slow_start_ms: Option<u64>,
    /// Maximum connections to this endpoint
    pub max_connections: Option<u32>,
}

impl Default for Endpoint {
    fn default() -> Self {
        Self {
            address: String::new(),
            weight: None,
            backup: false,
            slow_start_ms: None,
            max_connections: None,
        }
    }
}

impl From<String> for Endpoint {
    fn from(address: String) -> Self {
        Self {
            address,
            ..Default::default()
        }
    }
}

impl From<&str> for Endpoint {
    fn from(address: &str) -> Self {
        Self {
            address: address.to_string(),
            ..Default::default()
        }
    }
}

/// Load balancing algorithm
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancing {
    #[default]
    RoundRobin,
    LeastConnections,
    IpHash,
    Random,
    Weighted,
    ConsistentHash {
        key: String,
    },
    PowerOfTwoChoices,
    LeastTokens,
    Adaptive,
}

impl std::fmt::Display for LoadBalancing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RoundRobin => write!(f, "round_robin"),
            Self::LeastConnections => write!(f, "least_connections"),
            Self::IpHash => write!(f, "ip_hash"),
            Self::Random => write!(f, "random"),
            Self::Weighted => write!(f, "weighted"),
            Self::ConsistentHash { .. } => write!(f, "consistent_hash"),
            Self::PowerOfTwoChoices => write!(f, "power_of_two_choices"),
            Self::LeastTokens => write!(f, "least_tokens"),
            Self::Adaptive => write!(f, "adaptive"),
        }
    }
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Health check type
    pub check_type: HealthCheckType,
    /// Check interval in milliseconds
    pub interval_ms: u64,
    /// Check timeout in milliseconds
    pub timeout_ms: u64,
    /// Number of successful checks to mark healthy
    pub healthy_threshold: u32,
    /// Number of failed checks to mark unhealthy
    pub unhealthy_threshold: u32,
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self {
            check_type: HealthCheckType::Http {
                path: "/health".to_string(),
                expected_status: vec![200],
            },
            interval_ms: 10000,
            timeout_ms: 5000,
            healthy_threshold: 2,
            unhealthy_threshold: 3,
        }
    }
}

/// Health check type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum HealthCheckType {
    /// HTTP health check
    Http {
        path: String,
        #[serde(default)]
        expected_status: Vec<u16>,
    },
    /// TCP connection check
    Tcp,
    /// gRPC health check
    Grpc {
        service: Option<String>,
    },
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreaker {
    /// Number of consecutive failures to open circuit
    pub failure_threshold: u32,
    /// Number of successes in half-open to close
    pub success_threshold: u32,
    /// Time to wait before trying half-open (ms)
    pub timeout_ms: u64,
    /// Maximum requests in half-open state
    pub half_open_max_requests: Option<u32>,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            timeout_ms: 30000,
            half_open_max_requests: Some(1),
        }
    }
}

/// Connection pool settings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionPool {
    /// Maximum total connections
    pub max_connections: Option<u32>,
    /// Maximum idle connections
    pub max_idle: Option<u32>,
    /// Idle connection timeout in milliseconds
    pub idle_timeout_ms: Option<u64>,
}

/// Upstream timeout settings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpstreamTimeouts {
    /// Connect timeout in milliseconds
    pub connect_ms: Option<u64>,
    /// Request timeout in milliseconds
    pub request_ms: Option<u64>,
    /// Read timeout in milliseconds
    pub read_ms: Option<u64>,
}

/// Upstream TLS settings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpstreamTls {
    /// Enable TLS to upstream
    pub enabled: bool,
    /// Verify server certificate
    pub verify: bool,
    /// Client certificate path
    pub cert_path: Option<std::path::PathBuf>,
    /// Client key path
    pub key_path: Option<std::path::PathBuf>,
    /// CA certificate path
    pub ca_path: Option<std::path::PathBuf>,
    /// SNI hostname
    pub sni: Option<String>,
}
