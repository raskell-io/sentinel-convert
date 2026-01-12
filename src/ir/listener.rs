//! Listener configuration types

use super::SourceLocation;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Network listener configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listener {
    /// Listener name/identifier
    pub name: String,
    /// Bind address(es)
    pub bind: BindAddress,
    /// Protocol type
    pub protocol: Protocol,
    /// TLS configuration
    pub tls: Option<TlsConfig>,
    /// Additional options
    pub options: ListenerOptions,
    /// Source location for diagnostics
    #[serde(skip)]
    pub source: Option<SourceLocation>,
}

impl Default for Listener {
    fn default() -> Self {
        Self {
            name: String::new(),
            bind: BindAddress::Single("0.0.0.0:80".to_string()),
            protocol: Protocol::Http,
            tls: None,
            options: ListenerOptions::default(),
            source: None,
        }
    }
}

/// Bind address specification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BindAddress {
    /// Single address: "0.0.0.0:443"
    Single(String),
    /// Multiple addresses
    Multiple(Vec<String>),
    /// Unix socket path
    Unix(PathBuf),
}

impl Default for BindAddress {
    fn default() -> Self {
        Self::Single("0.0.0.0:80".to_string())
    }
}

/// Protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Http,
    Https,
    H2,
    H2c,
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::Https => write!(f, "https"),
            Self::H2 => write!(f, "h2"),
            Self::H2c => write!(f, "h2c"),
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
        }
    }
}

/// TLS configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Certificate file path
    pub cert_path: Option<PathBuf>,
    /// Private key file path
    pub key_path: Option<PathBuf>,
    /// CA certificate file path (for client auth)
    pub ca_path: Option<PathBuf>,
    /// Minimum TLS version
    pub min_version: Option<TlsVersion>,
    /// Maximum TLS version
    pub max_version: Option<TlsVersion>,
    /// Cipher suites
    pub ciphers: Option<Vec<String>>,
    /// ALPN protocols
    pub alpn: Option<Vec<String>>,
    /// Client authentication settings
    pub client_auth: Option<ClientAuth>,
}

/// TLS version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsVersion {
    #[serde(rename = "1.0")]
    Tls10,
    #[serde(rename = "1.1")]
    Tls11,
    #[serde(rename = "1.2")]
    Tls12,
    #[serde(rename = "1.3")]
    Tls13,
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls10 => write!(f, "1.0"),
            Self::Tls11 => write!(f, "1.1"),
            Self::Tls12 => write!(f, "1.2"),
            Self::Tls13 => write!(f, "1.3"),
        }
    }
}

/// Client authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAuth {
    /// Whether client auth is required
    pub required: bool,
    /// CA certificate path for verification
    pub ca_path: PathBuf,
}

/// Additional listener options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListenerOptions {
    /// Enable PROXY protocol
    pub proxy_protocol: Option<bool>,
    /// Keepalive timeout
    #[serde(with = "humantime_serde", default)]
    pub keepalive_timeout: Option<Duration>,
    /// Request timeout
    #[serde(with = "humantime_serde", default)]
    pub request_timeout: Option<Duration>,
    /// Maximum concurrent connections
    pub max_connections: Option<u32>,
}

mod humantime_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match duration {
            Some(d) => serializer.serialize_some(&humantime::format_duration(*d).to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        match s {
            Some(s) => humantime::parse_duration(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}
