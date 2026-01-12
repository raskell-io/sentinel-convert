//! Traefik configuration parser

mod mapping;
mod parser;

pub use parser::TraefikParser;
pub use mapping::map_traefik_to_ir;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Traefik configuration (YAML/TOML format)
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraefikConfig {
    /// Entry points (listeners)
    #[serde(default)]
    pub entry_points: HashMap<String, EntryPoint>,

    /// HTTP configuration
    #[serde(default)]
    pub http: HttpConfig,

    /// TCP configuration (not fully supported)
    #[serde(default)]
    pub tcp: Option<TcpConfig>,

    /// TLS configuration
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

/// Entry point configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryPoint {
    /// Address (e.g., ":80", ":443")
    pub address: Option<String>,

    /// HTTP configuration
    #[serde(default)]
    pub http: Option<EntryPointHttp>,

    /// Transport configuration
    #[serde(default)]
    pub transport: Option<Transport>,
}

/// Entry point HTTP configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryPointHttp {
    /// TLS configuration
    #[serde(default)]
    pub tls: Option<EntryPointTls>,

    /// Redirections
    #[serde(default)]
    pub redirections: Option<Redirections>,
}

/// Entry point TLS
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryPointTls {
    /// Cert resolver
    pub cert_resolver: Option<String>,
    /// Options
    pub options: Option<String>,
}

/// Redirections configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Redirections {
    /// Entry point redirection
    pub entry_point: Option<RedirectEntryPoint>,
}

/// Redirect to entry point
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectEntryPoint {
    pub to: Option<String>,
    pub scheme: Option<String>,
    pub permanent: Option<bool>,
}

/// Transport configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Transport {
    /// Respond timeout
    pub respond_timeout: Option<String>,
    /// Life cycle
    pub life_cycle: Option<LifeCycle>,
}

/// Life cycle configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifeCycle {
    pub request_accept_grace_period: Option<String>,
    pub grace_timeout: Option<String>,
}

/// HTTP configuration section
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpConfig {
    /// Routers
    #[serde(default)]
    pub routers: HashMap<String, Router>,

    /// Services
    #[serde(default)]
    pub services: HashMap<String, Service>,

    /// Middlewares
    #[serde(default)]
    pub middlewares: HashMap<String, Middleware>,
}

/// Router configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Router {
    /// Routing rule
    pub rule: Option<String>,

    /// Entry points
    #[serde(default)]
    pub entry_points: Vec<String>,

    /// Service name
    pub service: Option<String>,

    /// Middlewares
    #[serde(default)]
    pub middlewares: Vec<String>,

    /// Priority
    pub priority: Option<i32>,

    /// TLS configuration
    pub tls: Option<RouterTls>,
}

/// Router TLS configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterTls {
    pub cert_resolver: Option<String>,
    pub domains: Option<Vec<TlsDomain>>,
    pub options: Option<String>,
}

/// TLS domain
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsDomain {
    pub main: Option<String>,
    pub sans: Option<Vec<String>>,
}

/// Service configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// Load balancer configuration
    pub load_balancer: Option<LoadBalancer>,

    /// Weighted configuration
    pub weighted: Option<WeightedService>,

    /// Mirroring configuration
    pub mirroring: Option<MirrorService>,
}

/// Load balancer configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadBalancer {
    /// Servers
    #[serde(default)]
    pub servers: Vec<Server>,

    /// Health check
    pub health_check: Option<HealthCheck>,

    /// Sticky sessions
    pub sticky: Option<Sticky>,

    /// Pass host header
    pub pass_host_header: Option<bool>,

    /// Response forwarding
    pub response_forwarding: Option<ResponseForwarding>,

    /// Servers transport
    pub servers_transport: Option<String>,
}

/// Server endpoint
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    /// URL (e.g., "http://10.0.0.1:8080")
    pub url: Option<String>,
    /// Weight
    pub weight: Option<i32>,
}

/// Health check configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheck {
    pub path: Option<String>,
    pub scheme: Option<String>,
    pub mode: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<i32>,
    pub interval: Option<String>,
    pub timeout: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub follow_redirects: Option<bool>,
}

/// Sticky session configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Sticky {
    pub cookie: Option<StickyCookie>,
}

/// Sticky cookie configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StickyCookie {
    pub name: Option<String>,
    pub secure: Option<bool>,
    pub http_only: Option<bool>,
    pub same_site: Option<String>,
}

/// Response forwarding
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseForwarding {
    pub flush_interval: Option<String>,
}

/// Weighted service
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WeightedService {
    pub services: Option<Vec<WeightedServiceEntry>>,
    pub sticky: Option<Sticky>,
}

/// Weighted service entry
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WeightedServiceEntry {
    pub name: String,
    pub weight: Option<i32>,
}

/// Mirror service
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MirrorService {
    pub service: Option<String>,
    pub mirrors: Option<Vec<MirrorEntry>>,
}

/// Mirror entry
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MirrorEntry {
    pub name: String,
    pub percent: Option<i32>,
}

/// Middleware configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Middleware {
    /// Basic auth
    pub basic_auth: Option<BasicAuth>,

    /// Forward auth
    pub forward_auth: Option<ForwardAuth>,

    /// Rate limit
    pub rate_limit: Option<RateLimit>,

    /// IP white list
    pub ip_white_list: Option<IpWhiteList>,

    /// Headers
    pub headers: Option<Headers>,

    /// Strip prefix
    pub strip_prefix: Option<StripPrefix>,

    /// Add prefix
    pub add_prefix: Option<AddPrefix>,

    /// Redirect scheme
    pub redirect_scheme: Option<RedirectScheme>,

    /// Redirect regex
    pub redirect_regex: Option<RedirectRegex>,

    /// Compress
    pub compress: Option<Compress>,

    /// Retry
    pub retry: Option<Retry>,

    /// Circuit breaker
    pub circuit_breaker: Option<CircuitBreaker>,
}

/// Basic auth middleware
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BasicAuth {
    pub users: Option<Vec<String>>,
    pub users_file: Option<String>,
    pub realm: Option<String>,
    pub remove_header: Option<bool>,
}

/// Forward auth middleware
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardAuth {
    pub address: Option<String>,
    pub tls: Option<ForwardAuthTls>,
    pub trust_forward_header: Option<bool>,
    pub auth_response_headers: Option<Vec<String>>,
    pub auth_request_headers: Option<Vec<String>>,
}

/// Forward auth TLS
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardAuthTls {
    pub ca: Option<String>,
    pub ca_optional: Option<bool>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub insecure_skip_verify: Option<bool>,
}

/// Rate limit middleware
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimit {
    pub average: Option<i64>,
    pub burst: Option<i64>,
    pub period: Option<String>,
    pub source_criterion: Option<SourceCriterion>,
}

/// Source criterion for rate limiting
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceCriterion {
    pub ip_strategy: Option<IpStrategy>,
    pub request_header_name: Option<String>,
    pub request_host: Option<bool>,
}

/// IP strategy
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpStrategy {
    pub depth: Option<i32>,
    pub excluded_ips: Option<Vec<String>>,
}

/// IP white list middleware
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpWhiteList {
    pub source_range: Option<Vec<String>>,
    pub ip_strategy: Option<IpStrategy>,
}

/// Headers middleware
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Headers {
    pub custom_request_headers: Option<HashMap<String, String>>,
    pub custom_response_headers: Option<HashMap<String, String>>,
    pub access_control_allow_credentials: Option<bool>,
    pub access_control_allow_headers: Option<Vec<String>>,
    pub access_control_allow_methods: Option<Vec<String>>,
    pub access_control_allow_origin_list: Option<Vec<String>>,
    pub access_control_expose_headers: Option<Vec<String>>,
    pub access_control_max_age: Option<i64>,
    pub add_vary_header: Option<bool>,
    pub allowed_hosts: Option<Vec<String>>,
    pub hosts_proxy_headers: Option<Vec<String>>,
    pub ssl_redirect: Option<bool>,
    pub ssl_temporary_redirect: Option<bool>,
    pub ssl_host: Option<String>,
    pub ssl_force_host: Option<bool>,
    pub sts_seconds: Option<i64>,
    pub sts_include_subdomains: Option<bool>,
    pub sts_preload: Option<bool>,
    pub force_sts_header: Option<bool>,
    pub frame_deny: Option<bool>,
    pub custom_frame_options_value: Option<String>,
    pub content_type_nosniff: Option<bool>,
    pub browser_xss_filter: Option<bool>,
    pub custom_browser_xss_value: Option<String>,
    pub content_security_policy: Option<String>,
    pub public_key: Option<String>,
    pub referrer_policy: Option<String>,
    pub feature_policy: Option<String>,
    pub permissions_policy: Option<String>,
    pub is_development: Option<bool>,
}

/// Strip prefix middleware
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StripPrefix {
    pub prefixes: Option<Vec<String>>,
    pub force_slash: Option<bool>,
}

/// Add prefix middleware
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddPrefix {
    pub prefix: Option<String>,
}

/// Redirect scheme middleware
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectScheme {
    pub scheme: Option<String>,
    pub port: Option<String>,
    pub permanent: Option<bool>,
}

/// Redirect regex middleware
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectRegex {
    pub regex: Option<String>,
    pub replacement: Option<String>,
    pub permanent: Option<bool>,
}

/// Compress middleware
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Compress {
    pub excluded_content_types: Option<Vec<String>>,
    pub min_response_body_bytes: Option<i64>,
}

/// Retry middleware
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Retry {
    pub attempts: Option<i32>,
    pub initial_interval: Option<String>,
}

/// Circuit breaker middleware
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CircuitBreaker {
    pub expression: Option<String>,
    pub check_period: Option<String>,
    pub fallback_duration: Option<String>,
    pub recovery_duration: Option<String>,
}

/// TCP configuration (stub)
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpConfig {
    pub routers: Option<HashMap<String, serde_json::Value>>,
    pub services: Option<HashMap<String, serde_json::Value>>,
}

/// TLS configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsConfig {
    pub certificates: Option<Vec<Certificate>>,
    pub options: Option<HashMap<String, TlsOptions>>,
    pub stores: Option<HashMap<String, TlsStore>>,
}

/// TLS certificate
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Certificate {
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
}

/// TLS options
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsOptions {
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    pub cipher_suites: Option<Vec<String>>,
    pub curve_preferences: Option<Vec<String>>,
    pub client_auth: Option<ClientAuth>,
    pub sni_strict: Option<bool>,
    pub alpn_protocols: Option<Vec<String>>,
}

/// Client auth
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientAuth {
    pub ca_files: Option<Vec<String>>,
    pub client_auth_type: Option<String>,
}

/// TLS store
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsStore {
    pub default_certificate: Option<Certificate>,
    pub default_generated_cert: Option<DefaultGeneratedCert>,
}

/// Default generated cert
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DefaultGeneratedCert {
    pub resolver: Option<String>,
    pub domain: Option<TlsDomain>,
}
