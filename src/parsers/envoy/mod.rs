//! Envoy proxy configuration parser
//!
//! Parses Envoy's YAML/JSON configuration format including:
//! - Static resources (listeners, clusters)
//! - HTTP connection manager filters
//! - Route configurations
//! - External authorization (ext_authz)
//! - Rate limiting

mod mapping;
mod parser;

pub use mapping::map_envoy_to_ir;
pub use parser::EnvoyParser;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Root Envoy configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct EnvoyConfig {
    /// Static resources (listeners, clusters)
    #[serde(default)]
    pub static_resources: StaticResources,

    /// Admin interface configuration
    #[serde(default)]
    pub admin: Option<Admin>,

    /// Node information
    #[serde(default)]
    pub node: Option<Node>,
}

/// Static resources configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct StaticResources {
    /// Listeners
    #[serde(default)]
    pub listeners: Vec<Listener>,

    /// Clusters (upstreams)
    #[serde(default)]
    pub clusters: Vec<Cluster>,

    /// Secrets
    #[serde(default)]
    pub secrets: Vec<Secret>,
}

/// Listener configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Listener {
    /// Listener name
    pub name: Option<String>,

    /// Address to bind
    pub address: Option<Address>,

    /// Filter chains
    #[serde(default)]
    pub filter_chains: Vec<FilterChain>,

    /// Listener filters
    #[serde(default)]
    pub listener_filters: Vec<ListenerFilter>,

    /// Per connection buffer limit
    pub per_connection_buffer_limit_bytes: Option<u64>,
}

/// Address configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Address {
    /// Socket address
    pub socket_address: Option<SocketAddress>,

    /// Pipe (Unix socket)
    pub pipe: Option<Pipe>,
}

/// Socket address
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SocketAddress {
    /// IP address
    pub address: Option<String>,

    /// Port value
    pub port_value: Option<u16>,

    /// Named port
    pub named_port: Option<String>,

    /// Protocol (TCP/UDP)
    pub protocol: Option<String>,
}

/// Unix pipe address
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Pipe {
    /// Path to Unix socket
    pub path: Option<String>,

    /// Mode
    pub mode: Option<u32>,
}

/// Filter chain configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FilterChain {
    /// Filter chain match
    pub filter_chain_match: Option<FilterChainMatch>,

    /// Filters
    #[serde(default)]
    pub filters: Vec<Filter>,

    /// Transport socket (TLS)
    pub transport_socket: Option<TransportSocket>,

    /// Name
    pub name: Option<String>,
}

/// Filter chain match criteria
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FilterChainMatch {
    /// Server names (SNI)
    #[serde(default)]
    pub server_names: Vec<String>,

    /// Transport protocol
    pub transport_protocol: Option<String>,

    /// Application protocols (ALPN)
    #[serde(default)]
    pub application_protocols: Vec<String>,

    /// Source prefix ranges
    #[serde(default)]
    pub source_prefix_ranges: Vec<CidrRange>,

    /// Destination port
    pub destination_port: Option<u16>,
}

/// CIDR range
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CidrRange {
    /// Address prefix
    pub address_prefix: Option<String>,

    /// Prefix length
    pub prefix_len: Option<u32>,
}

/// Network filter
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Filter {
    /// Filter name
    pub name: Option<String>,

    /// Typed config
    pub typed_config: Option<TypedConfig>,
}

/// Typed configuration wrapper
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TypedConfig {
    /// Type URL
    #[serde(rename = "@type")]
    pub type_url: Option<String>,

    /// HTTP connection manager config
    #[serde(flatten)]
    pub config: Option<serde_json::Value>,
}

/// HTTP connection manager configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct HttpConnectionManager {
    /// Stat prefix
    pub stat_prefix: Option<String>,

    /// Codec type
    pub codec_type: Option<String>,

    /// Route config
    pub route_config: Option<RouteConfiguration>,

    /// RDS config
    pub rds: Option<Rds>,

    /// HTTP filters
    #[serde(default)]
    pub http_filters: Vec<HttpFilter>,

    /// Access log
    #[serde(default)]
    pub access_log: Vec<AccessLog>,

    /// Use remote address
    pub use_remote_address: Option<bool>,

    /// XFF num trusted hops
    pub xff_num_trusted_hops: Option<u32>,

    /// HTTP2 protocol options
    pub http2_protocol_options: Option<Http2ProtocolOptions>,

    /// Stream idle timeout
    pub stream_idle_timeout: Option<String>,

    /// Request timeout
    pub request_timeout: Option<String>,
}

/// Route configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RouteConfiguration {
    /// Name
    pub name: Option<String>,

    /// Virtual hosts
    #[serde(default)]
    pub virtual_hosts: Vec<VirtualHost>,
}

/// Virtual host
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct VirtualHost {
    /// Name
    pub name: Option<String>,

    /// Domains
    #[serde(default)]
    pub domains: Vec<String>,

    /// Routes
    #[serde(default)]
    pub routes: Vec<Route>,

    /// Rate limits
    #[serde(default)]
    pub rate_limits: Vec<RateLimitAction>,

    /// Request headers to add
    #[serde(default)]
    pub request_headers_to_add: Vec<HeaderValueOption>,

    /// Response headers to add
    #[serde(default)]
    pub response_headers_to_add: Vec<HeaderValueOption>,

    /// Request headers to remove
    #[serde(default)]
    pub request_headers_to_remove: Vec<String>,

    /// Response headers to remove
    #[serde(default)]
    pub response_headers_to_remove: Vec<String>,

    /// CORS policy
    pub cors: Option<CorsPolicy>,

    /// Retry policy
    pub retry_policy: Option<RetryPolicy>,
}

/// Route definition
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Route {
    /// Name
    pub name: Option<String>,

    /// Match criteria
    #[serde(rename = "match")]
    pub route_match: Option<RouteMatch>,

    /// Route action
    pub route: Option<RouteAction>,

    /// Redirect action
    pub redirect: Option<RedirectAction>,

    /// Direct response action
    pub direct_response: Option<DirectResponseAction>,
}

/// Route match criteria
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RouteMatch {
    /// Prefix match
    pub prefix: Option<String>,

    /// Exact path match
    pub path: Option<String>,

    /// Regex match
    pub safe_regex: Option<RegexMatch>,

    /// Headers to match
    #[serde(default)]
    pub headers: Vec<HeaderMatcher>,

    /// Query parameters to match
    #[serde(default)]
    pub query_parameters: Vec<QueryParameterMatcher>,
}

/// Regex match
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RegexMatch {
    /// Google RE2 regex
    pub google_re2: Option<GoogleRe2>,

    /// Regex pattern
    pub regex: Option<String>,
}

/// Google RE2 config
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct GoogleRe2 {
    pub max_program_size: Option<u32>,
}

/// Header matcher
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct HeaderMatcher {
    /// Header name
    pub name: Option<String>,

    /// Exact match
    pub exact_match: Option<String>,

    /// Prefix match
    pub prefix_match: Option<String>,

    /// Suffix match
    pub suffix_match: Option<String>,

    /// Regex match
    pub safe_regex_match: Option<RegexMatch>,

    /// Present match
    pub present_match: Option<bool>,

    /// Invert match
    pub invert_match: Option<bool>,
}

/// Query parameter matcher
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct QueryParameterMatcher {
    /// Parameter name
    pub name: Option<String>,

    /// String match
    pub string_match: Option<StringMatch>,

    /// Present match
    pub present_match: Option<bool>,
}

/// String match
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct StringMatch {
    /// Exact match
    pub exact: Option<String>,

    /// Prefix match
    pub prefix: Option<String>,

    /// Suffix match
    pub suffix: Option<String>,

    /// Regex match
    pub safe_regex: Option<RegexMatch>,
}

/// Route action
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RouteAction {
    /// Cluster to route to
    pub cluster: Option<String>,

    /// Weighted clusters
    pub weighted_clusters: Option<WeightedCluster>,

    /// Cluster header
    pub cluster_header: Option<String>,

    /// Prefix rewrite
    pub prefix_rewrite: Option<String>,

    /// Regex rewrite
    pub regex_rewrite: Option<RegexRewrite>,

    /// Host rewrite
    pub host_rewrite_literal: Option<String>,

    /// Auto host rewrite
    pub auto_host_rewrite: Option<bool>,

    /// Timeout
    pub timeout: Option<String>,

    /// Idle timeout
    pub idle_timeout: Option<String>,

    /// Retry policy
    pub retry_policy: Option<RetryPolicy>,

    /// Rate limits
    #[serde(default)]
    pub rate_limits: Vec<RateLimitAction>,

    /// Hash policy (for consistent hashing)
    #[serde(default)]
    pub hash_policy: Vec<HashPolicy>,
}

/// Weighted cluster configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct WeightedCluster {
    /// Clusters
    #[serde(default)]
    pub clusters: Vec<ClusterWeight>,

    /// Total weight
    pub total_weight: Option<u32>,
}

/// Cluster weight
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ClusterWeight {
    /// Cluster name
    pub name: Option<String>,

    /// Weight
    pub weight: Option<u32>,
}

/// Regex rewrite
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RegexRewrite {
    /// Pattern
    pub pattern: Option<RegexMatch>,

    /// Substitution
    pub substitution: Option<String>,
}

/// Retry policy
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RetryPolicy {
    /// Retry on
    pub retry_on: Option<String>,

    /// Num retries
    pub num_retries: Option<u32>,

    /// Per try timeout
    pub per_try_timeout: Option<String>,

    /// Retry host predicate
    #[serde(default)]
    pub retry_host_predicate: Vec<RetryHostPredicate>,
}

/// Retry host predicate
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RetryHostPredicate {
    pub name: Option<String>,
}

/// Rate limit action
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RateLimitAction {
    /// Stage
    pub stage: Option<u32>,

    /// Disable key
    pub disable_key: Option<String>,

    /// Actions
    #[serde(default)]
    pub actions: Vec<RateLimitActionEntry>,
}

/// Rate limit action entry
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RateLimitActionEntry {
    /// Source cluster
    pub source_cluster: Option<serde_json::Value>,

    /// Destination cluster
    pub destination_cluster: Option<serde_json::Value>,

    /// Request headers
    pub request_headers: Option<RequestHeaderAction>,

    /// Remote address
    pub remote_address: Option<serde_json::Value>,

    /// Generic key
    pub generic_key: Option<GenericKeyAction>,
}

/// Request header action for rate limiting
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RequestHeaderAction {
    /// Header name
    pub header_name: Option<String>,

    /// Descriptor key
    pub descriptor_key: Option<String>,

    /// Skip if absent
    pub skip_if_absent: Option<bool>,
}

/// Generic key action
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct GenericKeyAction {
    /// Descriptor key
    pub descriptor_key: Option<String>,

    /// Descriptor value
    pub descriptor_value: Option<String>,
}

/// Hash policy
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct HashPolicy {
    /// Header
    pub header: Option<HashPolicyHeader>,

    /// Cookie
    pub cookie: Option<HashPolicyCookie>,

    /// Connection properties
    pub connection_properties: Option<ConnectionProperties>,
}

/// Hash policy header
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct HashPolicyHeader {
    pub header_name: Option<String>,
}

/// Hash policy cookie
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct HashPolicyCookie {
    pub name: Option<String>,
    pub ttl: Option<String>,
    pub path: Option<String>,
}

/// Connection properties
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ConnectionProperties {
    pub source_ip: Option<bool>,
}

/// Redirect action
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedirectAction {
    /// HTTPS redirect
    pub https_redirect: Option<bool>,

    /// Scheme redirect
    pub scheme_redirect: Option<String>,

    /// Host redirect
    pub host_redirect: Option<String>,

    /// Port redirect
    pub port_redirect: Option<u16>,

    /// Path redirect
    pub path_redirect: Option<String>,

    /// Prefix rewrite
    pub prefix_rewrite: Option<String>,

    /// Response code
    pub response_code: Option<String>,

    /// Strip query
    pub strip_query: Option<bool>,
}

/// Direct response action
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectResponseAction {
    /// Status code
    pub status: Option<u32>,

    /// Response body
    pub body: Option<DataSource>,
}

/// Data source
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DataSource {
    /// Inline string
    pub inline_string: Option<String>,

    /// Inline bytes
    pub inline_bytes: Option<String>,

    /// Filename
    pub filename: Option<String>,
}

/// Header value option
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct HeaderValueOption {
    /// Header
    pub header: Option<HeaderValue>,

    /// Append
    pub append: Option<bool>,
}

/// Header value
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct HeaderValue {
    /// Key
    pub key: Option<String>,

    /// Value
    pub value: Option<String>,
}

/// CORS policy
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CorsPolicy {
    /// Allow origin string match
    #[serde(default)]
    pub allow_origin_string_match: Vec<StringMatch>,

    /// Allow methods
    pub allow_methods: Option<String>,

    /// Allow headers
    pub allow_headers: Option<String>,

    /// Expose headers
    pub expose_headers: Option<String>,

    /// Max age
    pub max_age: Option<String>,

    /// Allow credentials
    pub allow_credentials: Option<bool>,
}

/// HTTP filter
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct HttpFilter {
    /// Filter name
    pub name: Option<String>,

    /// Typed config
    pub typed_config: Option<TypedConfig>,
}

/// Access log configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AccessLog {
    /// Name
    pub name: Option<String>,

    /// Typed config
    pub typed_config: Option<TypedConfig>,
}

/// HTTP/2 protocol options
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Http2ProtocolOptions {
    /// Max concurrent streams
    pub max_concurrent_streams: Option<u32>,

    /// Initial stream window size
    pub initial_stream_window_size: Option<u32>,

    /// Initial connection window size
    pub initial_connection_window_size: Option<u32>,
}

/// RDS configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Rds {
    /// Route config name
    pub route_config_name: Option<String>,

    /// Config source
    pub config_source: Option<ConfigSource>,
}

/// Config source
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ConfigSource {
    /// API config source
    pub api_config_source: Option<ApiConfigSource>,

    /// ADS
    pub ads: Option<serde_json::Value>,
}

/// API config source
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ApiConfigSource {
    /// API type
    pub api_type: Option<String>,

    /// Transport API version
    pub transport_api_version: Option<String>,

    /// Cluster names
    #[serde(default)]
    pub cluster_names: Vec<String>,

    /// GRPC services
    #[serde(default)]
    pub grpc_services: Vec<GrpcService>,
}

/// GRPC service
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct GrpcService {
    /// Envoy GRPC
    pub envoy_grpc: Option<EnvoyGrpc>,
}

/// Envoy GRPC
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct EnvoyGrpc {
    /// Cluster name
    pub cluster_name: Option<String>,
}

/// Listener filter
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ListenerFilter {
    /// Name
    pub name: Option<String>,

    /// Typed config
    pub typed_config: Option<TypedConfig>,
}

/// Transport socket (TLS)
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TransportSocket {
    /// Name
    pub name: Option<String>,

    /// Typed config
    pub typed_config: Option<TypedConfig>,
}

/// Cluster configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Cluster {
    /// Cluster name
    pub name: Option<String>,

    /// Connect timeout
    pub connect_timeout: Option<String>,

    /// Cluster type
    #[serde(rename = "type")]
    pub cluster_type: Option<String>,

    /// LB policy
    pub lb_policy: Option<String>,

    /// Load assignment
    pub load_assignment: Option<ClusterLoadAssignment>,

    /// Health checks
    #[serde(default)]
    pub health_checks: Vec<HealthCheck>,

    /// Circuit breakers
    pub circuit_breakers: Option<CircuitBreakers>,

    /// Transport socket
    pub transport_socket: Option<TransportSocket>,

    /// HTTP/2 protocol options
    pub http2_protocol_options: Option<Http2ProtocolOptions>,

    /// DNS lookup family
    pub dns_lookup_family: Option<String>,

    /// DNS refresh rate
    pub dns_refresh_rate: Option<String>,

    /// Outlier detection
    pub outlier_detection: Option<OutlierDetection>,

    /// Common LB config
    pub common_lb_config: Option<CommonLbConfig>,
}

/// Cluster load assignment
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ClusterLoadAssignment {
    /// Cluster name
    pub cluster_name: Option<String>,

    /// Endpoints
    #[serde(default)]
    pub endpoints: Vec<LocalityLbEndpoints>,
}

/// Locality LB endpoints
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct LocalityLbEndpoints {
    /// Locality
    pub locality: Option<Locality>,

    /// LB endpoints
    #[serde(default)]
    pub lb_endpoints: Vec<LbEndpoint>,

    /// Priority
    pub priority: Option<u32>,

    /// Load balancing weight
    pub load_balancing_weight: Option<u32>,
}

/// Locality
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Locality {
    /// Region
    pub region: Option<String>,

    /// Zone
    pub zone: Option<String>,

    /// Sub zone
    pub sub_zone: Option<String>,
}

/// LB endpoint
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct LbEndpoint {
    /// Endpoint
    pub endpoint: Option<Endpoint>,

    /// Health status
    pub health_status: Option<String>,

    /// Load balancing weight
    pub load_balancing_weight: Option<u32>,
}

/// Endpoint
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Endpoint {
    /// Address
    pub address: Option<Address>,

    /// Health check config
    pub health_check_config: Option<HealthCheckConfig>,

    /// Hostname
    pub hostname: Option<String>,
}

/// Health check config
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct HealthCheckConfig {
    /// Port value
    pub port_value: Option<u16>,
}

/// Health check
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct HealthCheck {
    /// Timeout
    pub timeout: Option<String>,

    /// Interval
    pub interval: Option<String>,

    /// Unhealthy threshold
    pub unhealthy_threshold: Option<u32>,

    /// Healthy threshold
    pub healthy_threshold: Option<u32>,

    /// HTTP health check
    pub http_health_check: Option<HttpHealthCheck>,

    /// TCP health check
    pub tcp_health_check: Option<TcpHealthCheck>,

    /// GRPC health check
    pub grpc_health_check: Option<GrpcHealthCheck>,
}

/// HTTP health check
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct HttpHealthCheck {
    /// Host
    pub host: Option<String>,

    /// Path
    pub path: Option<String>,

    /// Expected statuses
    #[serde(default)]
    pub expected_statuses: Vec<StatusRange>,
}

/// Status range
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct StatusRange {
    /// Start
    pub start: Option<u32>,

    /// End
    pub end: Option<u32>,
}

/// TCP health check
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TcpHealthCheck {
    /// Send payload
    pub send: Option<DataSource>,

    /// Receive payload
    #[serde(default)]
    pub receive: Vec<DataSource>,
}

/// GRPC health check
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct GrpcHealthCheck {
    /// Service name
    pub service_name: Option<String>,

    /// Authority
    pub authority: Option<String>,
}

/// Circuit breakers
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CircuitBreakers {
    /// Thresholds
    #[serde(default)]
    pub thresholds: Vec<CircuitBreakerThreshold>,
}

/// Circuit breaker threshold
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CircuitBreakerThreshold {
    /// Priority
    pub priority: Option<String>,

    /// Max connections
    pub max_connections: Option<u32>,

    /// Max pending requests
    pub max_pending_requests: Option<u32>,

    /// Max requests
    pub max_requests: Option<u32>,

    /// Max retries
    pub max_retries: Option<u32>,
}

/// Outlier detection
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct OutlierDetection {
    /// Consecutive 5xx
    pub consecutive_5xx: Option<u32>,

    /// Interval
    pub interval: Option<String>,

    /// Base ejection time
    pub base_ejection_time: Option<String>,

    /// Max ejection percent
    pub max_ejection_percent: Option<u32>,

    /// Enforcing consecutive 5xx
    pub enforcing_consecutive_5xx: Option<u32>,

    /// Enforcing success rate
    pub enforcing_success_rate: Option<u32>,

    /// Success rate minimum hosts
    pub success_rate_minimum_hosts: Option<u32>,

    /// Success rate request volume
    pub success_rate_request_volume: Option<u32>,

    /// Success rate stdev factor
    pub success_rate_stdev_factor: Option<u32>,
}

/// Common LB config
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CommonLbConfig {
    /// Healthy panic threshold
    pub healthy_panic_threshold: Option<Percent>,

    /// Zone aware LB config
    pub zone_aware_lb_config: Option<ZoneAwareLbConfig>,

    /// Locality weighted LB config
    pub locality_weighted_lb_config: Option<serde_json::Value>,

    /// Update merge window
    pub update_merge_window: Option<String>,

    /// Ignore new hosts until first hc
    pub ignore_new_hosts_until_first_hc: Option<bool>,
}

/// Percent
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Percent {
    pub value: Option<f64>,
}

/// Zone aware LB config
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ZoneAwareLbConfig {
    /// Routing enabled
    pub routing_enabled: Option<Percent>,

    /// Min cluster size
    pub min_cluster_size: Option<u64>,
}

/// Secret configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Secret {
    /// Name
    pub name: Option<String>,

    /// TLS certificate
    pub tls_certificate: Option<TlsCertificate>,

    /// Validation context
    pub validation_context: Option<ValidationContext>,
}

/// TLS certificate
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TlsCertificate {
    /// Certificate chain
    pub certificate_chain: Option<DataSource>,

    /// Private key
    pub private_key: Option<DataSource>,
}

/// Validation context
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ValidationContext {
    /// Trusted CA
    pub trusted_ca: Option<DataSource>,

    /// Match subject alt names
    #[serde(default)]
    pub match_subject_alt_names: Vec<StringMatch>,
}

/// Admin configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Admin {
    /// Access log path
    pub access_log_path: Option<String>,

    /// Address
    pub address: Option<Address>,
}

/// Node information
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Node {
    /// ID
    pub id: Option<String>,

    /// Cluster
    pub cluster: Option<String>,

    /// Metadata
    pub metadata: Option<HashMap<String, serde_json::Value>>,

    /// Locality
    pub locality: Option<Locality>,
}
