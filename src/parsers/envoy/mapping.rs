//! Envoy to Sentinel IR mapping

use super::{
    Cluster, EnvoyConfig, FilterChain, HttpConnectionManager, Listener as EnvoyListener,
    Route as EnvoyRoute, RouteAction, RouteConfiguration, VirtualHost,
};
use crate::ir::{
    Agent, AgentConfig, AgentDetection, AgentType, AuthAgentConfig, AuthType, AuthTypeConfig,
    BindAddress, Confidence, ConnectionPool, ConversionWarning, Diagnostics, Endpoint, Filter,
    FilterConfig, FilterType, HealthCheck, HealthCheckType, HeaderOperation, HeaderOperationType,
    HeadersFilterConfig, Listener, ListenerOptions, LoadBalancing, PathMatch, PathMatchType,
    Protocol, RateLimitAgentConfig, Route, RouteAction as IrRouteAction, RouteMatcher, HostMatch,
    SentinelConfig, Severity, SystemConfig, Upstream,
};
use crate::parsers::{ParseContext, ParseError, ParseOutput};

/// Map Envoy configuration to Sentinel IR
pub fn map_envoy_to_ir(config: EnvoyConfig, _ctx: &ParseContext) -> Result<ParseOutput, ParseError> {
    let mut diagnostics = Diagnostics::default();
    let mut sentinel_config = SentinelConfig::default();

    // Process listeners
    for listener in &config.static_resources.listeners {
        if let Some(ir_listener) = map_listener(listener, &mut diagnostics) {
            sentinel_config.listeners.push(ir_listener);
        }

        // Extract routes and filters from filter chains
        for filter_chain in &listener.filter_chains {
            extract_routes_from_filter_chain(
                filter_chain,
                &mut sentinel_config,
                &mut diagnostics,
            );
        }
    }

    // Process clusters (upstreams)
    for cluster in &config.static_resources.clusters {
        if let Some((name, upstream)) = map_cluster(cluster, &mut diagnostics) {
            sentinel_config.upstreams.insert(name, upstream);
        }
    }

    // Detect agents from HTTP filters
    detect_agents_from_config(&config, &mut sentinel_config, &mut diagnostics);

    // Set default system config
    sentinel_config.system = SystemConfig {
        worker_threads: Some(0), // auto
        max_connections: Some(10000),
        ..Default::default()
    };

    Ok(ParseOutput {
        config: sentinel_config,
        diagnostics,
    })
}

/// Map Envoy listener to IR Listener
fn map_listener(listener: &EnvoyListener, _diagnostics: &mut Diagnostics) -> Option<Listener> {
    let name = listener.name.clone().unwrap_or_else(|| "listener".to_string());

    let bind_address = listener.address.as_ref().and_then(|addr| {
        if let Some(socket_addr) = &addr.socket_address {
            let ip = socket_addr.address.clone().unwrap_or_else(|| "0.0.0.0".to_string());
            let port = socket_addr.port_value.unwrap_or(8080);
            Some(format!("{}:{}", ip, port))
        } else if let Some(pipe) = &addr.pipe {
            pipe.path.clone()
        } else {
            None
        }
    })?;

    // Check for TLS in filter chains
    let has_tls = listener.filter_chains.iter().any(|fc| fc.transport_socket.is_some());

    // Check for HTTP/2
    let has_http2 = listener.filter_chains.iter().any(|fc| {
        fc.filters.iter().any(|f| {
            f.typed_config.as_ref().map_or(false, |tc| {
                tc.type_url.as_ref().map_or(false, |url| {
                    url.contains("http_connection_manager")
                })
            })
        })
    });

    let protocol = if has_tls && has_http2 {
        Protocol::H2
    } else if has_tls {
        Protocol::Https
    } else if has_http2 {
        Protocol::H2c
    } else {
        Protocol::Http
    };

    // Extract TLS config from first filter chain with transport_socket
    let tls = listener.filter_chains.iter()
        .find_map(|fc| fc.transport_socket.as_ref())
        .and_then(|ts| extract_tls_config(ts));

    Some(Listener {
        name: format!("listener_{}", name),
        bind: if listener.address.as_ref().and_then(|a| a.pipe.as_ref()).is_some() {
            BindAddress::Unix(bind_address.into())
        } else {
            BindAddress::Single(bind_address)
        },
        protocol,
        tls,
        options: ListenerOptions::default(),
        source: None,
    })
}

/// Extract TLS configuration from transport socket
fn extract_tls_config(ts: &super::TransportSocket) -> Option<crate::ir::TlsConfig> {
    // For now, just indicate TLS is enabled
    // Full extraction would require parsing the typed_config
    if ts.name.as_ref().map_or(false, |n| n.contains("tls")) {
        Some(crate::ir::TlsConfig {
            cert_path: None,
            key_path: None,
            ..Default::default()
        })
    } else {
        None
    }
}

/// Extract routes from filter chain
fn extract_routes_from_filter_chain(
    filter_chain: &FilterChain,
    config: &mut SentinelConfig,
    diagnostics: &mut Diagnostics,
) {
    for filter in &filter_chain.filters {
        if let Some(typed_config) = &filter.typed_config {
            // Check if this is HTTP connection manager
            let is_hcm = typed_config.type_url.as_ref().map_or(false, |url| {
                url.contains("http_connection_manager")
            });

            if is_hcm {
                if let Some(config_value) = &typed_config.config {
                    // Try to deserialize as HttpConnectionManager
                    if let Ok(hcm) = serde_json::from_value::<HttpConnectionManager>(config_value.clone()) {
                        process_http_connection_manager(&hcm, config, diagnostics);
                    }
                }
            }
        }
    }
}

/// Process HTTP connection manager configuration
fn process_http_connection_manager(
    hcm: &HttpConnectionManager,
    config: &mut SentinelConfig,
    diagnostics: &mut Diagnostics,
) {
    // Process route configuration
    if let Some(route_config) = &hcm.route_config {
        process_route_configuration(route_config, config, diagnostics);
    }

    // Process HTTP filters for agents
    process_http_filters(&hcm.http_filters, config, diagnostics);
}

/// Process route configuration
fn process_route_configuration(
    route_config: &RouteConfiguration,
    config: &mut SentinelConfig,
    diagnostics: &mut Diagnostics,
) {
    for vhost in &route_config.virtual_hosts {
        process_virtual_host(vhost, config, diagnostics);
    }
}

/// Process virtual host
fn process_virtual_host(
    vhost: &VirtualHost,
    config: &mut SentinelConfig,
    _diagnostics: &mut Diagnostics,
) {
    let vhost_name = vhost.name.clone().unwrap_or_else(|| "default".to_string());

    // Extract headers filter if present
    if !vhost.request_headers_to_add.is_empty() || !vhost.response_headers_to_add.is_empty() ||
       !vhost.request_headers_to_remove.is_empty() || !vhost.response_headers_to_remove.is_empty() {
        let filter_name = format!("headers-{}", vhost_name);
        let filter = create_headers_filter(vhost);
        config.filters.insert(filter_name, filter);
    }

    // Process routes
    for (idx, route) in vhost.routes.iter().enumerate() {
        if let Some(ir_route) = map_route(route, vhost, idx) {
            config.routes.push(ir_route);
        }
    }
}

/// Create headers filter from virtual host
fn create_headers_filter(vhost: &VirtualHost) -> Filter {
    let mut request_add = Vec::new();
    let mut request_remove = Vec::new();
    let mut response_add = Vec::new();
    let mut response_remove = Vec::new();

    for hvo in &vhost.request_headers_to_add {
        if let Some(header) = &hvo.header {
            if let (Some(key), Some(value)) = (&header.key, &header.value) {
                request_add.push(HeaderOperation {
                    name: key.clone(),
                    value: value.clone(),
                    operation: HeaderOperationType::Set,
                });
            }
        }
    }

    for hvo in &vhost.response_headers_to_add {
        if let Some(header) = &hvo.header {
            if let (Some(key), Some(value)) = (&header.key, &header.value) {
                response_add.push(HeaderOperation {
                    name: key.clone(),
                    value: value.clone(),
                    operation: HeaderOperationType::Set,
                });
            }
        }
    }

    request_remove.extend(vhost.request_headers_to_remove.clone());
    response_remove.extend(vhost.response_headers_to_remove.clone());

    Filter {
        name: "headers".to_string(),
        filter_type: FilterType::Headers,
        config: FilterConfig::Headers(HeadersFilterConfig {
            request_add,
            request_remove,
            response_add,
            response_remove,
        }),
        ..Default::default()
    }
}

/// Map Envoy route to IR Route
fn map_route(route: &EnvoyRoute, vhost: &VirtualHost, idx: usize) -> Option<Route> {
    let route_match = route.route_match.as_ref()?;

    // Build matchers
    let mut matchers = Vec::new();

    // Host matchers from virtual host domains
    if !vhost.domains.is_empty() && !vhost.domains.iter().all(|d| d == "*") {
        matchers.push(RouteMatcher::Host(HostMatch {
            patterns: vhost.domains.clone(),
            ..Default::default()
        }));
    }

    // Path matcher
    if let Some(prefix) = &route_match.prefix {
        matchers.push(RouteMatcher::Path(PathMatch {
            pattern: prefix.clone(),
            match_type: PathMatchType::Prefix,
        }));
    } else if let Some(path) = &route_match.path {
        matchers.push(RouteMatcher::Path(PathMatch {
            pattern: path.clone(),
            match_type: PathMatchType::Exact,
        }));
    } else if let Some(regex) = &route_match.safe_regex {
        if let Some(pattern) = &regex.regex {
            matchers.push(RouteMatcher::Path(PathMatch {
                pattern: pattern.clone(),
                match_type: PathMatchType::Regex,
            }));
        }
    }

    // Header matchers
    for header_match in &route_match.headers {
        if let Some(name) = &header_match.name {
            let pattern = header_match.exact_match.clone()
                .or_else(|| header_match.prefix_match.clone())
                .or_else(|| header_match.suffix_match.clone())
                .or_else(|| header_match.safe_regex_match.as_ref().and_then(|r| r.regex.clone()))
                .unwrap_or_default();

            matchers.push(RouteMatcher::Header(crate::ir::HeaderMatch {
                name: name.clone(),
                pattern,
                ..Default::default()
            }));
        }
    }

    // Determine action
    let action = if let Some(route_action) = &route.route {
        map_route_action(route_action)
    } else if let Some(redirect) = &route.redirect {
        let url = redirect.host_redirect.clone()
            .or_else(|| redirect.path_redirect.clone())
            .unwrap_or_default();

        let status_code = match redirect.response_code.as_deref() {
            Some("MOVED_PERMANENTLY") => 301,
            Some("FOUND") => 302,
            Some("SEE_OTHER") => 303,
            Some("TEMPORARY_REDIRECT") => 307,
            Some("PERMANENT_REDIRECT") => 308,
            _ => if redirect.https_redirect.unwrap_or(false) { 301 } else { 302 },
        };

        IrRouteAction::Redirect {
            url,
            status_code,
            preserve_path: redirect.strip_query.map(|s| !s).unwrap_or(true),
        }
    } else if let Some(direct) = &route.direct_response {
        IrRouteAction::FixedResponse {
            status_code: direct.status.unwrap_or(200) as u16,
            body: direct.body.as_ref().and_then(|b| b.inline_string.clone()),
            headers: Vec::new(),
        }
    } else {
        return None;
    };

    let route_name = route.name.clone().unwrap_or_else(|| {
        let vhost_name = vhost.name.clone().unwrap_or_else(|| "route".to_string());
        format!("{}-{}", vhost_name, idx)
    });

    Some(Route {
        name: route_name,
        matchers,
        action,
        priority: None,
        middleware: Vec::new(),
        metadata: Default::default(),
        source: None,
    })
}

/// Map route action
fn map_route_action(action: &RouteAction) -> IrRouteAction {
    let upstream = action.cluster.clone()
        .or_else(|| {
            action.weighted_clusters.as_ref().and_then(|wc| {
                wc.clusters.first().and_then(|c| c.name.clone())
            })
        })
        .unwrap_or_else(|| "unknown".to_string());

    let path_rewrite = action.prefix_rewrite.as_ref().map(|rewrite| {
        crate::ir::PathRewrite {
            pattern: "^/.*".to_string(),
            replacement: rewrite.clone(),
            regex: false,
        }
    });

    let host_rewrite = action.host_rewrite_literal.clone();

    let timeout_ms = action.timeout.as_ref().and_then(|t| parse_envoy_duration(t));

    IrRouteAction::Forward {
        upstream,
        path_rewrite,
        host_rewrite,
        timeout_ms,
    }
}

/// Map Envoy cluster to IR Upstream
fn map_cluster(cluster: &Cluster, _diagnostics: &mut Diagnostics) -> Option<(String, Upstream)> {
    let name = cluster.name.clone()?;

    let mut endpoints = Vec::new();

    // Extract endpoints from load_assignment
    if let Some(load_assignment) = &cluster.load_assignment {
        for locality_ep in &load_assignment.endpoints {
            for lb_ep in &locality_ep.lb_endpoints {
                if let Some(endpoint) = &lb_ep.endpoint {
                    if let Some(addr) = &endpoint.address {
                        if let Some(socket_addr) = &addr.socket_address {
                            let address = format!(
                                "{}:{}",
                                socket_addr.address.clone().unwrap_or_else(|| "127.0.0.1".to_string()),
                                socket_addr.port_value.unwrap_or(80)
                            );

                            endpoints.push(Endpoint {
                                address,
                                weight: lb_ep.load_balancing_weight.map(|w| w as u32),
                                backup: lb_ep.health_status.as_ref().map_or(false, |s| s == "UNHEALTHY"),
                                slow_start_ms: None,
                                max_connections: None,
                            });
                        }
                    }
                }
            }
        }
    }

    // Map load balancing policy
    let load_balancing = match cluster.lb_policy.as_deref() {
        Some("ROUND_ROBIN") => LoadBalancing::RoundRobin,
        Some("LEAST_REQUEST") | Some("LEAST_CONN") => LoadBalancing::LeastConnections,
        Some("RANDOM") => LoadBalancing::Random,
        Some("RING_HASH") | Some("MAGLEV") => LoadBalancing::ConsistentHash {
            key: "source_ip".to_string()
        },
        _ => LoadBalancing::RoundRobin,
    };

    // Extract health check
    let health_check = cluster.health_checks.first().map(|hc| {
        let check_type = if let Some(http_hc) = &hc.http_health_check {
            HealthCheckType::Http {
                path: http_hc.path.clone().unwrap_or_else(|| "/".to_string()),
                expected_status: http_hc.expected_statuses.first()
                    .and_then(|s| s.start.map(|v| vec![v as u16]))
                    .unwrap_or_else(|| vec![200]),
            }
        } else if hc.grpc_health_check.is_some() {
            HealthCheckType::Grpc {
                service: hc.grpc_health_check.as_ref().and_then(|g| g.service_name.clone()),
            }
        } else {
            HealthCheckType::Tcp
        };

        HealthCheck {
            check_type,
            interval_ms: hc.interval.as_ref().and_then(|i| parse_envoy_duration(i)).unwrap_or(10000),
            timeout_ms: hc.timeout.as_ref().and_then(|t| parse_envoy_duration(t)).unwrap_or(5000),
            healthy_threshold: hc.healthy_threshold.unwrap_or(2),
            unhealthy_threshold: hc.unhealthy_threshold.unwrap_or(3),
        }
    });

    // Extract connection pool settings from circuit breakers
    let connection_pool = cluster.circuit_breakers.as_ref().and_then(|cb| {
        cb.thresholds.first().map(|t| ConnectionPool {
            max_connections: t.max_connections,
            max_idle: None,
            idle_timeout_ms: None,
        })
    });

    let upstream = Upstream {
        name: name.clone(),
        endpoints,
        load_balancing,
        health_check,
        connection_pool,
        ..Default::default()
    };

    Some((name, upstream))
}

/// Process HTTP filters for agent detection
fn process_http_filters(
    filters: &[super::HttpFilter],
    config: &mut SentinelConfig,
    diagnostics: &mut Diagnostics,
) {
    for filter in filters {
        let filter_name = filter.name.as_deref().unwrap_or("");

        // Check for ext_authz (external authorization)
        if filter_name.contains("ext_authz") || filter_name.contains("envoy.filters.http.ext_authz") {
            let agent = Agent {
                name: "ext-authz".to_string(),
                agent_type: AgentType::Auth,
                config: AgentConfig::Auth(AuthAgentConfig {
                    socket_path: "/run/sentinel/ext-authz.sock".into(),
                    auth_type: AuthType::Custom,
                    type_config: AuthTypeConfig::Unknown,
                    timeout_ms: Some(100),
                    failure_mode: crate::ir::FailureMode::Closed,
                }),
                routes: Vec::new(),
                detection: AgentDetection::Inferred {
                    confidence: Confidence::High,
                    patterns_matched: vec!["envoy.filters.http.ext_authz".to_string()],
                },
                source: None,
            };
            config.agents.push(agent);

            diagnostics.warnings.push(ConversionWarning {
                severity: Severity::Info,
                source_location: None,
                source_directive: "ext_authz filter".to_string(),
                message: "Detected ext_authz filter - mapped to Auth agent".to_string(),
                suggestion: None,
            });
        }

        // Check for ratelimit filter
        if filter_name.contains("ratelimit") || filter_name.contains("envoy.filters.http.ratelimit") {
            let agent = Agent {
                name: "ratelimit".to_string(),
                agent_type: AgentType::RateLimit,
                config: AgentConfig::RateLimit(RateLimitAgentConfig {
                    socket_path: "/run/sentinel/ratelimit.sock".into(),
                    limits: vec![],
                    timeout_ms: Some(50),
                    failure_mode: crate::ir::FailureMode::Open,
                }),
                routes: Vec::new(),
                detection: AgentDetection::Inferred {
                    confidence: Confidence::High,
                    patterns_matched: vec!["envoy.filters.http.ratelimit".to_string()],
                },
                source: None,
            };
            config.agents.push(agent);

            diagnostics.warnings.push(ConversionWarning {
                severity: Severity::Info,
                source_location: None,
                source_directive: "ratelimit filter".to_string(),
                message: "Detected ratelimit filter - mapped to RateLimit agent".to_string(),
                suggestion: None,
            });
        }

        // Check for JWT authentication
        if filter_name.contains("jwt_authn") || filter_name.contains("envoy.filters.http.jwt_authn") {
            let agent = Agent {
                name: "jwt-auth".to_string(),
                agent_type: AgentType::Auth,
                config: AgentConfig::Auth(AuthAgentConfig {
                    socket_path: "/run/sentinel/jwt-auth.sock".into(),
                    auth_type: AuthType::Jwt,
                    type_config: AuthTypeConfig::Jwt {
                        issuer: None,
                        audience: None,
                        jwks_url: None,
                    },
                    timeout_ms: Some(100),
                    failure_mode: crate::ir::FailureMode::Closed,
                }),
                routes: Vec::new(),
                detection: AgentDetection::Inferred {
                    confidence: Confidence::High,
                    patterns_matched: vec!["envoy.filters.http.jwt_authn".to_string()],
                },
                source: None,
            };
            config.agents.push(agent);

            diagnostics.warnings.push(ConversionWarning {
                severity: Severity::Info,
                source_location: None,
                source_directive: "jwt_authn filter".to_string(),
                message: "Detected JWT authentication filter - mapped to Auth agent".to_string(),
                suggestion: None,
            });
        }

        // Check for RBAC (role-based access control)
        if filter_name.contains("rbac") || filter_name.contains("envoy.filters.http.rbac") {
            diagnostics.warnings.push(ConversionWarning {
                severity: Severity::Warning,
                source_location: None,
                source_directive: "rbac filter".to_string(),
                message: "RBAC filter detected - manual configuration required for Sentinel".to_string(),
                suggestion: Some("Configure custom Auth agent with RBAC rules".to_string()),
            });
        }
    }
}

/// Detect agents from Envoy configuration
fn detect_agents_from_config(
    config: &EnvoyConfig,
    _sentinel_config: &mut SentinelConfig,
    diagnostics: &mut Diagnostics,
) {
    // Check for rate limits in virtual hosts
    for listener in &config.static_resources.listeners {
        for filter_chain in &listener.filter_chains {
            for filter in &filter_chain.filters {
                if let Some(typed_config) = &filter.typed_config {
                    if let Some(config_value) = &typed_config.config {
                        if let Ok(hcm) = serde_json::from_value::<HttpConnectionManager>(config_value.clone()) {
                            if let Some(route_config) = &hcm.route_config {
                                for vhost in &route_config.virtual_hosts {
                                    if !vhost.rate_limits.is_empty() {
                                        // Already detected via HTTP filters, just log
                                        diagnostics.warnings.push(ConversionWarning {
                                            severity: Severity::Info,
                                            source_location: None,
                                            source_directive: "virtual_host rate_limits".to_string(),
                                            message: format!(
                                                "Virtual host '{}' has {} rate limit rules",
                                                vhost.name.as_deref().unwrap_or("default"),
                                                vhost.rate_limits.len()
                                            ),
                                            suggestion: None,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Parse Envoy duration string (e.g., "30s", "1m", "500ms")
fn parse_envoy_duration(duration: &str) -> Option<u64> {
    let duration = duration.trim();

    if duration.ends_with("ms") {
        duration[..duration.len()-2].parse().ok()
    } else if duration.ends_with('s') {
        duration[..duration.len()-1].parse::<u64>().ok().map(|s| s * 1000)
    } else if duration.ends_with('m') {
        duration[..duration.len()-1].parse::<u64>().ok().map(|m| m * 60 * 1000)
    } else if duration.ends_with('h') {
        duration[..duration.len()-1].parse::<u64>().ok().map(|h| h * 60 * 60 * 1000)
    } else {
        // Assume seconds if no suffix
        duration.parse::<u64>().ok().map(|s| s * 1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_envoy_duration() {
        assert_eq!(parse_envoy_duration("500ms"), Some(500));
        assert_eq!(parse_envoy_duration("30s"), Some(30000));
        assert_eq!(parse_envoy_duration("1m"), Some(60000));
        assert_eq!(parse_envoy_duration("1h"), Some(3600000));
        assert_eq!(parse_envoy_duration("10"), Some(10000));
    }

    #[test]
    fn test_map_lb_policy() {
        let cluster = Cluster {
            name: Some("test".to_string()),
            lb_policy: Some("ROUND_ROBIN".to_string()),
            ..Default::default()
        };

        let mut diag = Diagnostics::default();
        let (_, upstream) = map_cluster(&cluster, &mut diag).unwrap();
        assert!(matches!(upstream.load_balancing, LoadBalancing::RoundRobin));

        let cluster2 = Cluster {
            name: Some("test2".to_string()),
            lb_policy: Some("LEAST_REQUEST".to_string()),
            ..Default::default()
        };
        let (_, upstream2) = map_cluster(&cluster2, &mut diag).unwrap();
        assert!(matches!(upstream2.load_balancing, LoadBalancing::LeastConnections));
    }
}
