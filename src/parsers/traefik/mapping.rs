//! Traefik to IR mapping

use super::{
    BasicAuth, ForwardAuth, Headers, IpWhiteList, Middleware, RateLimit, Router, Service,
    TraefikConfig,
};
use crate::ir::{
    Agent, AgentConfig, AgentDetection, AgentType, AuthAgentConfig, AuthType, AuthTypeConfig,
    BindAddress, CompressionAlgorithm, CompressionFilterConfig, Confidence, ConversionWarning,
    Diagnostics, Endpoint, FailureMode, Filter, FilterConfig, FilterType, HeaderOperation,
    HeadersFilterConfig, HealthCheck, HealthCheckType, HeaderMatch, HostMatch, Listener,
    ListenerOptions, LoadBalancing, MiddlewareRef, PathMatch, PathMatchType, Protocol,
    RateLimitAgentConfig, RateLimitKey, RateLimitRule, Route, RouteAction, RouteMatcher,
    RouteMetadata, SentinelConfig, Severity, SourceLocation, TlsConfig, Upstream, WafAgentConfig,
    WafMode,
};
use crate::parsers::{ParseContext, ParseError, ParseOutput};
use std::collections::HashMap;
use std::path::PathBuf;

/// Convert Traefik config to Sentinel IR
pub fn map_traefik_to_ir(
    config: TraefikConfig,
    ctx: &ParseContext,
) -> Result<ParseOutput, ParseError> {
    let mut sentinel = SentinelConfig::default();
    let mut diagnostics = Diagnostics::default();

    // Map entry points to listeners
    for (name, entry_point) in &config.entry_points {
        if let Some(listener) = map_entry_point(name, entry_point, &mut diagnostics) {
            sentinel.listeners.push(listener);
        }
    }

    // Map services to upstreams
    for (name, service) in &config.http.services {
        if let Some(upstream) = map_service(name, service, &mut diagnostics) {
            sentinel.upstreams.insert(name.clone(), upstream);
        }
    }

    // Map middlewares to filters/agents
    let (filters, agents) = map_middlewares(&config.http.middlewares, ctx, &mut diagnostics);
    sentinel.filters = filters;
    sentinel.agents = agents;

    // Map routers to routes
    for (name, router) in &config.http.routers {
        if let Some(route) =
            map_router(name, router, &config.http.middlewares, ctx, &mut diagnostics)
        {
            sentinel.routes.push(route);
        }
    }

    // Handle TLS configuration
    if let Some(tls_config) = &config.tls {
        if let Some(options) = &tls_config.options {
            for (name, opts) in options {
                add_info(
                    &mut diagnostics,
                    &format!(
                        "TLS options '{}' detected - manual TLS configuration may be needed",
                        name
                    ),
                    None,
                );
                if let Some(min_ver) = &opts.min_version {
                    add_info(
                        &mut diagnostics,
                        &format!("TLS minimum version: {}", min_ver),
                        None,
                    );
                }
            }
        }
    }

    // Warn about TCP configuration (not fully supported)
    if config.tcp.is_some() {
        add_warning(
            &mut diagnostics,
            "TCP configuration detected but not fully supported - only HTTP converted",
            None,
        );
    }

    Ok(ParseOutput {
        config: sentinel,
        diagnostics,
    })
}

/// Add an info diagnostic
fn add_info(diagnostics: &mut Diagnostics, message: &str, location: Option<SourceLocation>) {
    diagnostics.warnings.push(ConversionWarning {
        severity: Severity::Info,
        source_location: location,
        source_directive: String::new(),
        message: message.to_string(),
        suggestion: None,
    });
}

/// Add a warning diagnostic
fn add_warning(diagnostics: &mut Diagnostics, message: &str, location: Option<SourceLocation>) {
    diagnostics.warnings.push(ConversionWarning {
        severity: Severity::Warning,
        source_location: location,
        source_directive: String::new(),
        message: message.to_string(),
        suggestion: None,
    });
}

/// Map a Traefik entry point to a Sentinel listener
fn map_entry_point(
    name: &str,
    entry_point: &super::EntryPoint,
    diagnostics: &mut Diagnostics,
) -> Option<Listener> {
    let address = entry_point.address.as_ref()?;

    // Parse address (e.g., ":80", ":443", "0.0.0.0:8080")
    let bind_address = format_bind_address(address);

    // Determine protocol from entry point configuration
    let (protocol, tls) = if let Some(http) = &entry_point.http {
        if http.tls.is_some() {
            (Protocol::Https, Some(TlsConfig::default()))
        } else {
            (Protocol::Http, None)
        }
    } else {
        // Guess from port
        let port = parse_port(address);
        if port == 443 {
            (Protocol::Https, Some(TlsConfig::default()))
        } else {
            (Protocol::Http, None)
        }
    };

    // Handle HTTP to HTTPS redirection
    if let Some(http) = &entry_point.http {
        if let Some(redirections) = &http.redirections {
            if let Some(redirect) = &redirections.entry_point {
                if let Some(to) = &redirect.to {
                    add_info(
                        diagnostics,
                        &format!(
                            "Entry point '{}' redirects to '{}' - configure redirect filter",
                            name, to
                        ),
                        None,
                    );
                }
            }
        }
    }

    Some(Listener {
        name: name.to_string(),
        bind: BindAddress::Single(bind_address),
        protocol,
        tls,
        options: ListenerOptions::default(),
        source: None,
    })
}

/// Format Traefik address to bind address string (e.g., ":80" -> "0.0.0.0:80")
fn format_bind_address(address: &str) -> String {
    let address = address.trim();
    if address.starts_with(':') {
        format!("0.0.0.0{}", address)
    } else {
        address.to_string()
    }
}

/// Parse port from Traefik address format
fn parse_port(address: &str) -> u16 {
    let address = address.trim();
    if let Some(colon_pos) = address.rfind(':') {
        let port_str = &address[colon_pos + 1..];
        port_str.parse().unwrap_or(80)
    } else {
        80
    }
}

/// Map a Traefik service to a Sentinel upstream
fn map_service(name: &str, service: &Service, diagnostics: &mut Diagnostics) -> Option<Upstream> {
    // Handle load balancer service
    if let Some(lb) = &service.load_balancer {
        let endpoints: Vec<Endpoint> = lb
            .servers
            .iter()
            .filter_map(|server| {
                server.url.as_ref().map(|url| {
                    let address = parse_server_url_to_address(url);
                    Endpoint {
                        address,
                        weight: server.weight.map(|w| w as u32),
                        backup: false,
                        slow_start_ms: None,
                        max_connections: None,
                    }
                })
            })
            .collect();

        if endpoints.is_empty() {
            return None;
        }

        // Map health check
        let health_check = lb.health_check.as_ref().map(|hc| HealthCheck {
            check_type: HealthCheckType::Http {
                path: hc.path.clone().unwrap_or_else(|| "/health".to_string()),
                expected_status: vec![200],
            },
            interval_ms: parse_duration_ms(hc.interval.as_deref()).unwrap_or(10000),
            timeout_ms: parse_duration_ms(hc.timeout.as_deref()).unwrap_or(5000),
            healthy_threshold: 2,
            unhealthy_threshold: 3,
        });

        // Handle sticky sessions
        if lb.sticky.is_some() {
            add_info(
                diagnostics,
                &format!(
                    "Service '{}' has sticky sessions - using IP hash load balancing",
                    name
                ),
                None,
            );
        }

        let load_balancing = if lb.sticky.is_some() {
            LoadBalancing::IpHash
        } else {
            LoadBalancing::RoundRobin
        };

        return Some(Upstream {
            name: name.to_string(),
            endpoints,
            load_balancing,
            health_check,
            circuit_breaker: None,
            connection_pool: None,
            timeouts: None,
            tls: None,
            source: None,
        });
    }

    // Handle weighted service
    if let Some(weighted) = &service.weighted {
        add_warning(
            diagnostics,
            &format!(
                "Service '{}' uses weighted routing - converted to simple upstream",
                name
            ),
            None,
        );

        if let Some(services) = &weighted.services {
            let endpoints: Vec<Endpoint> = services
                .iter()
                .map(|ws| Endpoint {
                    address: ws.name.clone(),
                    weight: ws.weight.map(|w| w as u32),
                    backup: false,
                    slow_start_ms: None,
                    max_connections: None,
                })
                .collect();

            if !endpoints.is_empty() {
                return Some(Upstream {
                    name: name.to_string(),
                    endpoints,
                    load_balancing: LoadBalancing::Weighted,
                    health_check: None,
                    circuit_breaker: None,
                    connection_pool: None,
                    timeouts: None,
                    tls: None,
                    source: None,
                });
            }
        }
    }

    // Handle mirroring service
    if let Some(mirror) = &service.mirroring {
        add_warning(
            diagnostics,
            &format!(
                "Service '{}' uses traffic mirroring - not directly supported, manual configuration needed",
                name
            ),
            None,
        );

        if let Some(primary) = &mirror.service {
            return Some(Upstream {
                name: name.to_string(),
                endpoints: vec![Endpoint {
                    address: primary.clone(),
                    weight: None,
                    backup: false,
                    slow_start_ms: None,
                    max_connections: None,
                }],
                load_balancing: LoadBalancing::RoundRobin,
                health_check: None,
                circuit_breaker: None,
                connection_pool: None,
                timeouts: None,
                tls: None,
                source: None,
            });
        }
    }

    None
}

/// Parse server URL to address string (host:port format)
fn parse_server_url_to_address(url: &str) -> String {
    // URL format: http://host:port or https://host:port
    let url = url
        .trim_start_matches("http://")
        .trim_start_matches("https://");

    // Remove any path component
    url.split('/').next().unwrap_or(url).to_string()
}

/// Parse duration string to milliseconds (e.g., "10s", "1m", "500ms")
fn parse_duration_ms(duration: Option<&str>) -> Option<u64> {
    let duration = duration?;
    let duration = duration.trim();

    if duration.ends_with("ms") {
        duration.trim_end_matches("ms").parse().ok()
    } else if duration.ends_with('s') {
        let val: u64 = duration.trim_end_matches('s').parse().ok()?;
        Some(val * 1000)
    } else if duration.ends_with('m') {
        let val: u64 = duration.trim_end_matches('m').parse().ok()?;
        Some(val * 60 * 1000)
    } else if duration.ends_with('h') {
        let val: u64 = duration.trim_end_matches('h').parse().ok()?;
        Some(val * 3600 * 1000)
    } else {
        // Assume milliseconds
        duration.parse().ok()
    }
}

/// Map Traefik middlewares to Sentinel filters and agents
fn map_middlewares(
    middlewares: &HashMap<String, Middleware>,
    ctx: &ParseContext,
    diagnostics: &mut Diagnostics,
) -> (HashMap<String, Filter>, Vec<Agent>) {
    let mut filters = HashMap::new();
    let mut agents = Vec::new();

    for (name, middleware) in middlewares {
        let location = SourceLocation::new(ctx.primary_path.clone(), 0);

        // Rate limit -> Agent
        if let Some(rate_limit) = &middleware.rate_limit {
            agents.push(map_rate_limit_middleware(name, rate_limit, &location));
        }

        // Basic auth -> Agent
        if let Some(basic_auth) = &middleware.basic_auth {
            agents.push(map_basic_auth_middleware(name, basic_auth, &location));
        }

        // Forward auth -> Agent
        if let Some(forward_auth) = &middleware.forward_auth {
            agents.push(map_forward_auth_middleware(
                name,
                forward_auth,
                &location,
                diagnostics,
            ));
        }

        // IP whitelist -> Agent (WAF)
        if let Some(ip_whitelist) = &middleware.ip_white_list {
            agents.push(map_ip_whitelist_middleware(name, ip_whitelist, &location));
        }

        // Headers -> Filter
        if let Some(headers) = &middleware.headers {
            if let Some(filter) = map_headers_middleware(name, headers, &location) {
                filters.insert(name.clone(), filter);
            }
        }

        // Strip prefix -> Diagnostic (path rewrite not directly supported as filter)
        if let Some(strip_prefix) = &middleware.strip_prefix {
            if let Some(prefixes) = &strip_prefix.prefixes {
                add_info(
                    diagnostics,
                    &format!(
                        "Middleware '{}' strips prefix '{}' - configure path rewrite on route",
                        name,
                        prefixes.first().cloned().unwrap_or_default()
                    ),
                    Some(location.clone()),
                );
            }
        }

        // Add prefix -> Diagnostic (path rewrite not directly supported as filter)
        if let Some(add_prefix) = &middleware.add_prefix {
            if let Some(prefix) = &add_prefix.prefix {
                add_info(
                    diagnostics,
                    &format!(
                        "Middleware '{}' adds prefix '{}' - configure path rewrite on route",
                        name, prefix
                    ),
                    Some(location.clone()),
                );
            }
        }

        // Compress -> Filter
        if middleware.compress.is_some() {
            let min_size = middleware
                .compress
                .as_ref()
                .and_then(|c| c.min_response_body_bytes)
                .map(|s| s as u64);

            filters.insert(
                name.clone(),
                Filter {
                    name: name.clone(),
                    filter_type: FilterType::Compression,
                    config: FilterConfig::Compression(CompressionFilterConfig {
                        algorithms: vec![CompressionAlgorithm::Gzip, CompressionAlgorithm::Brotli],
                        min_size,
                        mime_types: None,
                        level: None,
                    }),
                    source: Some(location.clone()),
                },
            );
        }

        // Redirect scheme -> Diagnostic only
        if let Some(redirect) = &middleware.redirect_scheme {
            add_info(
                diagnostics,
                &format!(
                    "Middleware '{}' redirects to scheme '{}' - configure redirect behavior",
                    name,
                    redirect.scheme.as_deref().unwrap_or("https")
                ),
                Some(location.clone()),
            );
        }

        // Circuit breaker -> Diagnostic only
        if middleware.circuit_breaker.is_some() {
            add_warning(
                diagnostics,
                &format!(
                    "Middleware '{}' has circuit breaker - not directly supported in Sentinel",
                    name
                ),
                Some(location.clone()),
            );
        }

        // Retry -> Diagnostic only
        if middleware.retry.is_some() {
            add_info(
                diagnostics,
                &format!(
                    "Middleware '{}' has retry configuration - map to upstream retry settings",
                    name
                ),
                Some(location),
            );
        }
    }

    (filters, agents)
}

/// Map rate limit middleware to agent
fn map_rate_limit_middleware(
    name: &str,
    rate_limit: &RateLimit,
    location: &SourceLocation,
) -> Agent {
    let key = if let Some(source) = &rate_limit.source_criterion {
        if source.request_host.unwrap_or(false) {
            RateLimitKey::Header("Host".to_string())
        } else if let Some(header_name) = &source.request_header_name {
            RateLimitKey::Header(header_name.clone())
        } else {
            RateLimitKey::SourceIp
        }
    } else {
        RateLimitKey::SourceIp
    };

    let rule = RateLimitRule {
        name: name.to_string(),
        key,
        rate: rate_limit.average.unwrap_or(100) as u32,
        period_ms: parse_duration_ms(rate_limit.period.as_deref()).unwrap_or(1000),
        burst: rate_limit.burst.map(|b| b as u32),
    };

    Agent {
        name: format!("{}-ratelimit", name),
        agent_type: AgentType::RateLimit,
        config: AgentConfig::RateLimit(RateLimitAgentConfig {
            socket_path: PathBuf::from(format!("/run/sentinel/{}-ratelimit.sock", name)),
            limits: vec![rule],
            timeout_ms: Some(50),
            failure_mode: FailureMode::Open,
        }),
        routes: Vec::new(),
        detection: AgentDetection::Inferred {
            confidence: Confidence::High,
            patterns_matched: vec!["traefik rateLimit middleware".to_string()],
        },
        source: Some(location.clone()),
    }
}

/// Map basic auth middleware to agent
fn map_basic_auth_middleware(
    name: &str,
    basic_auth: &BasicAuth,
    location: &SourceLocation,
) -> Agent {
    Agent {
        name: format!("{}-auth", name),
        agent_type: AgentType::Auth,
        config: AgentConfig::Auth(AuthAgentConfig {
            socket_path: PathBuf::from(format!("/run/sentinel/{}-auth.sock", name)),
            auth_type: AuthType::Basic,
            type_config: AuthTypeConfig::Basic {
                realm: basic_auth.realm.clone(),
                htpasswd_path: basic_auth.users_file.as_ref().map(PathBuf::from),
            },
            timeout_ms: Some(100),
            failure_mode: FailureMode::Closed,
        }),
        routes: Vec::new(),
        detection: AgentDetection::Inferred {
            confidence: Confidence::High,
            patterns_matched: vec!["traefik basicAuth middleware".to_string()],
        },
        source: Some(location.clone()),
    }
}

/// Map forward auth middleware to agent
fn map_forward_auth_middleware(
    name: &str,
    forward_auth: &ForwardAuth,
    location: &SourceLocation,
    diagnostics: &mut Diagnostics,
) -> Agent {
    if let Some(address) = &forward_auth.address {
        add_info(
            diagnostics,
            &format!("Forward auth '{}' points to: {}", name, address),
            Some(location.clone()),
        );
    }

    Agent {
        name: format!("{}-auth", name),
        agent_type: AgentType::Auth,
        config: AgentConfig::Auth(AuthAgentConfig {
            socket_path: PathBuf::from(format!("/run/sentinel/{}-auth.sock", name)),
            auth_type: AuthType::Custom,
            type_config: AuthTypeConfig::Unknown,
            timeout_ms: Some(100),
            failure_mode: FailureMode::Closed,
        }),
        routes: Vec::new(),
        detection: AgentDetection::Inferred {
            confidence: Confidence::High,
            patterns_matched: vec!["traefik forwardAuth middleware".to_string()],
        },
        source: Some(location.clone()),
    }
}

/// Map IP whitelist middleware to WAF agent
fn map_ip_whitelist_middleware(
    name: &str,
    ip_whitelist: &IpWhiteList,
    location: &SourceLocation,
) -> Agent {
    use crate::ir::{ExtractedWafRule, WafAction, WafRuleType};

    let allowed_ips = ip_whitelist.source_range.clone().unwrap_or_default();

    let extracted_rules: Vec<ExtractedWafRule> = allowed_ips
        .iter()
        .map(|ip| ExtractedWafRule {
            rule_type: WafRuleType::IpWhitelist,
            pattern: ip.clone(),
            action: WafAction::Allow,
            description: Some("IP whitelist from Traefik".to_string()),
        })
        .collect();

    Agent {
        name: format!("{}-waf", name),
        agent_type: AgentType::Waf,
        config: AgentConfig::Waf(WafAgentConfig {
            socket_path: PathBuf::from(format!("/run/sentinel/{}-waf.sock", name)),
            mode: WafMode::Prevention,
            ruleset: None,
            paranoia_level: None,
            timeout_ms: Some(50),
            failure_mode: FailureMode::Closed,
            extracted_rules,
        }),
        routes: Vec::new(),
        detection: AgentDetection::Inferred {
            confidence: Confidence::High,
            patterns_matched: vec!["traefik ipWhiteList middleware".to_string()],
        },
        source: Some(location.clone()),
    }
}

/// Map headers middleware to filter
fn map_headers_middleware(
    name: &str,
    headers: &Headers,
    location: &SourceLocation,
) -> Option<Filter> {
    let mut request_remove = Vec::new();
    let mut response_add = Vec::new();

    // Custom request headers (remove empty ones)
    if let Some(custom) = &headers.custom_request_headers {
        for (k, v) in custom {
            if v.is_empty() {
                request_remove.push(k.clone());
            }
        }
    }

    // Custom response headers
    if let Some(custom) = &headers.custom_response_headers {
        for (k, v) in custom {
            if !v.is_empty() {
                response_add.push(HeaderOperation {
                    name: k.clone(),
                    value: v.clone(),
                    operation: crate::ir::HeaderOperationType::Set,
                });
            }
        }
    }

    // Security headers
    if headers.sts_seconds.is_some() {
        let mut value = format!("max-age={}", headers.sts_seconds.unwrap_or(31536000));
        if headers.sts_include_subdomains.unwrap_or(false) {
            value.push_str("; includeSubDomains");
        }
        if headers.sts_preload.unwrap_or(false) {
            value.push_str("; preload");
        }
        response_add.push(HeaderOperation {
            name: "Strict-Transport-Security".to_string(),
            value,
            operation: crate::ir::HeaderOperationType::Set,
        });
    }

    if headers.frame_deny.unwrap_or(false) {
        response_add.push(HeaderOperation {
            name: "X-Frame-Options".to_string(),
            value: "DENY".to_string(),
            operation: crate::ir::HeaderOperationType::Set,
        });
    } else if let Some(value) = &headers.custom_frame_options_value {
        response_add.push(HeaderOperation {
            name: "X-Frame-Options".to_string(),
            value: value.clone(),
            operation: crate::ir::HeaderOperationType::Set,
        });
    }

    if headers.content_type_nosniff.unwrap_or(false) {
        response_add.push(HeaderOperation {
            name: "X-Content-Type-Options".to_string(),
            value: "nosniff".to_string(),
            operation: crate::ir::HeaderOperationType::Set,
        });
    }

    if headers.browser_xss_filter.unwrap_or(false) {
        response_add.push(HeaderOperation {
            name: "X-XSS-Protection".to_string(),
            value: headers
                .custom_browser_xss_value
                .clone()
                .unwrap_or_else(|| "1; mode=block".to_string()),
            operation: crate::ir::HeaderOperationType::Set,
        });
    }

    if let Some(csp) = &headers.content_security_policy {
        response_add.push(HeaderOperation {
            name: "Content-Security-Policy".to_string(),
            value: csp.clone(),
            operation: crate::ir::HeaderOperationType::Set,
        });
    }

    if let Some(referrer) = &headers.referrer_policy {
        response_add.push(HeaderOperation {
            name: "Referrer-Policy".to_string(),
            value: referrer.clone(),
            operation: crate::ir::HeaderOperationType::Set,
        });
    }

    if let Some(permissions) = &headers.permissions_policy {
        response_add.push(HeaderOperation {
            name: "Permissions-Policy".to_string(),
            value: permissions.clone(),
            operation: crate::ir::HeaderOperationType::Set,
        });
    }

    if response_add.is_empty() && request_remove.is_empty() {
        return None;
    }

    Some(Filter {
        name: name.to_string(),
        filter_type: FilterType::Headers,
        config: FilterConfig::Headers(HeadersFilterConfig {
            request_add: Vec::new(),
            request_remove,
            response_add,
            response_remove: Vec::new(),
        }),
        source: Some(location.clone()),
    })
}

/// Map a Traefik router to a Sentinel route
fn map_router(
    name: &str,
    router: &Router,
    middlewares: &HashMap<String, Middleware>,
    ctx: &ParseContext,
    diagnostics: &mut Diagnostics,
) -> Option<Route> {
    let location = SourceLocation::new(ctx.primary_path.clone(), 0);

    // Parse the rule to extract matchers
    let matchers = if let Some(rule) = &router.rule {
        parse_traefik_rule(rule, diagnostics)
    } else {
        Vec::new()
    };

    // Determine upstream
    let upstream_name = router.service.clone().unwrap_or_default();

    // Map middlewares to middleware refs
    let middleware_refs: Vec<MiddlewareRef> = router
        .middlewares
        .iter()
        .filter_map(|mw_name| {
            if let Some(mw) = middlewares.get(mw_name) {
                // Return appropriate middleware name
                if mw.headers.is_some()
                    || mw.strip_prefix.is_some()
                    || mw.add_prefix.is_some()
                    || mw.compress.is_some()
                {
                    return Some(MiddlewareRef::from(mw_name.as_str()));
                }
                if mw.rate_limit.is_some() {
                    return Some(MiddlewareRef::from(format!("{}-ratelimit", mw_name)));
                }
                if mw.basic_auth.is_some() || mw.forward_auth.is_some() {
                    return Some(MiddlewareRef::from(format!("{}-auth", mw_name)));
                }
                if mw.ip_white_list.is_some() {
                    return Some(MiddlewareRef::from(format!("{}-waf", mw_name)));
                }
            }
            None
        })
        .collect();

    // Handle TLS
    if router.tls.is_some() {
        add_info(
            diagnostics,
            &format!(
                "Router '{}' has TLS configuration - ensure listener has TLS enabled",
                name
            ),
            Some(location.clone()),
        );
    }

    Some(Route {
        name: name.to_string(),
        priority: router.priority,
        matchers,
        action: RouteAction::Forward {
            upstream: upstream_name,
            path_rewrite: None,
            host_rewrite: None,
            timeout_ms: None,
        },
        middleware: middleware_refs,
        metadata: RouteMetadata::default(),
        source: Some(location),
    })
}

/// Parse Traefik rule syntax into route matchers
fn parse_traefik_rule(rule: &str, diagnostics: &mut Diagnostics) -> Vec<RouteMatcher> {
    let mut matchers = Vec::new();

    // Traefik rule format examples:
    // Host(`example.com`)
    // Host(`example.com`) && PathPrefix(`/api`)
    // Host(`example.com`, `www.example.com`)
    // HostRegexp(`{subdomain:[a-z]+}.example.com`)
    // PathPrefix(`/api`) || PathPrefix(`/v1`)
    // Headers(`X-Custom`, `value`)
    // Method(`GET`, `POST`)

    let rule = rule.trim();

    // Split by && and || (simplified - doesn't handle complex nesting)
    for part in rule.split("&&").flat_map(|s| s.split("||")) {
        let part = part.trim();

        if part.starts_with("Host(") || part.starts_with("Host`") {
            if let Some(hosts) = extract_function_args(part, "Host") {
                matchers.push(RouteMatcher::Host(HostMatch {
                    patterns: hosts,
                    exact: false,
                }));
            }
        } else if part.starts_with("HostRegexp(") {
            if let Some(patterns) = extract_function_args(part, "HostRegexp") {
                matchers.push(RouteMatcher::Host(HostMatch {
                    patterns,
                    exact: false, // regex pattern
                }));
            }
        } else if part.starts_with("PathPrefix(") || part.starts_with("PathPrefix`") {
            if let Some(prefixes) = extract_function_args(part, "PathPrefix") {
                for prefix in prefixes {
                    matchers.push(RouteMatcher::Path(PathMatch {
                        pattern: prefix,
                        match_type: PathMatchType::Prefix,
                    }));
                }
            }
        } else if part.starts_with("Path(") || part.starts_with("Path`") {
            if let Some(paths) = extract_function_args(part, "Path") {
                for path in paths {
                    matchers.push(RouteMatcher::Path(PathMatch {
                        pattern: path,
                        match_type: PathMatchType::Exact,
                    }));
                }
            }
        } else if part.starts_with("PathRegexp(") {
            if let Some(patterns) = extract_function_args(part, "PathRegexp") {
                for pattern in patterns {
                    matchers.push(RouteMatcher::Path(PathMatch {
                        pattern,
                        match_type: PathMatchType::Regex,
                    }));
                }
            }
        } else if part.starts_with("Method(") {
            if let Some(methods) = extract_function_args(part, "Method") {
                let http_methods: Vec<_> = methods
                    .iter()
                    .filter_map(|m| parse_http_method(m))
                    .collect();
                if !http_methods.is_empty() {
                    matchers.push(RouteMatcher::Method {
                        methods: http_methods,
                    });
                }
            }
        } else if part.starts_with("Headers(") {
            if let Some(args) = extract_function_args(part, "Headers") {
                if args.len() >= 2 {
                    matchers.push(RouteMatcher::Header(HeaderMatch {
                        name: args[0].clone(),
                        pattern: args[1].clone(),
                        regex: false,
                    }));
                }
            }
        } else if part.starts_with("HeadersRegexp(") {
            if let Some(args) = extract_function_args(part, "HeadersRegexp") {
                if args.len() >= 2 {
                    matchers.push(RouteMatcher::Header(HeaderMatch {
                        name: args[0].clone(),
                        pattern: args[1].clone(),
                        regex: true,
                    }));
                }
            }
        } else if part.starts_with("Query(") {
            add_warning(
                diagnostics,
                &format!("Query matcher not directly supported: {}", part),
                None,
            );
        } else if part.starts_with("ClientIP(") {
            add_info(
                diagnostics,
                "ClientIP matcher detected - consider using WAF agent for IP filtering",
                None,
            );
        } else if !part.is_empty() {
            add_warning(
                diagnostics,
                &format!("Unrecognized rule component: {}", part),
                None,
            );
        }
    }

    matchers
}

/// Parse HTTP method string
fn parse_http_method(method: &str) -> Option<crate::ir::HttpMethod> {
    use crate::ir::HttpMethod;
    match method.to_uppercase().as_str() {
        "GET" => Some(HttpMethod::Get),
        "POST" => Some(HttpMethod::Post),
        "PUT" => Some(HttpMethod::Put),
        "DELETE" => Some(HttpMethod::Delete),
        "PATCH" => Some(HttpMethod::Patch),
        "HEAD" => Some(HttpMethod::Head),
        "OPTIONS" => Some(HttpMethod::Options),
        "CONNECT" => Some(HttpMethod::Connect),
        "TRACE" => Some(HttpMethod::Trace),
        _ => None,
    }
}

/// Extract arguments from function-style Traefik rule
fn extract_function_args(part: &str, func_name: &str) -> Option<Vec<String>> {
    let content = part
        .strip_prefix(func_name)?
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim();

    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_backtick = false;

    for c in content.chars() {
        match c {
            '`' => {
                if in_backtick {
                    if !current.is_empty() {
                        args.push(current.clone());
                        current.clear();
                    }
                }
                in_backtick = !in_backtick;
            }
            ',' if !in_backtick => {
                // Skip comma between arguments
            }
            ' ' if !in_backtick => {
                // Skip whitespace outside backticks
            }
            _ if in_backtick => {
                current.push(c);
            }
            _ => {}
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    if args.is_empty() {
        None
    } else {
        Some(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bind_address() {
        assert_eq!(format_bind_address(":80"), "0.0.0.0:80");
        assert_eq!(format_bind_address(":443"), "0.0.0.0:443");
        assert_eq!(format_bind_address("0.0.0.0:8080"), "0.0.0.0:8080");
        assert_eq!(format_bind_address("127.0.0.1:9000"), "127.0.0.1:9000");
    }

    #[test]
    fn test_parse_port() {
        assert_eq!(parse_port(":80"), 80);
        assert_eq!(parse_port(":443"), 443);
        assert_eq!(parse_port("0.0.0.0:8080"), 8080);
    }

    #[test]
    fn test_parse_server_url() {
        assert_eq!(
            parse_server_url_to_address("http://10.0.0.1:8080"),
            "10.0.0.1:8080"
        );
        assert_eq!(
            parse_server_url_to_address("https://backend.local:443"),
            "backend.local:443"
        );
        assert_eq!(
            parse_server_url_to_address("http://localhost"),
            "localhost"
        );
    }

    #[test]
    fn test_extract_function_args() {
        assert_eq!(
            extract_function_args("Host(`example.com`)", "Host"),
            Some(vec!["example.com".to_string()])
        );
        assert_eq!(
            extract_function_args("Host(`a.com`, `b.com`)", "Host"),
            Some(vec!["a.com".to_string(), "b.com".to_string()])
        );
        assert_eq!(
            extract_function_args("PathPrefix(`/api`)", "PathPrefix"),
            Some(vec!["/api".to_string()])
        );
    }

    #[test]
    fn test_parse_traefik_rule() {
        let mut diag = Diagnostics::default();

        let matchers = parse_traefik_rule("Host(`example.com`)", &mut diag);
        assert_eq!(matchers.len(), 1);

        let matchers = parse_traefik_rule("Host(`example.com`) && PathPrefix(`/api`)", &mut diag);
        assert_eq!(matchers.len(), 2);
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration_ms(Some("10s")), Some(10000));
        assert_eq!(parse_duration_ms(Some("1m")), Some(60000));
        assert_eq!(parse_duration_ms(Some("500ms")), Some(500));
        assert_eq!(parse_duration_ms(None), None);
    }
}
