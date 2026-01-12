//! Caddy to IR mapping

use super::{directives, CaddyConfig, Directive, SiteAddress, SiteBlock};
use crate::ir::{
    Agent, AgentConfig, AgentDetection, AgentType, AuthAgentConfig, AuthType, AuthTypeConfig,
    BindAddress, CompressionAlgorithm, CompressionFilterConfig, Confidence, ConversionWarning,
    Diagnostics, Endpoint, FailureMode, Filter, FilterConfig, FilterType, HeaderOperation,
    HeaderOperationType, HeadersFilterConfig, HealthCheck, HealthCheckType, HostMatch, Listener,
    ListenerOptions, LoadBalancing, MiddlewareRef, PathMatch, PathMatchType, Protocol,
    RateLimitAgentConfig, RateLimitKey, RateLimitRule, Route, RouteAction, RouteMatcher,
    RouteMetadata, SentinelConfig, Severity, SourceLocation, TlsConfig, Upstream,
};
use crate::parsers::{ParseContext, ParseError, ParseOutput};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

/// Convert Caddy config to Sentinel IR
pub fn map_caddy_to_ir(
    config: CaddyConfig,
    ctx: &ParseContext,
) -> Result<ParseOutput, ParseError> {
    let mut sentinel = SentinelConfig::default();
    let mut diagnostics = Diagnostics::default();

    // Track unique listeners by address
    let mut listener_addresses: HashSet<String> = HashSet::new();
    let mut upstream_counter = 0;

    // Process global options
    if let Some(global) = &config.global_options {
        process_global_options(global, &mut diagnostics);
    }

    // Process each site block
    for site in &config.sites {
        // Create listeners for site addresses
        for addr in &site.addresses {
            if let Some(listener) = create_listener_from_address(addr, &mut listener_addresses) {
                sentinel.listeners.push(listener);
            }
        }

        // Process site directives
        let (routes, upstreams, filters, agents) = process_site_block(
            site,
            &mut upstream_counter,
            ctx,
            &mut diagnostics,
        );

        sentinel.routes.extend(routes);
        for (name, upstream) in upstreams {
            sentinel.upstreams.insert(name, upstream);
        }
        for (name, filter) in filters {
            sentinel.filters.insert(name, filter);
        }
        sentinel.agents.extend(agents);
    }

    // Handle snippets
    for snippet in &config.snippets {
        add_info(
            &mut diagnostics,
            &format!("Snippet '{}' defined - expand via import directives", snippet.name),
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

/// Process global options
fn process_global_options(global: &super::GlobalOptions, diagnostics: &mut Diagnostics) {
    if let Some(email) = &global.email {
        add_info(
            diagnostics,
            &format!("ACME email configured: {}", email),
            None,
        );
    }

    if let Some(admin) = &global.admin {
        add_info(
            diagnostics,
            &format!("Admin endpoint: {} - not mapped to Sentinel", admin),
            None,
        );
    }

    if let Some(auto_https) = &global.auto_https {
        add_info(
            diagnostics,
            &format!("Auto HTTPS mode: {}", auto_https),
            None,
        );
    }
}

/// Create listener from site address
fn create_listener_from_address(
    addr: &SiteAddress,
    seen: &mut HashSet<String>,
) -> Option<Listener> {
    let port = addr.port.unwrap_or_else(|| {
        if addr.scheme.as_deref() == Some("https") {
            443
        } else if addr.scheme.as_deref() == Some("http") {
            80
        } else {
            // Caddy defaults to HTTPS
            443
        }
    });

    let bind_addr = format!("0.0.0.0:{}", port);

    // Skip if we've already created a listener for this address
    if seen.contains(&bind_addr) {
        return None;
    }
    seen.insert(bind_addr.clone());

    let protocol = if port == 443 || addr.scheme.as_deref() == Some("https") {
        Protocol::Https
    } else {
        Protocol::Http
    };

    let tls = if protocol == Protocol::Https {
        Some(TlsConfig::default())
    } else {
        None
    };

    let name = format!("listener-{}", port);

    Some(Listener {
        name,
        bind: BindAddress::Single(bind_addr),
        protocol,
        tls,
        options: ListenerOptions::default(),
        source: None,
    })
}

/// Process a site block and return routes, upstreams, filters, and agents
fn process_site_block(
    site: &SiteBlock,
    upstream_counter: &mut u32,
    ctx: &ParseContext,
    diagnostics: &mut Diagnostics,
) -> (
    Vec<Route>,
    HashMap<String, Upstream>,
    HashMap<String, Filter>,
    Vec<Agent>,
) {
    let mut routes = Vec::new();
    let mut upstreams = HashMap::new();
    let mut filters = HashMap::new();
    let mut agents = Vec::new();

    // Build host matchers from site addresses
    let host_patterns: Vec<String> = site
        .addresses
        .iter()
        .filter_map(|a| a.host.clone())
        .collect();

    // Track matchers defined in this site
    let mut named_matchers: HashMap<String, Vec<RouteMatcher>> = HashMap::new();

    // First pass: collect named matchers
    for directive in &site.directives {
        if directive.name.starts_with('@') {
            let matcher_name = directive.name.clone();
            let matchers = parse_matcher_directive(directive);
            named_matchers.insert(matcher_name, matchers);
        }
    }

    // Second pass: process directives
    for directive in &site.directives {
        match directive.name.as_str() {
            directives::REVERSE_PROXY => {
                let (route, upstream) = process_reverse_proxy(
                    directive,
                    &host_patterns,
                    &named_matchers,
                    upstream_counter,
                    ctx,
                    diagnostics,
                );
                if let Some(r) = route {
                    routes.push(r);
                }
                if let Some((name, u)) = upstream {
                    upstreams.insert(name, u);
                }
            }
            directives::FILE_SERVER => {
                if let Some(route) = process_file_server(directive, &host_patterns, &named_matchers, ctx) {
                    routes.push(route);
                }
            }
            directives::ENCODE => {
                if let Some((name, filter)) = process_encode(directive, &site.location) {
                    filters.insert(name, filter);
                }
            }
            directives::HEADER | directives::REQUEST_HEADER | directives::RESPONSE_HEADER => {
                if let Some((name, filter)) = process_header_directive(directive, &site.location) {
                    filters.insert(name, filter);
                }
            }
            directives::BASICAUTH => {
                if let Some(agent) = process_basicauth(directive, &site.location) {
                    agents.push(agent);
                }
            }
            directives::FORWARD_AUTH => {
                if let Some(agent) = process_forward_auth(directive, &site.location, diagnostics) {
                    agents.push(agent);
                }
            }
            directives::RATE_LIMIT => {
                if let Some(agent) = process_rate_limit(directive, &site.location) {
                    agents.push(agent);
                }
            }
            directives::HANDLE | directives::HANDLE_PATH => {
                // Process nested handle blocks
                let (sub_routes, sub_upstreams, sub_filters, sub_agents) =
                    process_handle_block(directive, &host_patterns, &named_matchers, upstream_counter, ctx, diagnostics);
                routes.extend(sub_routes);
                upstreams.extend(sub_upstreams);
                filters.extend(sub_filters);
                agents.extend(sub_agents);
            }
            directives::REDIR => {
                if let Some(route) = process_redir(directive, &host_patterns, &named_matchers, ctx) {
                    routes.push(route);
                }
            }
            directives::RESPOND => {
                if let Some(route) = process_respond(directive, &host_patterns, &named_matchers, ctx) {
                    routes.push(route);
                }
            }
            directives::TLS => {
                process_tls_directive(directive, diagnostics);
            }
            directives::LOG => {
                add_info(diagnostics, "Log directive detected - configure observability", Some(directive.location.clone()));
            }
            directives::IMPORT => {
                add_info(
                    diagnostics,
                    &format!("Import directive: {} - expand manually", directive.args.first().unwrap_or(&String::new())),
                    Some(directive.location.clone()),
                );
            }
            name if name.starts_with('@') => {
                // Named matcher definition, already processed
            }
            _ => {
                add_warning(
                    diagnostics,
                    &format!("Unhandled directive: {}", directive.name),
                    Some(directive.location.clone()),
                );
            }
        }
    }

    (routes, upstreams, filters, agents)
}

/// Parse matcher directive
fn parse_matcher_directive(directive: &Directive) -> Vec<RouteMatcher> {
    let mut matchers = Vec::new();

    // Check block for matcher conditions
    if let Some(block) = &directive.block {
        for sub in block {
            match sub.name.as_str() {
                "path" => {
                    for arg in &sub.args {
                        if arg.contains('*') {
                            matchers.push(RouteMatcher::Path(PathMatch {
                                pattern: arg.replace("*", ""),
                                match_type: PathMatchType::Prefix,
                            }));
                        } else {
                            matchers.push(RouteMatcher::Path(PathMatch {
                                pattern: arg.clone(),
                                match_type: PathMatchType::Exact,
                            }));
                        }
                    }
                }
                "path_regexp" => {
                    if let Some(pattern) = sub.args.first() {
                        matchers.push(RouteMatcher::Path(PathMatch {
                            pattern: pattern.clone(),
                            match_type: PathMatchType::Regex,
                        }));
                    }
                }
                "host" => {
                    let patterns: Vec<String> = sub.args.iter().cloned().collect();
                    if !patterns.is_empty() {
                        matchers.push(RouteMatcher::Host(HostMatch {
                            patterns,
                            exact: false,
                        }));
                    }
                }
                "method" => {
                    let methods: Vec<_> = sub.args.iter()
                        .filter_map(|m| parse_http_method(m))
                        .collect();
                    if !methods.is_empty() {
                        matchers.push(RouteMatcher::Method { methods });
                    }
                }
                "header" => {
                    if sub.args.len() >= 2 {
                        matchers.push(RouteMatcher::Header(crate::ir::HeaderMatch {
                            name: sub.args[0].clone(),
                            pattern: sub.args[1].clone(),
                            regex: false,
                        }));
                    }
                }
                _ => {}
            }
        }
    }

    // Also check args for inline path matcher
    for arg in &directive.args {
        if arg.starts_with('/') {
            if arg.contains('*') {
                matchers.push(RouteMatcher::Path(PathMatch {
                    pattern: arg.replace("*", ""),
                    match_type: PathMatchType::Prefix,
                }));
            } else {
                matchers.push(RouteMatcher::Path(PathMatch {
                    pattern: arg.clone(),
                    match_type: PathMatchType::Exact,
                }));
            }
        }
    }

    matchers
}

/// Parse HTTP method
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

/// Get matchers for a directive
fn get_directive_matchers(
    directive: &Directive,
    host_patterns: &[String],
    named_matchers: &HashMap<String, Vec<RouteMatcher>>,
) -> Vec<RouteMatcher> {
    let mut matchers = Vec::new();

    // Add host matchers if present
    if !host_patterns.is_empty() {
        matchers.push(RouteMatcher::Host(HostMatch {
            patterns: host_patterns.to_vec(),
            exact: false,
        }));
    }

    // Check for named matcher reference
    if let Some(matcher_ref) = &directive.matcher {
        if matcher_ref.starts_with('@') {
            if let Some(named) = named_matchers.get(matcher_ref) {
                matchers.extend(named.clone());
            }
        } else if matcher_ref.starts_with('/') {
            // Inline path matcher
            if matcher_ref.contains('*') {
                matchers.push(RouteMatcher::Path(PathMatch {
                    pattern: matcher_ref.trim_end_matches('*').to_string(),
                    match_type: PathMatchType::Prefix,
                }));
            } else {
                matchers.push(RouteMatcher::Path(PathMatch {
                    pattern: matcher_ref.clone(),
                    match_type: PathMatchType::Exact,
                }));
            }
        } else if matcher_ref == "*" {
            // Match all - no additional matchers needed
        }
    }

    matchers
}

/// Process reverse_proxy directive
fn process_reverse_proxy(
    directive: &Directive,
    host_patterns: &[String],
    named_matchers: &HashMap<String, Vec<RouteMatcher>>,
    upstream_counter: &mut u32,
    ctx: &ParseContext,
    diagnostics: &mut Diagnostics,
) -> (Option<Route>, Option<(String, Upstream)>) {
    *upstream_counter += 1;
    let upstream_name = format!("upstream-{}", upstream_counter);

    // Parse upstream targets from args
    let mut endpoints = Vec::new();
    for arg in &directive.args {
        if !arg.starts_with('/') && !arg.starts_with('@') && !arg.starts_with('*') {
            endpoints.push(Endpoint {
                address: arg.clone(),
                weight: None,
                backup: false,
                slow_start_ms: None,
                max_connections: None,
            });
        }
    }

    // Check block for additional configuration
    let mut health_check = None;
    let mut load_balancing = LoadBalancing::RoundRobin;

    if let Some(block) = &directive.block {
        for sub in block {
            match sub.name.as_str() {
                "to" => {
                    // Additional targets
                    for arg in &sub.args {
                        endpoints.push(Endpoint {
                            address: arg.clone(),
                            weight: None,
                            backup: false,
                            slow_start_ms: None,
                            max_connections: None,
                        });
                    }
                }
                "lb_policy" => {
                    if let Some(policy) = sub.args.first() {
                        load_balancing = match policy.as_str() {
                            "round_robin" => LoadBalancing::RoundRobin,
                            "least_conn" => LoadBalancing::LeastConnections,
                            "ip_hash" => LoadBalancing::IpHash,
                            "random" => LoadBalancing::Random,
                            "first" => LoadBalancing::RoundRobin, // Approximate
                            _ => LoadBalancing::RoundRobin,
                        };
                    }
                }
                "health_uri" | "health_path" => {
                    let path = sub.args.first().cloned().unwrap_or_else(|| "/".to_string());
                    health_check = Some(HealthCheck {
                        check_type: HealthCheckType::Http {
                            path,
                            expected_status: vec![200],
                        },
                        interval_ms: 10000,
                        timeout_ms: 5000,
                        healthy_threshold: 2,
                        unhealthy_threshold: 3,
                    });
                }
                "health_interval" => {
                    if let Some(interval) = sub.args.first() {
                        if let Some(ms) = parse_caddy_duration(interval) {
                            if let Some(hc) = health_check.as_mut() {
                                hc.interval_ms = ms;
                            }
                        }
                    }
                }
                "header_up" | "header_down" => {
                    add_info(
                        diagnostics,
                        &format!("reverse_proxy header modification: {} - map to headers filter", sub.name),
                        Some(directive.location.clone()),
                    );
                }
                _ => {}
            }
        }
    }

    if endpoints.is_empty() {
        return (None, None);
    }

    let upstream = Upstream {
        name: upstream_name.clone(),
        endpoints,
        load_balancing,
        health_check,
        circuit_breaker: None,
        connection_pool: None,
        timeouts: None,
        tls: None,
        source: Some(directive.location.clone()),
    };

    let matchers = get_directive_matchers(directive, host_patterns, named_matchers);

    let route = Route {
        name: format!("route-{}", upstream_counter),
        priority: None,
        matchers,
        action: RouteAction::Forward {
            upstream: upstream_name.clone(),
            path_rewrite: None,
            host_rewrite: None,
            timeout_ms: None,
        },
        middleware: Vec::new(),
        metadata: RouteMetadata::default(),
        source: Some(directive.location.clone()),
    };

    (Some(route), Some((upstream_name, upstream)))
}

/// Process file_server directive
fn process_file_server(
    directive: &Directive,
    host_patterns: &[String],
    named_matchers: &HashMap<String, Vec<RouteMatcher>>,
    ctx: &ParseContext,
) -> Option<Route> {
    let matchers = get_directive_matchers(directive, host_patterns, named_matchers);

    // file_server browse enables directory listing
    let directory_listing = directive.args.iter().any(|a| a == "browse");

    // Get root from directive or default
    let root = directive
        .get_subdirective("root")
        .and_then(|d| d.first_arg())
        .map(|s| PathBuf::from(s))
        .unwrap_or_else(|| PathBuf::from("/var/www/html"));

    Some(Route {
        name: format!("static-{}", host_patterns.first().unwrap_or(&"default".to_string())),
        priority: Some(-100), // Lower priority for static files
        matchers,
        action: RouteAction::Static {
            root,
            index: Some(vec!["index.html".to_string(), "index.htm".to_string()]),
            directory_listing,
        },
        middleware: Vec::new(),
        metadata: RouteMetadata::default(),
        source: Some(directive.location.clone()),
    })
}

/// Process encode directive
fn process_encode(directive: &Directive, location: &SourceLocation) -> Option<(String, Filter)> {
    let mut algorithms = Vec::new();

    for arg in &directive.args {
        match arg.as_str() {
            "gzip" => algorithms.push(CompressionAlgorithm::Gzip),
            "zstd" => algorithms.push(CompressionAlgorithm::Zstd),
            "br" => algorithms.push(CompressionAlgorithm::Brotli),
            _ => {}
        }
    }

    if algorithms.is_empty() {
        algorithms = vec![CompressionAlgorithm::Gzip, CompressionAlgorithm::Zstd];
    }

    let filter = Filter {
        name: "compression".to_string(),
        filter_type: FilterType::Compression,
        config: FilterConfig::Compression(CompressionFilterConfig {
            algorithms,
            min_size: Some(1024),
            mime_types: None,
            level: None,
        }),
        source: Some(location.clone()),
    };

    Some(("compression".to_string(), filter))
}

/// Process header directive
fn process_header_directive(
    directive: &Directive,
    location: &SourceLocation,
) -> Option<(String, Filter)> {
    let mut response_add = Vec::new();
    let mut response_remove = Vec::new();

    // Process args
    if directive.args.len() >= 2 {
        let name = &directive.args[0];
        let value = &directive.args[1];

        if value.is_empty() || value == "-" {
            response_remove.push(name.clone());
        } else {
            response_add.push(HeaderOperation {
                name: name.clone(),
                value: value.clone(),
                operation: HeaderOperationType::Set,
            });
        }
    }

    // Process block
    if let Some(block) = &directive.block {
        for sub in block {
            if sub.args.len() >= 2 {
                let name = &sub.args[0];
                let value = &sub.args[1];

                if value.is_empty() || value == "-" {
                    response_remove.push(name.clone());
                } else {
                    let op = if sub.name == "+" {
                        HeaderOperationType::Add
                    } else {
                        HeaderOperationType::Set
                    };
                    response_add.push(HeaderOperation {
                        name: name.clone(),
                        value: value.clone(),
                        operation: op,
                    });
                }
            } else if sub.args.len() == 1 && sub.name == "-" {
                response_remove.push(sub.args[0].clone());
            }
        }
    }

    if response_add.is_empty() && response_remove.is_empty() {
        return None;
    }

    let filter_name = format!("headers-{}", directive.location.line);
    let filter = Filter {
        name: filter_name.clone(),
        filter_type: FilterType::Headers,
        config: FilterConfig::Headers(HeadersFilterConfig {
            request_add: Vec::new(),
            request_remove: Vec::new(),
            response_add,
            response_remove,
        }),
        source: Some(location.clone()),
    };

    Some((filter_name, filter))
}

/// Process basicauth directive
fn process_basicauth(directive: &Directive, location: &SourceLocation) -> Option<Agent> {
    let realm = directive.args.first().cloned();

    Some(Agent {
        name: "basicauth".to_string(),
        agent_type: AgentType::Auth,
        config: AgentConfig::Auth(AuthAgentConfig {
            socket_path: PathBuf::from("/run/sentinel/auth.sock"),
            auth_type: AuthType::Basic,
            type_config: AuthTypeConfig::Basic {
                realm,
                htpasswd_path: None,
            },
            timeout_ms: Some(100),
            failure_mode: FailureMode::Closed,
        }),
        routes: Vec::new(),
        detection: AgentDetection::Inferred {
            confidence: Confidence::High,
            patterns_matched: vec!["caddy basicauth directive".to_string()],
        },
        source: Some(location.clone()),
    })
}

/// Process forward_auth directive
fn process_forward_auth(
    directive: &Directive,
    location: &SourceLocation,
    diagnostics: &mut Diagnostics,
) -> Option<Agent> {
    let address = directive.args.first().cloned();

    if let Some(addr) = &address {
        add_info(
            diagnostics,
            &format!("Forward auth configured to: {}", addr),
            Some(location.clone()),
        );
    }

    Some(Agent {
        name: "forward-auth".to_string(),
        agent_type: AgentType::Auth,
        config: AgentConfig::Auth(AuthAgentConfig {
            socket_path: PathBuf::from("/run/sentinel/forward-auth.sock"),
            auth_type: AuthType::Custom,
            type_config: AuthTypeConfig::Unknown,
            timeout_ms: Some(100),
            failure_mode: FailureMode::Closed,
        }),
        routes: Vec::new(),
        detection: AgentDetection::Inferred {
            confidence: Confidence::High,
            patterns_matched: vec!["caddy forward_auth directive".to_string()],
        },
        source: Some(location.clone()),
    })
}

/// Process rate_limit directive
fn process_rate_limit(directive: &Directive, location: &SourceLocation) -> Option<Agent> {
    let mut limits = Vec::new();

    // Parse rate limit zones from block
    if let Some(block) = &directive.block {
        for sub in block {
            if sub.name == "zone" {
                let zone_name = sub.args.first().cloned().unwrap_or_else(|| "default".to_string());
                let mut rate = 100u32;
                let mut period_ms = 1000u64;
                let mut burst = None;
                let mut key = RateLimitKey::SourceIp;

                if let Some(zone_block) = &sub.block {
                    for param in zone_block {
                        match param.name.as_str() {
                            "key" => {
                                if let Some(k) = param.args.first() {
                                    key = match k.as_str() {
                                        "static" => RateLimitKey::Global,
                                        "{remote_host}" | "{client_ip}" => RateLimitKey::SourceIp,
                                        _ if k.starts_with("{header.") => {
                                            let header = k.trim_start_matches("{header.")
                                                .trim_end_matches('}');
                                            RateLimitKey::Header(header.to_string())
                                        }
                                        _ => RateLimitKey::SourceIp,
                                    };
                                }
                            }
                            "events" => {
                                if let Some(v) = param.args.first() {
                                    rate = v.parse().unwrap_or(100);
                                }
                            }
                            "window" => {
                                if let Some(v) = param.args.first() {
                                    if let Some(ms) = parse_caddy_duration(v) {
                                        period_ms = ms;
                                    }
                                }
                            }
                            "burst" => {
                                if let Some(v) = param.args.first() {
                                    burst = v.parse().ok();
                                }
                            }
                            _ => {}
                        }
                    }
                }

                limits.push(RateLimitRule {
                    name: zone_name,
                    key,
                    rate,
                    period_ms,
                    burst,
                });
            }
        }
    }

    if limits.is_empty() {
        // Default rate limit
        limits.push(RateLimitRule {
            name: "default".to_string(),
            key: RateLimitKey::SourceIp,
            rate: 100,
            period_ms: 1000,
            burst: Some(50),
        });
    }

    Some(Agent {
        name: "rate-limit".to_string(),
        agent_type: AgentType::RateLimit,
        config: AgentConfig::RateLimit(RateLimitAgentConfig {
            socket_path: PathBuf::from("/run/sentinel/ratelimit.sock"),
            limits,
            timeout_ms: Some(50),
            failure_mode: FailureMode::Open,
        }),
        routes: Vec::new(),
        detection: AgentDetection::Inferred {
            confidence: Confidence::High,
            patterns_matched: vec!["caddy rate_limit directive".to_string()],
        },
        source: Some(location.clone()),
    })
}

/// Process handle/handle_path block
fn process_handle_block(
    directive: &Directive,
    host_patterns: &[String],
    named_matchers: &HashMap<String, Vec<RouteMatcher>>,
    upstream_counter: &mut u32,
    ctx: &ParseContext,
    diagnostics: &mut Diagnostics,
) -> (
    Vec<Route>,
    HashMap<String, Upstream>,
    HashMap<String, Filter>,
    Vec<Agent>,
) {
    let mut routes = Vec::new();
    let mut upstreams = HashMap::new();
    let mut filters = HashMap::new();
    let mut agents = Vec::new();

    // Get path from handle_path or matcher
    let mut handle_matchers = get_directive_matchers(directive, host_patterns, named_matchers);

    // For handle_path, add path matcher from first arg
    if directive.name == directives::HANDLE_PATH {
        if let Some(path) = directive.args.first() {
            if path.ends_with('*') {
                handle_matchers.push(RouteMatcher::Path(PathMatch {
                    pattern: path.trim_end_matches('*').to_string(),
                    match_type: PathMatchType::Prefix,
                }));
            } else {
                handle_matchers.push(RouteMatcher::Path(PathMatch {
                    pattern: path.clone(),
                    match_type: PathMatchType::Exact,
                }));
            }
        }
    }

    // Process nested directives
    if let Some(block) = &directive.block {
        for sub in block {
            match sub.name.as_str() {
                directives::REVERSE_PROXY => {
                    let (route, upstream) = process_reverse_proxy(
                        sub,
                        &[], // Don't add host patterns again
                        named_matchers,
                        upstream_counter,
                        ctx,
                        diagnostics,
                    );
                    if let Some(mut r) = route {
                        // Add handle's matchers to route
                        r.matchers.extend(handle_matchers.clone());
                        routes.push(r);
                    }
                    if let Some((name, u)) = upstream {
                        upstreams.insert(name, u);
                    }
                }
                directives::FILE_SERVER => {
                    if let Some(mut route) = process_file_server(sub, &[], named_matchers, ctx) {
                        route.matchers.extend(handle_matchers.clone());
                        routes.push(route);
                    }
                }
                directives::RESPOND => {
                    if let Some(mut route) = process_respond(sub, &[], named_matchers, ctx) {
                        route.matchers.extend(handle_matchers.clone());
                        routes.push(route);
                    }
                }
                directives::REDIR => {
                    if let Some(mut route) = process_redir(sub, &[], named_matchers, ctx) {
                        route.matchers.extend(handle_matchers.clone());
                        routes.push(route);
                    }
                }
                _ => {}
            }
        }
    }

    (routes, upstreams, filters, agents)
}

/// Process redir directive
fn process_redir(
    directive: &Directive,
    host_patterns: &[String],
    named_matchers: &HashMap<String, Vec<RouteMatcher>>,
    ctx: &ParseContext,
) -> Option<Route> {
    let url = directive.args.first()?.clone();

    let status_code = directive
        .args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(302);

    let matchers = get_directive_matchers(directive, host_patterns, named_matchers);

    Some(Route {
        name: format!("redirect-{}", directive.location.line),
        priority: None,
        matchers,
        action: RouteAction::Redirect {
            url,
            status_code,
            preserve_path: false,
        },
        middleware: Vec::new(),
        metadata: RouteMetadata::default(),
        source: Some(directive.location.clone()),
    })
}

/// Process respond directive
fn process_respond(
    directive: &Directive,
    host_patterns: &[String],
    named_matchers: &HashMap<String, Vec<RouteMatcher>>,
    ctx: &ParseContext,
) -> Option<Route> {
    let body = directive.args.first().cloned();
    let status_code = directive
        .args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);

    let matchers = get_directive_matchers(directive, host_patterns, named_matchers);

    Some(Route {
        name: format!("respond-{}", directive.location.line),
        priority: None,
        matchers,
        action: RouteAction::FixedResponse {
            status_code,
            body,
            headers: Vec::new(),
        },
        middleware: Vec::new(),
        metadata: RouteMetadata::default(),
        source: Some(directive.location.clone()),
    })
}

/// Process TLS directive
fn process_tls_directive(directive: &Directive, diagnostics: &mut Diagnostics) {
    if directive.args.is_empty() || directive.args.first().map(|s| s.as_str()) == Some("internal") {
        add_info(
            diagnostics,
            "TLS with automatic certificates - Sentinel requires manual TLS configuration",
            Some(directive.location.clone()),
        );
    } else if directive.args.len() >= 2 {
        add_info(
            diagnostics,
            &format!(
                "TLS certificate: {}, key: {}",
                directive.args.get(0).unwrap_or(&String::new()),
                directive.args.get(1).unwrap_or(&String::new())
            ),
            Some(directive.location.clone()),
        );
    }
}

/// Parse Caddy duration string (e.g., "1m", "30s", "1h")
fn parse_caddy_duration(s: &str) -> Option<u64> {
    let s = s.trim();

    if s.ends_with("ms") {
        return s.trim_end_matches("ms").parse().ok();
    } else if s.ends_with('s') {
        let val: u64 = s.trim_end_matches('s').parse().ok()?;
        return Some(val * 1000);
    } else if s.ends_with('m') {
        let val: u64 = s.trim_end_matches('m').parse().ok()?;
        return Some(val * 60 * 1000);
    } else if s.ends_with('h') {
        let val: u64 = s.trim_end_matches('h').parse().ok()?;
        return Some(val * 3600 * 1000);
    }

    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_caddy_duration() {
        assert_eq!(parse_caddy_duration("1s"), Some(1000));
        assert_eq!(parse_caddy_duration("30s"), Some(30000));
        assert_eq!(parse_caddy_duration("1m"), Some(60000));
        assert_eq!(parse_caddy_duration("500ms"), Some(500));
        assert_eq!(parse_caddy_duration("1h"), Some(3600000));
    }
}
