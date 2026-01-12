//! HAProxy to IR mapping

use super::{HAProxyConfig, Section, SectionType};
use crate::ir::*;
use crate::parsers::{ParseContext, ParseError, ParseOutput};
use std::collections::HashMap;

/// Convert HAProxy config AST to Sentinel IR
pub fn map_haproxy_to_ir(config: HAProxyConfig, _ctx: &ParseContext) -> Result<ParseOutput, ParseError> {
    let mut sentinel_config = SentinelConfig::default();
    let mut diagnostics = Diagnostics::default();
    let mut acls: HashMap<String, AclDefinition> = HashMap::new();

    // Process global section
    if let Some(global) = &config.global {
        process_global(global, &mut sentinel_config, &mut diagnostics);
    }

    // Process defaults section
    let defaults = config.defaults.as_ref();

    // Process backends first to have upstreams ready
    for backend in &config.backends {
        if let Some(name) = &backend.name {
            let upstream = process_backend(backend, defaults, &mut diagnostics);
            sentinel_config.upstreams.insert(name.clone(), upstream);
        }
    }

    // Process frontends
    for frontend in &config.frontends {
        // Collect ACLs defined in this frontend
        collect_acls(frontend, &mut acls);

        // Create listeners and routes
        process_frontend(frontend, defaults, &acls, &mut sentinel_config, &mut diagnostics)?;
    }

    // Process listen sections (combined frontend + backend)
    for listen in &config.listens {
        collect_acls(listen, &mut acls);
        process_listen(listen, defaults, &acls, &mut sentinel_config, &mut diagnostics)?;
    }

    Ok(ParseOutput {
        config: sentinel_config,
        diagnostics,
    })
}

/// Temporary ACL definition storage
#[derive(Debug, Clone)]
struct AclDefinition {
    name: String,
    acl_type: String,
    pattern: String,
}

/// Collect ACL definitions from a section
fn collect_acls(section: &Section, acls: &mut HashMap<String, AclDefinition>) {
    for directive in section.find_all_directives("acl") {
        if directive.args.len() >= 2 {
            let name = directive.args[0].clone();
            let acl_type = directive.args[1].clone();
            let pattern = directive.args.get(2).cloned().unwrap_or_default();

            acls.insert(name.clone(), AclDefinition {
                name,
                acl_type,
                pattern,
            });
        }
    }
}

/// Process global section
fn process_global(global: &Section, config: &mut SentinelConfig, diagnostics: &mut Diagnostics) {
    for directive in &global.directives {
        match directive.name.as_str() {
            "maxconn" => {
                if let Some(val) = directive.first_arg() {
                    config.system.max_connections = val.parse().ok();
                }
            }
            "nbproc" | "nbthread" => {
                if let Some(val) = directive.first_arg() {
                    config.system.worker_threads = val.parse().ok();
                }
            }
            _ => {}
        }
    }

    diagnostics.converted.push(ConvertedItem {
        item_type: "global".to_string(),
        name: "global".to_string(),
        source_location: Some(global.location.clone()),
    });
}

/// Process a backend section into an Upstream
fn process_backend(
    backend: &Section,
    defaults: Option<&Section>,
    diagnostics: &mut Diagnostics,
) -> Upstream {
    let name = backend.name.clone().unwrap_or_else(|| "default".to_string());
    let mut upstream = Upstream {
        name: name.clone(),
        source: Some(backend.location.clone()),
        ..Default::default()
    };

    // Get mode from defaults or backend
    let _mode = backend
        .find_directive("mode")
        .or_else(|| defaults.and_then(|d| d.find_directive("mode")))
        .and_then(|d| d.first_arg())
        .unwrap_or("http");

    for directive in &backend.directives {
        match directive.name.as_str() {
            "server" => {
                if let Some(endpoint) = parse_server_directive(directive) {
                    upstream.endpoints.push(endpoint);
                }
            }
            "balance" => {
                upstream.load_balancing = parse_balance_algorithm(directive.first_arg());
            }
            "option httpchk" | "http-check" => {
                // Health check configuration
                let path = directive.arg(1).unwrap_or("/").to_string();
                upstream.health_check = Some(HealthCheck {
                    check_type: HealthCheckType::Http {
                        path,
                        expected_status: vec![200],
                    },
                    ..Default::default()
                });
            }
            _ => {}
        }
    }

    // Apply default timeouts
    if let Some(defaults) = defaults {
        if let Some(timeout) = defaults.find_directive("timeout server") {
            if let Some(ms) = parse_haproxy_time(timeout.first_arg()) {
                upstream.timeouts = Some(UpstreamTimeouts {
                    request_ms: Some(ms),
                    ..Default::default()
                });
            }
        }
        if let Some(timeout) = defaults.find_directive("timeout connect") {
            if let Some(ms) = parse_haproxy_time(timeout.first_arg()) {
                let timeouts = upstream.timeouts.get_or_insert(UpstreamTimeouts::default());
                timeouts.connect_ms = Some(ms);
            }
        }
    }

    diagnostics.converted.push(ConvertedItem {
        item_type: "backend".to_string(),
        name,
        source_location: Some(backend.location.clone()),
    });

    upstream
}

/// Parse a server directive into an Endpoint
fn parse_server_directive(directive: &super::Directive) -> Option<Endpoint> {
    if directive.args.len() < 2 {
        return None;
    }

    let _name = &directive.args[0];
    let address = &directive.args[1];

    let mut endpoint = Endpoint {
        address: address.clone(),
        ..Default::default()
    };

    // Parse additional options
    let mut i = 2;
    while i < directive.args.len() {
        match directive.args[i].as_str() {
            "weight" => {
                if let Some(w) = directive.args.get(i + 1) {
                    endpoint.weight = w.parse().ok();
                    i += 1;
                }
            }
            "backup" => {
                endpoint.backup = true;
            }
            "maxconn" => {
                if let Some(m) = directive.args.get(i + 1) {
                    endpoint.max_connections = m.parse().ok();
                    i += 1;
                }
            }
            "check" => {
                // Health check enabled (handled at backend level)
            }
            _ => {}
        }
        i += 1;
    }

    Some(endpoint)
}

/// Parse balance algorithm
fn parse_balance_algorithm(algo: Option<&str>) -> LoadBalancing {
    match algo {
        Some("roundrobin") => LoadBalancing::RoundRobin,
        Some("leastconn") => LoadBalancing::LeastConnections,
        Some("source") => LoadBalancing::IpHash,
        Some("random") => LoadBalancing::Random,
        Some("uri") => LoadBalancing::ConsistentHash { key: "uri".to_string() },
        Some("hdr") => LoadBalancing::ConsistentHash { key: "header".to_string() },
        _ => LoadBalancing::RoundRobin,
    }
}

/// Process a frontend section
fn process_frontend(
    frontend: &Section,
    defaults: Option<&Section>,
    acls: &HashMap<String, AclDefinition>,
    config: &mut SentinelConfig,
    diagnostics: &mut Diagnostics,
) -> Result<(), ParseError> {
    let frontend_name = frontend.name.clone().unwrap_or_else(|| "frontend".to_string());

    // Create listener from bind directives
    for bind in frontend.find_all_directives("bind") {
        if let Some(addr) = bind.first_arg() {
            let listener = create_listener_from_bind(&frontend_name, addr, bind, defaults);
            config.listeners.push(listener);
        }
    }

    // Process routing rules (use_backend with ACL conditions)
    let mut route_index = 0;
    for directive in &frontend.directives {
        match directive.name.as_str() {
            "use_backend" => {
                if let Some(backend_name) = directive.first_arg() {
                    let route = create_route_from_use_backend(
                        &frontend_name,
                        route_index,
                        backend_name,
                        directive,
                        acls,
                        diagnostics,
                    );
                    config.routes.push(route);
                    route_index += 1;
                }
            }
            "default_backend" => {
                if let Some(backend_name) = directive.first_arg() {
                    let route = Route {
                        name: format!("{}_default", frontend_name),
                        priority: Some(-100), // Low priority for default
                        matchers: Vec::new(), // Matches everything
                        action: RouteAction::Forward {
                            upstream: backend_name.to_string(),
                            path_rewrite: None,
                            host_rewrite: None,
                            timeout_ms: None,
                        },
                        source: Some(directive.location.clone()),
                        ..Default::default()
                    };
                    config.routes.push(route);
                }
            }
            "http-request deny" | "http-request reject" => {
                // WAF-like behavior
                diagnostics.agent_suggestions.push(AgentSuggestion {
                    agent_type: AgentType::Waf,
                    confidence: Confidence::Medium,
                    reason: format!("{} directive detected", directive.name),
                    source_locations: vec![directive.location.clone()],
                    ..Default::default()
                });
            }
            "http-request auth" => {
                // Auth detection
                diagnostics.agent_suggestions.push(AgentSuggestion {
                    agent_type: AgentType::Auth,
                    confidence: Confidence::High,
                    reason: "http-request auth directive detected".to_string(),
                    source_locations: vec![directive.location.clone()],
                    ..Default::default()
                });
            }
            "stick-table" => {
                // Rate limiting via stick tables
                diagnostics.agent_suggestions.push(AgentSuggestion {
                    agent_type: AgentType::RateLimit,
                    confidence: Confidence::High,
                    reason: "stick-table (rate limiting) detected".to_string(),
                    source_locations: vec![directive.location.clone()],
                    ..Default::default()
                });
            }
            "rate-limit" => {
                diagnostics.agent_suggestions.push(AgentSuggestion {
                    agent_type: AgentType::RateLimit,
                    confidence: Confidence::High,
                    reason: "rate-limit directive detected".to_string(),
                    source_locations: vec![directive.location.clone()],
                    ..Default::default()
                });
            }
            _ => {}
        }
    }

    diagnostics.converted.push(ConvertedItem {
        item_type: "frontend".to_string(),
        name: frontend_name,
        source_location: Some(frontend.location.clone()),
    });

    Ok(())
}

/// Process a listen section (combined frontend + backend)
fn process_listen(
    listen: &Section,
    defaults: Option<&Section>,
    acls: &HashMap<String, AclDefinition>,
    config: &mut SentinelConfig,
    diagnostics: &mut Diagnostics,
) -> Result<(), ParseError> {
    let listen_name = listen.name.clone().unwrap_or_else(|| "listen".to_string());

    // Create listener
    for bind in listen.find_all_directives("bind") {
        if let Some(addr) = bind.first_arg() {
            let listener = create_listener_from_bind(&listen_name, addr, bind, defaults);
            config.listeners.push(listener);
        }
    }

    // Create upstream from server directives
    let servers: Vec<_> = listen.find_all_directives("server");
    if !servers.is_empty() {
        let mut upstream = Upstream {
            name: format!("{}_backend", listen_name),
            source: Some(listen.location.clone()),
            ..Default::default()
        };

        for server in servers {
            if let Some(endpoint) = parse_server_directive(server) {
                upstream.endpoints.push(endpoint);
            }
        }

        // Get balance algorithm
        if let Some(balance) = listen.find_directive("balance") {
            upstream.load_balancing = parse_balance_algorithm(balance.first_arg());
        }

        let upstream_name = upstream.name.clone();
        config.upstreams.insert(upstream_name.clone(), upstream);

        // Create default route to this upstream
        let route = Route {
            name: format!("{}_route", listen_name),
            matchers: Vec::new(),
            action: RouteAction::Forward {
                upstream: upstream_name,
                path_rewrite: None,
                host_rewrite: None,
                timeout_ms: None,
            },
            source: Some(listen.location.clone()),
            ..Default::default()
        };
        config.routes.push(route);
    }

    diagnostics.converted.push(ConvertedItem {
        item_type: "listen".to_string(),
        name: listen_name,
        source_location: Some(listen.location.clone()),
    });

    Ok(())
}

/// Create a listener from a bind directive
fn create_listener_from_bind(
    frontend_name: &str,
    addr: &str,
    bind: &super::Directive,
    defaults: Option<&Section>,
) -> Listener {
    let mut listener = Listener {
        name: format!("{}_{}", frontend_name, sanitize_address(addr)),
        bind: BindAddress::Single(normalize_bind_address(addr)),
        source: Some(bind.location.clone()),
        ..Default::default()
    };

    // Check for SSL
    if bind.has_arg("ssl") {
        listener.protocol = Protocol::Https;

        // Look for certificate
        for (i, arg) in bind.args.iter().enumerate() {
            if arg == "crt" {
                if let Some(cert) = bind.args.get(i + 1) {
                    listener.tls = Some(TlsConfig {
                        cert_path: Some(cert.into()),
                        ..Default::default()
                    });
                }
            }
        }
    }

    // Apply default timeouts
    if let Some(defaults) = defaults {
        if let Some(timeout) = defaults.find_directive("timeout client") {
            if let Some(ms) = parse_haproxy_time(timeout.first_arg()) {
                listener.options.request_timeout = Some(std::time::Duration::from_millis(ms));
            }
        }
    }

    listener
}

/// Create a route from use_backend directive with ACL conditions
fn create_route_from_use_backend(
    frontend_name: &str,
    index: usize,
    backend_name: &str,
    directive: &super::Directive,
    acls: &HashMap<String, AclDefinition>,
    diagnostics: &mut Diagnostics,
) -> Route {
    let mut route = Route {
        name: format!("{}_route_{}", frontend_name, index),
        action: RouteAction::Forward {
            upstream: backend_name.to_string(),
            path_rewrite: None,
            host_rewrite: None,
            timeout_ms: None,
        },
        source: Some(directive.location.clone()),
        ..Default::default()
    };

    // Parse ACL conditions: use_backend backend if acl1 acl2 ...
    // Look for "if" keyword
    if let Some(if_pos) = directive.args.iter().position(|a| a == "if") {
        for acl_name in directive.args.iter().skip(if_pos + 1) {
            // Skip logical operators
            if acl_name == "or" || acl_name == "||" || acl_name == "!" {
                continue;
            }

            if let Some(acl) = acls.get(acl_name) {
                if let Some(matcher) = acl_to_matcher(acl) {
                    route.matchers.push(matcher);
                }
            }
        }
    }

    diagnostics.converted.push(ConvertedItem {
        item_type: "route".to_string(),
        name: route.name.clone(),
        source_location: Some(directive.location.clone()),
    });

    route
}

/// Convert an ACL definition to a route matcher
fn acl_to_matcher(acl: &AclDefinition) -> Option<RouteMatcher> {
    match acl.acl_type.as_str() {
        "path_beg" | "path_sub" | "path" => {
            let match_type = match acl.acl_type.as_str() {
                "path_beg" => PathMatchType::Prefix,
                "path" => PathMatchType::Exact,
                _ => PathMatchType::Prefix,
            };
            Some(RouteMatcher::Path(PathMatch {
                pattern: acl.pattern.clone(),
                match_type,
            }))
        }
        "path_reg" => Some(RouteMatcher::Path(PathMatch {
            pattern: acl.pattern.clone(),
            match_type: PathMatchType::Regex,
        })),
        "hdr" | "hdr_beg" | "hdr_end" | "hdr_sub" => {
            // Header matching - pattern format is usually "header_name value"
            let parts: Vec<&str> = acl.pattern.split_whitespace().collect();
            if parts.len() >= 2 {
                Some(RouteMatcher::Header(HeaderMatch {
                    name: parts[0].to_string(),
                    pattern: parts[1..].join(" "),
                    regex: acl.acl_type == "hdr_reg",
                }))
            } else {
                None
            }
        }
        "hdr_dom" | "hdr(host)" => {
            Some(RouteMatcher::Host(HostMatch {
                patterns: vec![acl.pattern.clone()],
                exact: false,
            }))
        }
        "src" => {
            // Source IP matching
            Some(RouteMatcher::SourceIp(IpMatch {
                cidrs: vec![acl.pattern.clone()],
                allow: true,
            }))
        }
        "method" => {
            let method = match acl.pattern.to_uppercase().as_str() {
                "GET" => HttpMethod::Get,
                "POST" => HttpMethod::Post,
                "PUT" => HttpMethod::Put,
                "DELETE" => HttpMethod::Delete,
                "PATCH" => HttpMethod::Patch,
                "HEAD" => HttpMethod::Head,
                "OPTIONS" => HttpMethod::Options,
                _ => return None,
            };
            Some(RouteMatcher::Method { methods: vec![method] })
        }
        _ => None,
    }
}

/// Normalize bind address
fn normalize_bind_address(addr: &str) -> String {
    // Handle *:port format
    if addr.starts_with('*') {
        return addr.replace('*', "0.0.0.0");
    }
    // Handle just port number
    if addr.parse::<u16>().is_ok() {
        return format!("0.0.0.0:{}", addr);
    }
    addr.to_string()
}

/// Sanitize address for use in names
fn sanitize_address(addr: &str) -> String {
    addr.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

/// Parse HAProxy time format (e.g., "5000ms", "5s", "1m")
fn parse_haproxy_time(s: Option<&str>) -> Option<u64> {
    let s = s?.trim();
    if s.ends_with("ms") {
        s[..s.len() - 2].parse().ok()
    } else if s.ends_with('s') {
        s[..s.len() - 1].parse::<u64>().ok().map(|v| v * 1000)
    } else if s.ends_with('m') {
        s[..s.len() - 1].parse::<u64>().ok().map(|v| v * 60 * 1000)
    } else if s.ends_with('h') {
        s[..s.len() - 1].parse::<u64>().ok().map(|v| v * 60 * 60 * 1000)
    } else {
        // Assume milliseconds
        s.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_haproxy_time() {
        assert_eq!(parse_haproxy_time(Some("5000ms")), Some(5000));
        assert_eq!(parse_haproxy_time(Some("5s")), Some(5000));
        assert_eq!(parse_haproxy_time(Some("1m")), Some(60000));
        assert_eq!(parse_haproxy_time(Some("5000")), Some(5000));
    }

    #[test]
    fn test_normalize_bind_address() {
        assert_eq!(normalize_bind_address("*:80"), "0.0.0.0:80");
        assert_eq!(normalize_bind_address("80"), "0.0.0.0:80");
        assert_eq!(normalize_bind_address("192.168.1.1:8080"), "192.168.1.1:8080");
    }

    #[test]
    fn test_parse_balance_algorithm() {
        assert!(matches!(parse_balance_algorithm(Some("roundrobin")), LoadBalancing::RoundRobin));
        assert!(matches!(parse_balance_algorithm(Some("leastconn")), LoadBalancing::LeastConnections));
        assert!(matches!(parse_balance_algorithm(Some("source")), LoadBalancing::IpHash));
    }
}
