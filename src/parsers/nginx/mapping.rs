//! nginx to IR mapping

use super::{Directive, NginxConfig};
use crate::ir::*;
use crate::parsers::{ParseContext, ParseError, ParseOutput};
use std::collections::HashMap;

/// Convert nginx config AST to Sentinel IR
pub fn map_nginx_to_ir(config: NginxConfig, ctx: &ParseContext) -> Result<ParseOutput, ParseError> {
    let mut sentinel_config = SentinelConfig::default();
    let mut diagnostics = Diagnostics::default();

    // Process top-level directives
    for directive in &config.directives {
        match directive.name.as_str() {
            "worker_processes" => {
                if let Some(arg) = directive.first_arg() {
                    sentinel_config.system.worker_threads = if arg == "auto" {
                        Some(0)
                    } else {
                        arg.parse().ok()
                    };
                }
            }
            "events" => {
                // Process events block
                if let Some(block) = &directive.block {
                    for d in block {
                        if d.name == "worker_connections" {
                            if let Some(arg) = d.first_arg() {
                                sentinel_config.system.max_connections = arg.parse().ok();
                            }
                        }
                    }
                }
            }
            "http" => {
                // Process http block
                if let Some(block) = &directive.block {
                    process_http_block(block, &mut sentinel_config, &mut diagnostics, ctx)?;
                }
            }
            _ => {
                // Skip unknown top-level directives
                diagnostics.skipped.push(SkippedItem {
                    directive: directive.name.clone(),
                    reason: "Unknown top-level directive".to_string(),
                    source_location: Some(directive.location.clone()),
                });
            }
        }
    }

    Ok(ParseOutput {
        config: sentinel_config,
        diagnostics,
    })
}

/// Process the http block
fn process_http_block(
    block: &[Directive],
    config: &mut SentinelConfig,
    diagnostics: &mut Diagnostics,
    ctx: &ParseContext,
) -> Result<(), ParseError> {
    // First pass: collect upstreams
    for directive in block {
        if directive.name == "upstream" {
            if let Some(name) = directive.first_arg() {
                let upstream = process_upstream(directive, diagnostics);
                config.upstreams.insert(name.to_string(), upstream);
            }
        }
    }

    // Second pass: process servers
    for directive in block {
        match directive.name.as_str() {
            "server" => {
                process_server_block(directive, config, diagnostics, ctx)?;
            }
            "upstream" => {
                // Already processed
            }
            "gzip" => {
                if directive.first_arg() == Some("on") {
                    // Create compression filter if not exists
                    if !config.filters.contains_key("compression") {
                        config.filters.insert(
                            "compression".to_string(),
                            Filter {
                                name: "compression".to_string(),
                                filter_type: FilterType::Compression,
                                config: FilterConfig::Compression(CompressionFilterConfig {
                                    algorithms: vec![CompressionAlgorithm::Gzip],
                                    ..Default::default()
                                }),
                                source: Some(directive.location.clone()),
                            },
                        );
                    }
                }
            }
            "limit_req_zone" => {
                // Rate limiting - will be detected by agent detector
                diagnostics.agent_suggestions.push(AgentSuggestion {
                    agent_type: AgentType::RateLimit,
                    confidence: Confidence::High,
                    reason: "limit_req_zone directive detected".to_string(),
                    source_locations: vec![directive.location.clone()],
                    ..Default::default()
                });
            }
            _ => {
                // Skip other http-level directives
            }
        }
    }

    Ok(())
}

/// Process an upstream block
fn process_upstream(directive: &Directive, diagnostics: &mut Diagnostics) -> Upstream {
    let name = directive.first_arg().unwrap_or("default").to_string();
    let mut upstream = Upstream {
        name: name.clone(),
        source: Some(directive.location.clone()),
        ..Default::default()
    };

    if let Some(block) = &directive.block {
        for d in block {
            match d.name.as_str() {
                "server" => {
                    if let Some(addr) = d.first_arg() {
                        let mut endpoint = Endpoint::from(addr.to_string());

                        // Parse weight and other options
                        for arg in d.args.iter().skip(1) {
                            if let Some(weight_str) = arg.strip_prefix("weight=") {
                                endpoint.weight = weight_str.parse().ok();
                            } else if arg == "backup" {
                                endpoint.backup = true;
                            } else if let Some(max_conn) = arg.strip_prefix("max_conns=") {
                                endpoint.max_connections = max_conn.parse().ok();
                            }
                        }

                        upstream.endpoints.push(endpoint);
                    }
                }
                "least_conn" => {
                    upstream.load_balancing = LoadBalancing::LeastConnections;
                }
                "ip_hash" => {
                    upstream.load_balancing = LoadBalancing::IpHash;
                }
                "random" => {
                    upstream.load_balancing = LoadBalancing::Random;
                }
                "keepalive" => {
                    if let Some(arg) = d.first_arg() {
                        upstream.connection_pool = Some(ConnectionPool {
                            max_idle: arg.parse().ok(),
                            ..Default::default()
                        });
                    }
                }
                _ => {}
            }
        }
    }

    diagnostics.converted.push(ConvertedItem {
        item_type: "upstream".to_string(),
        name,
        source_location: Some(directive.location.clone()),
    });

    upstream
}

/// Process a server block
fn process_server_block(
    directive: &Directive,
    config: &mut SentinelConfig,
    diagnostics: &mut Diagnostics,
    ctx: &ParseContext,
) -> Result<(), ParseError> {
    let block = match &directive.block {
        Some(b) => b,
        None => return Ok(()),
    };

    // Extract server-level info
    let mut server_names: Vec<String> = Vec::new();
    let mut listen_directives: Vec<&Directive> = Vec::new();
    let mut locations: Vec<&Directive> = Vec::new();
    let mut ssl_cert: Option<String> = None;
    let mut ssl_key: Option<String> = None;
    let mut ssl_enabled = false;

    for d in block {
        match d.name.as_str() {
            "listen" => listen_directives.push(d),
            "server_name" => {
                server_names.extend(d.args.iter().cloned());
            }
            "location" => locations.push(d),
            "ssl_certificate" => {
                ssl_cert = d.first_arg().map(|s| s.to_string());
                ssl_enabled = true;
            }
            "ssl_certificate_key" => {
                ssl_key = d.first_arg().map(|s| s.to_string());
            }
            "ssl" | "ssl_on" => {
                if d.first_arg() == Some("on") {
                    ssl_enabled = true;
                }
            }
            "auth_basic" => {
                // Auth detection
                diagnostics.agent_suggestions.push(AgentSuggestion {
                    agent_type: AgentType::Auth,
                    confidence: Confidence::High,
                    reason: format!("auth_basic directive: {}", d.first_arg().unwrap_or("")),
                    extracted_config: Some(AgentConfig::Auth(AuthAgentConfig {
                        auth_type: AuthType::Basic,
                        type_config: AuthTypeConfig::Basic {
                            realm: d.first_arg().map(|s| s.to_string()),
                            htpasswd_path: None,
                        },
                        ..Default::default()
                    })),
                    source_locations: vec![d.location.clone()],
                    ..Default::default()
                });
            }
            "auth_basic_user_file" => {
                // Update the auth suggestion with htpasswd path
            }
            "limit_req" => {
                // Rate limiting detection
                diagnostics.agent_suggestions.push(AgentSuggestion {
                    agent_type: AgentType::RateLimit,
                    confidence: Confidence::High,
                    reason: "limit_req directive detected".to_string(),
                    source_locations: vec![d.location.clone()],
                    ..Default::default()
                });
            }
            "deny" | "allow" => {
                // WAF-like IP filtering
                if let Some(ip) = d.first_arg() {
                    if ip != "all" {
                        diagnostics.agent_suggestions.push(AgentSuggestion {
                            agent_type: AgentType::Waf,
                            confidence: Confidence::Medium,
                            reason: format!("{} {} directive", d.name, ip),
                            source_locations: vec![d.location.clone()],
                            ..Default::default()
                        });
                    }
                }
            }
            _ => {}
        }
    }

    // Create listeners from listen directives
    for listen in &listen_directives {
        let listener_name = format!(
            "listener_{}",
            listen.first_arg().unwrap_or("80").replace(':', "_")
        );

        // Check if listener already exists
        if config.listeners.iter().any(|l| l.name == listener_name) {
            continue;
        }

        let mut listener = Listener {
            name: listener_name.clone(),
            source: Some(listen.location.clone()),
            ..Default::default()
        };

        // Parse listen directive arguments
        if let Some(addr) = listen.first_arg() {
            listener.bind = BindAddress::Single(normalize_listen_address(addr));
        }

        // Check for SSL
        let has_ssl = listen.has_arg("ssl") || ssl_enabled;
        if has_ssl {
            listener.protocol = Protocol::Https;
            listener.tls = Some(TlsConfig {
                cert_path: ssl_cert.as_ref().map(|s| s.into()),
                key_path: ssl_key.as_ref().map(|s| s.into()),
                ..Default::default()
            });
        }

        // Check for HTTP/2
        if listen.has_arg("http2") {
            listener.protocol = if has_ssl { Protocol::H2 } else { Protocol::H2c };
        }

        config.listeners.push(listener);

        diagnostics.converted.push(ConvertedItem {
            item_type: "listener".to_string(),
            name: listener_name,
            source_location: Some(listen.location.clone()),
        });
    }

    // Create routes from locations
    for location in locations {
        let route = process_location(location, &server_names, diagnostics)?;
        config.routes.push(route);
    }

    Ok(())
}

/// Process a location block
fn process_location(
    directive: &Directive,
    server_names: &[String],
    diagnostics: &mut Diagnostics,
) -> Result<Route, ParseError> {
    let mut route = Route {
        source: Some(directive.location.clone()),
        ..Default::default()
    };

    // Parse location path and modifier
    let (modifier, path) = parse_location_args(&directive.args);
    let match_type = match modifier {
        Some("=") => PathMatchType::Exact,
        Some("~") | Some("~*") => PathMatchType::Regex,
        Some("^~") => PathMatchType::Prefix,
        _ => PathMatchType::Prefix,
    };

    route.name = format!("route_{}", sanitize_name(&path));
    route.matchers.push(RouteMatcher::Path(PathMatch {
        pattern: path.clone(),
        match_type,
    }));

    // Add host matcher if server_names are specified
    if !server_names.is_empty() && !server_names.iter().any(|n| n == "_" || n == "localhost") {
        route.matchers.push(RouteMatcher::Host(HostMatch {
            patterns: server_names.to_vec(),
            exact: false,
        }));
    }

    // Process location block
    if let Some(block) = &directive.block {
        for d in block {
            match d.name.as_str() {
                "proxy_pass" => {
                    if let Some(upstream_url) = d.first_arg() {
                        let upstream = extract_upstream_name(upstream_url);
                        route.action = RouteAction::Forward {
                            upstream,
                            path_rewrite: None,
                            host_rewrite: None,
                            timeout_ms: None,
                        };
                    }
                }
                "return" => {
                    if let Some(code) = d.first_arg() {
                        if let Ok(status) = code.parse::<u16>() {
                            if status >= 300 && status < 400 {
                                // Redirect
                                route.action = RouteAction::Redirect {
                                    url: d.arg(1).unwrap_or("/").to_string(),
                                    status_code: status,
                                    preserve_path: false,
                                };
                            } else {
                                // Fixed response
                                route.action = RouteAction::FixedResponse {
                                    status_code: status,
                                    body: d.arg(1).map(|s| s.to_string()),
                                    headers: Vec::new(),
                                };
                            }
                        }
                    }
                }
                "root" => {
                    if let Some(path) = d.first_arg() {
                        route.action = RouteAction::Static {
                            root: path.into(),
                            index: Some(vec!["index.html".to_string()]),
                            directory_listing: false,
                        };
                    }
                }
                "alias" => {
                    if let Some(path) = d.first_arg() {
                        route.action = RouteAction::Static {
                            root: path.into(),
                            index: Some(vec!["index.html".to_string()]),
                            directory_listing: false,
                        };
                    }
                }
                "index" => {
                    // Update static action if exists
                    if let RouteAction::Static { ref mut index, .. } = route.action {
                        *index = Some(d.args.clone());
                    }
                }
                "rewrite" => {
                    // Path rewriting
                    if d.args.len() >= 2 {
                        if let RouteAction::Forward {
                            ref mut path_rewrite,
                            ..
                        } = route.action
                        {
                            *path_rewrite = Some(PathRewrite {
                                pattern: d.args[0].clone(),
                                replacement: d.args[1].clone(),
                                regex: true,
                            });
                        }
                    }
                }
                "proxy_set_header" => {
                    // Header manipulation - could be a filter
                }
                "add_header" => {
                    // Response headers
                }
                "limit_req" => {
                    route.metadata.rate_limit_hint = parse_limit_req(&d.args);
                }
                "auth_basic" => {
                    route.metadata.requires_auth = true;
                }
                "proxy_connect_timeout" | "proxy_read_timeout" => {
                    if let Some(timeout) = d.first_arg() {
                        if let RouteAction::Forward {
                            ref mut timeout_ms, ..
                        } = route.action
                        {
                            *timeout_ms = parse_nginx_time(timeout);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    diagnostics.converted.push(ConvertedItem {
        item_type: "route".to_string(),
        name: route.name.clone(),
        source_location: Some(directive.location.clone()),
    });

    Ok(route)
}

/// Parse location directive arguments
fn parse_location_args(args: &[String]) -> (Option<&str>, String) {
    match args.len() {
        0 => (None, "/".to_string()),
        1 => (None, args[0].clone()),
        _ => {
            // First arg might be modifier
            let first = args[0].as_str();
            if first == "=" || first == "~" || first == "~*" || first == "^~" {
                (Some(first), args[1].clone())
            } else {
                (None, args[0].clone())
            }
        }
    }
}

/// Normalize listen address
fn normalize_listen_address(addr: &str) -> String {
    if addr.contains(':') {
        addr.to_string()
    } else {
        format!("0.0.0.0:{}", addr)
    }
}

/// Extract upstream name from proxy_pass URL
fn extract_upstream_name(url: &str) -> String {
    // Remove protocol prefix
    let without_proto = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    // Get host part (before any path)
    without_proto
        .split('/')
        .next()
        .unwrap_or(without_proto)
        .to_string()
}

/// Sanitize string for use as identifier
fn sanitize_name(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

/// Parse limit_req arguments
fn parse_limit_req(args: &[String]) -> Option<RateLimitHint> {
    let mut burst = None;

    for arg in args {
        if let Some(b) = arg.strip_prefix("burst=") {
            burst = b.parse().ok();
        }
    }

    Some(RateLimitHint {
        requests_per_second: None, // Would need to look up zone definition
        burst,
        key: RateLimitKey::SourceIp,
    })
}

/// Parse nginx time format (e.g., "60s", "1m", "1h")
fn parse_nginx_time(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.ends_with("ms") {
        s[..s.len() - 2].parse().ok()
    } else if s.ends_with('s') {
        s[..s.len() - 1].parse::<u64>().ok().map(|v| v * 1000)
    } else if s.ends_with('m') {
        s[..s.len() - 1].parse::<u64>().ok().map(|v| v * 60 * 1000)
    } else if s.ends_with('h') {
        s[..s.len() - 1]
            .parse::<u64>()
            .ok()
            .map(|v| v * 60 * 60 * 1000)
    } else {
        // Assume seconds
        s.parse::<u64>().ok().map(|v| v * 1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_upstream_name() {
        assert_eq!(extract_upstream_name("http://backend"), "backend");
        assert_eq!(extract_upstream_name("http://backend/api"), "backend");
        assert_eq!(
            extract_upstream_name("http://127.0.0.1:8080"),
            "127.0.0.1:8080"
        );
    }

    #[test]
    fn test_parse_nginx_time() {
        assert_eq!(parse_nginx_time("60s"), Some(60000));
        assert_eq!(parse_nginx_time("1m"), Some(60000));
        assert_eq!(parse_nginx_time("100ms"), Some(100));
        assert_eq!(parse_nginx_time("1h"), Some(3600000));
    }

    #[test]
    fn test_normalize_listen_address() {
        assert_eq!(normalize_listen_address("80"), "0.0.0.0:80");
        assert_eq!(normalize_listen_address("0.0.0.0:443"), "0.0.0.0:443");
        assert_eq!(normalize_listen_address("[::]:80"), "[::]:80");
    }
}
