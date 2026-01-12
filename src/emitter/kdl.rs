//! KDL output generation

use crate::ir::*;
use std::fmt::Write;

/// KDL emitter for generating Sentinel configuration
pub struct KdlEmitter {
    options: EmitterOptions,
}

/// Options for KDL emission
#[derive(Debug, Clone, Default)]
pub struct EmitterOptions {
    /// Add comments explaining conversions
    pub include_comments: bool,
    /// Add source location comments
    pub include_source_refs: bool,
    /// Indent string (default: 4 spaces)
    pub indent: String,
}

impl KdlEmitter {
    pub fn new(options: EmitterOptions) -> Self {
        Self { options }
    }

    /// Emit Sentinel KDL configuration
    pub fn emit(&self, config: &SentinelConfig) -> Result<String, String> {
        let mut output = String::new();
        let indent = if self.options.indent.is_empty() {
            "    "
        } else {
            &self.options.indent
        };

        // Schema version
        writeln!(output, "schema-version \"1.0\"").unwrap();
        writeln!(output).unwrap();

        // System block
        self.emit_system(&mut output, &config.system, indent)?;

        // Listeners
        if !config.listeners.is_empty() {
            self.emit_listeners(&mut output, &config.listeners, indent)?;
        }

        // Routes
        if !config.routes.is_empty() {
            self.emit_routes(&mut output, &config.routes, indent)?;
        }

        // Upstreams
        if !config.upstreams.is_empty() {
            self.emit_upstreams(&mut output, &config.upstreams, indent)?;
        }

        // Filters
        if !config.filters.is_empty() {
            self.emit_filters(&mut output, &config.filters, indent)?;
        }

        // Agents
        if !config.agents.is_empty() {
            self.emit_agents(&mut output, &config.agents, indent)?;
        }

        // Limits
        if let Some(limits) = &config.limits {
            self.emit_limits(&mut output, limits, indent)?;
        }

        // Cache
        if let Some(cache) = &config.cache {
            self.emit_cache(&mut output, cache, indent)?;
        }

        // Observability
        if let Some(obs) = &config.observability {
            self.emit_observability(&mut output, obs, indent)?;
        }

        Ok(output)
    }

    fn emit_system(&self, output: &mut String, system: &SystemConfig, indent: &str) -> Result<(), String> {
        writeln!(output, "system {{").unwrap();

        if let Some(workers) = system.worker_threads {
            writeln!(output, "{}worker-threads {}", indent, workers).unwrap();
        }

        if let Some(max_conn) = system.max_connections {
            writeln!(output, "{}max-connections {}", indent, max_conn).unwrap();
        }

        if let Some(shutdown) = system.graceful_shutdown_secs {
            writeln!(output, "{}graceful-shutdown-timeout-secs {}", indent, shutdown).unwrap();
        }

        writeln!(output, "}}").unwrap();
        writeln!(output).unwrap();

        Ok(())
    }

    fn emit_listeners(&self, output: &mut String, listeners: &[Listener], indent: &str) -> Result<(), String> {
        writeln!(output, "listeners {{").unwrap();

        // Sort by name for deterministic output
        let mut sorted_listeners: Vec<_> = listeners.iter().collect();
        sorted_listeners.sort_by_key(|l| &l.name);

        for listener in sorted_listeners {
            writeln!(output, "{}listener \"{}\" {{", indent, listener.name).unwrap();

            // Address
            match &listener.bind {
                BindAddress::Single(addr) => {
                    writeln!(output, "{}{}address \"{}\"", indent, indent, addr).unwrap();
                }
                BindAddress::Multiple(addrs) => {
                    for addr in addrs {
                        writeln!(output, "{}{}address \"{}\"", indent, indent, addr).unwrap();
                    }
                }
                BindAddress::Unix(path) => {
                    writeln!(output, "{}{}unix-socket \"{}\"", indent, indent, path.display()).unwrap();
                }
            }

            // Protocol
            writeln!(output, "{}{}protocol \"{}\"", indent, indent, listener.protocol).unwrap();

            // TLS
            if let Some(tls) = &listener.tls {
                writeln!(output, "{}{}tls {{", indent, indent).unwrap();
                if let Some(cert) = &tls.cert_path {
                    writeln!(output, "{}{}{}cert-file \"{}\"", indent, indent, indent, cert.display()).unwrap();
                }
                if let Some(key) = &tls.key_path {
                    writeln!(output, "{}{}{}key-file \"{}\"", indent, indent, indent, key.display()).unwrap();
                }
                if let Some(min) = &tls.min_version {
                    writeln!(output, "{}{}{}min-version \"{}\"", indent, indent, indent, min).unwrap();
                }
                writeln!(output, "{}{}}}", indent, indent).unwrap();
            }

            // Options
            if let Some(timeout) = listener.options.request_timeout {
                writeln!(output, "{}{}request-timeout-secs {}", indent, indent, timeout.as_secs()).unwrap();
            }

            writeln!(output, "{}}}", indent).unwrap();
        }

        writeln!(output, "}}").unwrap();
        writeln!(output).unwrap();

        Ok(())
    }

    fn emit_routes(&self, output: &mut String, routes: &[Route], indent: &str) -> Result<(), String> {
        writeln!(output, "routes {{").unwrap();

        // Sort by name for deterministic output
        let mut sorted_routes: Vec<_> = routes.iter().collect();
        sorted_routes.sort_by_key(|r| &r.name);

        for route in sorted_routes {
            if self.options.include_comments {
                if let Some(desc) = &route.metadata.description {
                    writeln!(output, "{}// {}", indent, desc).unwrap();
                }
            }

            writeln!(output, "{}route \"{}\" {{", indent, route.name).unwrap();

            // Priority
            if let Some(priority) = route.priority {
                let priority_str = match priority {
                    p if p >= 100 => "critical",
                    p if p >= 50 => "high",
                    p if p >= 0 => "normal",
                    _ => "low",
                };
                writeln!(output, "{}{}priority \"{}\"", indent, indent, priority_str).unwrap();
            }

            // Matches
            if !route.matchers.is_empty() {
                writeln!(output, "{}{}matches {{", indent, indent).unwrap();
                for matcher in &route.matchers {
                    self.emit_matcher(output, matcher, &format!("{}{}{}", indent, indent, indent))?;
                }
                writeln!(output, "{}{}}}", indent, indent).unwrap();
            }

            // Action
            self.emit_action(output, &route.action, &format!("{}{}", indent, indent))?;

            // Middleware
            if !route.middleware.is_empty() {
                let mw_names: Vec<_> = route.middleware.iter().map(|m| format!("\"{}\"", m.name)).collect();
                writeln!(output, "{}{}filters {}", indent, indent, mw_names.join(" ")).unwrap();
            }

            writeln!(output, "{}}}", indent).unwrap();
        }

        writeln!(output, "}}").unwrap();
        writeln!(output).unwrap();

        Ok(())
    }

    fn emit_matcher(&self, output: &mut String, matcher: &RouteMatcher, indent: &str) -> Result<(), String> {
        match matcher {
            RouteMatcher::Host(host) => {
                for pattern in &host.patterns {
                    writeln!(output, "{}host \"{}\"", indent, pattern).unwrap();
                }
            }
            RouteMatcher::Path(path) => {
                let directive = match path.match_type {
                    PathMatchType::Exact => "path",
                    PathMatchType::Prefix => "path-prefix",
                    PathMatchType::Regex => "path-regex",
                    PathMatchType::Glob => "path-glob",
                };
                writeln!(output, "{}{} \"{}\"", indent, directive, path.pattern).unwrap();
            }
            RouteMatcher::Method { methods } => {
                let methods_str: Vec<_> = methods.iter().map(|m| format!("\"{}\"", m)).collect();
                writeln!(output, "{}method {}", indent, methods_str.join(" ")).unwrap();
            }
            RouteMatcher::Header(header) => {
                writeln!(output, "{}header \"{}\" \"{}\"", indent, header.name, header.pattern).unwrap();
            }
            RouteMatcher::Query(query) => {
                writeln!(output, "{}query \"{}\" \"{}\"", indent, query.name, query.pattern).unwrap();
            }
            RouteMatcher::SourceIp(ip) => {
                let directive = if ip.allow { "source-ip-allow" } else { "source-ip-deny" };
                for cidr in &ip.cidrs {
                    writeln!(output, "{}{} \"{}\"", indent, directive, cidr).unwrap();
                }
            }
            RouteMatcher::And { matchers } => {
                for m in matchers {
                    self.emit_matcher(output, m, indent)?;
                }
            }
            RouteMatcher::Or { matchers } => {
                writeln!(output, "{}or {{", indent).unwrap();
                for m in matchers {
                    self.emit_matcher(output, m, &format!("{}    ", indent))?;
                }
                writeln!(output, "{}}}", indent).unwrap();
            }
        }
        Ok(())
    }

    fn emit_action(&self, output: &mut String, action: &RouteAction, indent: &str) -> Result<(), String> {
        match action {
            RouteAction::Forward { upstream, path_rewrite, host_rewrite, timeout_ms } => {
                writeln!(output, "{}upstream \"{}\"", indent, upstream).unwrap();
                if let Some(rewrite) = path_rewrite {
                    writeln!(output, "{}path-rewrite \"{}\" \"{}\"", indent, rewrite.pattern, rewrite.replacement).unwrap();
                }
                if let Some(host) = host_rewrite {
                    writeln!(output, "{}host-rewrite \"{}\"", indent, host).unwrap();
                }
                if let Some(timeout) = timeout_ms {
                    writeln!(output, "{}timeout-ms {}", indent, timeout).unwrap();
                }
            }
            RouteAction::Redirect { url, status_code, preserve_path } => {
                writeln!(output, "{}redirect {{", indent).unwrap();
                writeln!(output, "{}    url \"{}\"", indent, url).unwrap();
                writeln!(output, "{}    status {}", indent, status_code).unwrap();
                if *preserve_path {
                    writeln!(output, "{}    preserve-path #true", indent).unwrap();
                }
                writeln!(output, "{}}}", indent).unwrap();
            }
            RouteAction::FixedResponse { status_code, body, headers } => {
                writeln!(output, "{}respond {{", indent).unwrap();
                writeln!(output, "{}    status {}", indent, status_code).unwrap();
                if let Some(body) = body {
                    writeln!(output, "{}    body \"{}\"", indent, escape_string(body)).unwrap();
                }
                for (name, value) in headers {
                    writeln!(output, "{}    header \"{}\" \"{}\"", indent, name, value).unwrap();
                }
                writeln!(output, "{}}}", indent).unwrap();
            }
            RouteAction::Static { root, index, directory_listing } => {
                writeln!(output, "{}static-files {{", indent).unwrap();
                writeln!(output, "{}    root \"{}\"", indent, root.display()).unwrap();
                if let Some(indexes) = index {
                    let idx_str: Vec<_> = indexes.iter().map(|i| format!("\"{}\"", i)).collect();
                    writeln!(output, "{}    index {}", indent, idx_str.join(" ")).unwrap();
                }
                writeln!(output, "{}    directory-listing #{}", indent, directory_listing).unwrap();
                writeln!(output, "{}}}", indent).unwrap();
            }
        }
        Ok(())
    }

    fn emit_upstreams(&self, output: &mut String, upstreams: &std::collections::HashMap<String, Upstream>, indent: &str) -> Result<(), String> {
        writeln!(output, "upstreams {{").unwrap();

        // Sort by name for deterministic output
        let mut sorted_upstreams: Vec<_> = upstreams.iter().collect();
        sorted_upstreams.sort_by_key(|(name, _)| *name);

        for (name, upstream) in sorted_upstreams {
            writeln!(output, "{}upstream \"{}\" {{", indent, name).unwrap();

            // Endpoints
            for endpoint in &upstream.endpoints {
                let mut line = format!("{}{}target \"{}\"", indent, indent, endpoint.address);
                if let Some(weight) = endpoint.weight {
                    line.push_str(&format!(" weight={}", weight));
                }
                if endpoint.backup {
                    line.push_str(" backup=#true");
                }
                writeln!(output, "{}", line).unwrap();
            }

            // Load balancing
            writeln!(output, "{}{}load-balancing \"{}\"", indent, indent, upstream.load_balancing).unwrap();

            // Health check
            if let Some(hc) = &upstream.health_check {
                writeln!(output, "{}{}health-check {{", indent, indent).unwrap();
                match &hc.check_type {
                    HealthCheckType::Http { path, expected_status } => {
                        writeln!(output, "{}{}{}type \"http\" {{", indent, indent, indent).unwrap();
                        writeln!(output, "{}{}{}{}path \"{}\"", indent, indent, indent, indent, path).unwrap();
                        if !expected_status.is_empty() {
                            writeln!(output, "{}{}{}{}expected-status {}", indent, indent, indent, indent, expected_status[0]).unwrap();
                        }
                        writeln!(output, "{}{}{}}}", indent, indent, indent).unwrap();
                    }
                    HealthCheckType::Tcp => {
                        writeln!(output, "{}{}{}type \"tcp\"", indent, indent, indent).unwrap();
                    }
                    HealthCheckType::Grpc { service } => {
                        writeln!(output, "{}{}{}type \"grpc\"", indent, indent, indent).unwrap();
                        if let Some(svc) = service {
                            writeln!(output, "{}{}{}service \"{}\"", indent, indent, indent, svc).unwrap();
                        }
                    }
                }
                writeln!(output, "{}{}{}interval-ms {}", indent, indent, indent, hc.interval_ms).unwrap();
                writeln!(output, "{}{}{}timeout-ms {}", indent, indent, indent, hc.timeout_ms).unwrap();
                writeln!(output, "{}{}{}healthy-threshold {}", indent, indent, indent, hc.healthy_threshold).unwrap();
                writeln!(output, "{}{}{}unhealthy-threshold {}", indent, indent, indent, hc.unhealthy_threshold).unwrap();
                writeln!(output, "{}{}}}", indent, indent).unwrap();
            }

            // Connection pool
            if let Some(pool) = &upstream.connection_pool {
                writeln!(output, "{}{}connection-pool {{", indent, indent).unwrap();
                if let Some(max) = pool.max_connections {
                    writeln!(output, "{}{}{}max-connections {}", indent, indent, indent, max).unwrap();
                }
                if let Some(idle) = pool.max_idle {
                    writeln!(output, "{}{}{}max-idle {}", indent, indent, indent, idle).unwrap();
                }
                if let Some(timeout) = pool.idle_timeout_ms {
                    writeln!(output, "{}{}{}idle-timeout-ms {}", indent, indent, indent, timeout).unwrap();
                }
                writeln!(output, "{}{}}}", indent, indent).unwrap();
            }

            writeln!(output, "{}}}", indent).unwrap();
        }

        writeln!(output, "}}").unwrap();
        writeln!(output).unwrap();

        Ok(())
    }

    fn emit_filters(&self, output: &mut String, filters: &std::collections::HashMap<String, Filter>, indent: &str) -> Result<(), String> {
        writeln!(output, "filters {{").unwrap();

        // Sort by name for deterministic output
        let mut sorted_filters: Vec<_> = filters.iter().collect();
        sorted_filters.sort_by_key(|(name, _)| *name);

        for (name, filter) in sorted_filters {
            writeln!(output, "{}filter \"{}\" {{", indent, name).unwrap();
            writeln!(output, "{}{}type \"{}\"", indent, indent, filter.filter_type).unwrap();

            match &filter.config {
                FilterConfig::Headers(headers) => {
                    if !headers.request_add.is_empty() || !headers.request_remove.is_empty() {
                        writeln!(output, "{}{}request {{", indent, indent).unwrap();
                        for op in &headers.request_add {
                            writeln!(output, "{}{}{}set \"{}\" \"{}\"", indent, indent, indent, op.name, op.value).unwrap();
                        }
                        for name in &headers.request_remove {
                            writeln!(output, "{}{}{}remove \"{}\"", indent, indent, indent, name).unwrap();
                        }
                        writeln!(output, "{}{}}}", indent, indent).unwrap();
                    }
                    if !headers.response_add.is_empty() || !headers.response_remove.is_empty() {
                        writeln!(output, "{}{}response {{", indent, indent).unwrap();
                        for op in &headers.response_add {
                            writeln!(output, "{}{}{}set \"{}\" \"{}\"", indent, indent, indent, op.name, op.value).unwrap();
                        }
                        for name in &headers.response_remove {
                            writeln!(output, "{}{}{}remove \"{}\"", indent, indent, indent, name).unwrap();
                        }
                        writeln!(output, "{}{}}}", indent, indent).unwrap();
                    }
                }
                FilterConfig::Compression(comp) => {
                    let algs: Vec<_> = comp.algorithms.iter().map(|a| format!("\"{}\"", a)).collect();
                    writeln!(output, "{}{}algorithms {}", indent, indent, algs.join(" ")).unwrap();
                    if let Some(min) = comp.min_size {
                        writeln!(output, "{}{}min-size {}", indent, indent, min).unwrap();
                    }
                }
                _ => {}
            }

            writeln!(output, "{}}}", indent).unwrap();
        }

        writeln!(output, "}}").unwrap();
        writeln!(output).unwrap();

        Ok(())
    }

    fn emit_agents(&self, output: &mut String, agents: &[Agent], indent: &str) -> Result<(), String> {
        writeln!(output, "agents {{").unwrap();

        // Sort by name for deterministic output
        let mut sorted_agents: Vec<_> = agents.iter().collect();
        sorted_agents.sort_by_key(|a| &a.name);

        for agent in sorted_agents {
            // Add comment about detection
            if self.options.include_comments {
                if let AgentDetection::Inferred { patterns_matched, .. } = &agent.detection {
                    for pattern in patterns_matched {
                        writeln!(output, "{}// Detected from: {}", indent, pattern).unwrap();
                    }
                }
            }

            writeln!(output, "{}agent \"{}\" {{", indent, agent.name).unwrap();
            writeln!(output, "{}{}type \"{}\"", indent, indent, agent.agent_type).unwrap();

            // Socket path
            let socket_path = match &agent.config {
                AgentConfig::Waf(c) => &c.socket_path,
                AgentConfig::Auth(c) => &c.socket_path,
                AgentConfig::RateLimit(c) => &c.socket_path,
                AgentConfig::Custom(c) => &c.socket_path,
            };
            writeln!(output, "{}{}unix-socket path=\"{}\"", indent, indent, socket_path.display()).unwrap();

            // Timeout
            let timeout = match &agent.config {
                AgentConfig::Waf(c) => c.timeout_ms,
                AgentConfig::Auth(c) => c.timeout_ms,
                AgentConfig::RateLimit(c) => c.timeout_ms,
                AgentConfig::Custom(c) => c.timeout_ms,
            };
            if let Some(t) = timeout {
                writeln!(output, "{}{}timeout-ms {}", indent, indent, t).unwrap();
            }

            // Failure mode
            let failure_mode = match &agent.config {
                AgentConfig::Waf(c) => &c.failure_mode,
                AgentConfig::Auth(c) => &c.failure_mode,
                AgentConfig::RateLimit(c) => &c.failure_mode,
                AgentConfig::Custom(c) => &c.failure_mode,
            };
            writeln!(output, "{}{}failure-mode \"{}\"", indent, indent, failure_mode).unwrap();

            // Type-specific config
            match &agent.config {
                AgentConfig::Auth(auth) => {
                    match &auth.type_config {
                        AuthTypeConfig::Basic { realm, .. } => {
                            if let Some(r) = realm {
                                writeln!(output, "{}{}realm \"{}\"", indent, indent, r).unwrap();
                            }
                        }
                        _ => {}
                    }
                }
                AgentConfig::RateLimit(rate) => {
                    if !rate.limits.is_empty() {
                        writeln!(output, "{}{}limits {{", indent, indent).unwrap();
                        for limit in &rate.limits {
                            writeln!(output, "{}{}{}{} {{", indent, indent, indent, limit.name).unwrap();
                            writeln!(output, "{}{}{}{}rate {}", indent, indent, indent, indent, limit.rate).unwrap();
                            writeln!(output, "{}{}{}{}period-ms {}", indent, indent, indent, indent, limit.period_ms).unwrap();
                            if let Some(burst) = limit.burst {
                                writeln!(output, "{}{}{}{}burst {}", indent, indent, indent, indent, burst).unwrap();
                            }
                            writeln!(output, "{}{}{}}}", indent, indent, indent).unwrap();
                        }
                        writeln!(output, "{}{}}}", indent, indent).unwrap();
                    }
                }
                _ => {}
            }

            // Routes this agent applies to
            if !agent.routes.is_empty() {
                let routes: Vec<_> = agent.routes.iter().map(|r| format!("\"{}\"", r)).collect();
                writeln!(output, "{}{}routes {}", indent, indent, routes.join(" ")).unwrap();
            }

            writeln!(output, "{}}}", indent).unwrap();
        }

        writeln!(output, "}}").unwrap();
        writeln!(output).unwrap();

        Ok(())
    }

    fn emit_limits(&self, output: &mut String, limits: &LimitsConfig, indent: &str) -> Result<(), String> {
        writeln!(output, "limits {{").unwrap();

        if let Some(size) = limits.max_header_size {
            writeln!(output, "{}max-header-size-bytes {}", indent, size).unwrap();
        }
        if let Some(count) = limits.max_header_count {
            writeln!(output, "{}max-header-count {}", indent, count).unwrap();
        }
        if let Some(size) = limits.max_body_size {
            writeln!(output, "{}max-body-size-bytes {}", indent, size).unwrap();
        }

        writeln!(output, "}}").unwrap();
        writeln!(output).unwrap();

        Ok(())
    }

    fn emit_cache(&self, output: &mut String, cache: &CacheConfig, indent: &str) -> Result<(), String> {
        writeln!(output, "cache {{").unwrap();
        writeln!(output, "{}enabled #{}", indent, cache.enabled).unwrap();
        writeln!(output, "{}backend \"{}\"", indent, match cache.backend {
            CacheBackend::Memory => "memory",
            CacheBackend::Disk => "disk",
            CacheBackend::Hybrid => "hybrid",
        }).unwrap();
        if let Some(size) = cache.max_size {
            writeln!(output, "{}max-size {}", indent, size).unwrap();
        }
        writeln!(output, "}}").unwrap();
        writeln!(output).unwrap();

        Ok(())
    }

    fn emit_observability(&self, output: &mut String, obs: &ObservabilityConfig, indent: &str) -> Result<(), String> {
        writeln!(output, "observability {{").unwrap();

        if let Some(metrics) = &obs.metrics {
            writeln!(output, "{}metrics {{", indent).unwrap();
            writeln!(output, "{}{}enabled #{}", indent, indent, metrics.enabled).unwrap();
            if let Some(addr) = &metrics.address {
                writeln!(output, "{}{}address \"{}\"", indent, indent, addr).unwrap();
            }
            if let Some(path) = &metrics.path {
                writeln!(output, "{}{}path \"{}\"", indent, indent, path).unwrap();
            }
            writeln!(output, "{}}}", indent).unwrap();
        }

        if let Some(logging) = &obs.logging {
            writeln!(output, "{}logging {{", indent).unwrap();
            if let Some(level) = &logging.level {
                writeln!(output, "{}{}level \"{}\"", indent, indent, level).unwrap();
            }
            if let Some(format) = &logging.format {
                writeln!(output, "{}{}format \"{}\"", indent, indent, format).unwrap();
            }
            writeln!(output, "{}}}", indent).unwrap();
        }

        if let Some(tracing) = &obs.tracing {
            writeln!(output, "{}tracing {{", indent).unwrap();
            writeln!(output, "{}{}enabled #{}", indent, indent, tracing.enabled).unwrap();
            if let Some(backend) = &tracing.backend {
                writeln!(output, "{}{}backend \"{}\"", indent, indent, backend).unwrap();
            }
            if let Some(endpoint) = &tracing.endpoint {
                writeln!(output, "{}{}endpoint \"{}\"", indent, indent, endpoint).unwrap();
            }
            writeln!(output, "{}}}", indent).unwrap();
        }

        writeln!(output, "}}").unwrap();
        writeln!(output).unwrap();

        Ok(())
    }
}

impl Default for KdlEmitter {
    fn default() -> Self {
        Self::new(EmitterOptions::default())
    }
}

/// Escape string for KDL output
fn escape_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_string() {
        assert_eq!(escape_string("hello"), "hello");
        assert_eq!(escape_string("hello\nworld"), "hello\\nworld");
        assert_eq!(escape_string("say \"hi\""), "say \\\"hi\\\"");
    }
}
