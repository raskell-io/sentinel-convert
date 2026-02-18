# zentinel-convert

Convert reverse proxy configurations to [Zentinel](https://github.com/zentinelproxy/zentinel) KDL format.

Supports **nginx**, **HAProxy**, **Traefik**, **Caddy**, and **Envoy**. Auto-detects the source format, translates to Zentinel's intermediate representation, and emits idiomatic KDL — including agent suggestions where your existing config maps to Zentinel agents (WAF, auth, rate limiting).

Also available as a **WebAssembly module** for in-browser conversion.

## Install

```sh
cargo install zentinel-convert
```

Or build from source:

```sh
git clone https://github.com/zentinelproxy/zentinel-convert
cd zentinel-convert
cargo build --release
```

## Usage

### Convert

```sh
# Auto-detect format, print KDL to stdout
zentinel-convert convert nginx.conf

# Specify format explicitly
zentinel-convert convert --format haproxy haproxy.cfg

# Write to file
zentinel-convert convert nginx.conf -o zentinel.kdl

# Follow nginx include directives
zentinel-convert convert --follow-includes nginx.conf

# Auto-create agents for high-confidence detections
zentinel-convert convert --agents auto nginx.conf

# Dry run — show output without writing
zentinel-convert convert --dry-run nginx.conf
```

### Analyze

Scan a config for patterns that map to Zentinel agents without performing a full conversion:

```sh
zentinel-convert analyze nginx.conf

# JSON output for scripting
zentinel-convert analyze --json haproxy.cfg
```

### Detect

Identify the format of a configuration file:

```sh
zentinel-convert detect mystery-config.txt
# => nginx
```

## Example

Given this nginx config:

```nginx
upstream backend {
    least_conn;
    server 10.0.0.1:8080 weight=5;
    server 10.0.0.2:8080 weight=3;
    server 10.0.0.3:8080 backup;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate     /etc/ssl/certs/api.crt;
    ssl_certificate_key /etc/ssl/private/api.key;

    location /api/v1/ {
        limit_req zone=api_limit burst=20;
        proxy_pass http://backend;
    }
}
```

`zentinel-convert convert nginx.conf` produces:

```kdl
schema-version "1.0"

system {
    worker-threads 4
    max-connections 1024
}

listeners {
    listener "listener_443" {
        address "0.0.0.0:443"
        protocol "h2"
        tls {
            cert-file "/etc/ssl/certs/api.crt"
            key-file "/etc/ssl/private/api.key"
        }
    }
}

routes {
    route "route_api_v1" {
        matches {
            path-prefix "/api/v1/"
            host "api.example.com"
        }
        upstream "backend"
        timeout-ms 60000
    }
}

upstreams {
    upstream "backend" {
        target "10.0.0.1:8080" weight=5
        target "10.0.0.2:8080" weight=3
        target "10.0.0.3:8080" backup=#true
        load-balancing "least_connections"
        connection-pool {
            max-idle 32
        }
    }
}
```

The converter also detects that `limit_req` maps to Zentinel's [ratelimit agent](https://github.com/zentinelproxy/zentinel-agent-ratelimit) and will suggest (or auto-create with `--agents auto`) the appropriate agent configuration.

## Agent Detection

The converter recognizes patterns in source configs that correspond to Zentinel agents:

| Source pattern | Detected agent |
|---|---|
| `limit_req`, rate limiting rules | [`ratelimit`](https://github.com/zentinelproxy/zentinel-agent-ratelimit) |
| `auth_basic`, JWT/OIDC directives | [`auth`](https://github.com/zentinelproxy/zentinel-agent-auth) |
| ModSecurity, WAF rules, `deny` blocks | [`waf`](https://github.com/zentinelproxy/zentinel-agent-waf) |

Three modes control this behavior:

- **`--agents suggest`** (default) — report agent opportunities in diagnostics
- **`--agents auto`** — auto-create agents for high-confidence detections, suggest the rest
- **`--agents none`** — skip agent detection entirely

## Supported Formats

| Format | Extensions | Status |
|---|---|---|
| nginx | `.conf` | Full support — includes, upstreams, locations, SSL, rate limiting |
| HAProxy | `.cfg` | Frontends, backends, ACLs, stick-tables |
| Traefik | `.yaml`, `.toml` | Routers, services, middlewares (v2/v3) |
| Caddy | `Caddyfile` | Sites, reverse_proxy, TLS, matchers |
| Envoy | `.yaml` | Listeners, clusters, routes, filters |

## WebAssembly

A WASM build is available for in-browser conversion (powers the playground on [zentinelproxy.io](https://zentinelproxy.io)):

```sh
cd crates/wasm
wasm-pack build --target web --release
```

The WASM module exports:

- `convert(config, format?)` — convert a config string to KDL
- `detect_format(config)` — detect the source format
- `validate(config, format?)` — validate without full conversion
- `get_supported_formats()` — list supported formats

## Library Usage

`zentinel-convert` is also a Rust library:

```rust
use zentinel_convert::{convert, ConvertOptions, AgentMode};
use std::path::Path;

let result = convert(
    Path::new("nginx.conf"),
    ConvertOptions {
        agent_mode: AgentMode::Auto,
        ..Default::default()
    },
)?;

println!("{}", result.kdl_output);

for suggestion in &result.diagnostics.agent_suggestions {
    println!("  {:?} agent ({:?} confidence)", suggestion.agent_type, suggestion.confidence);
}
```

## Testing

Tests use [insta](https://insta.rs) for snapshot testing:

```sh
cargo test

# Review snapshot changes after modifying parser/emitter output
cargo insta review
```

## License

MIT OR Apache-2.0
