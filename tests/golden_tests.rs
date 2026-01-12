//! Golden file tests for sentinel-convert
//!
//! These tests convert fixture files and compare the KDL output against snapshots.
//! Run `cargo insta review` to update snapshots after intentional changes.

use sentinel_convert::emitter::{EmitterOptions, KdlEmitter};
use sentinel_convert::parsers::{ParseContext, ParserRegistry};
use std::fs;
use std::path::PathBuf;

fn convert_fixture(fixture_path: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(fixture_path);

    let content = fs::read_to_string(&path).expect("Failed to read fixture file");

    let registry = ParserRegistry::new();
    let parser = registry
        .detect_format(&path, &content)
        .expect("Failed to detect format");

    let mut ctx = ParseContext::new(path, content);
    let output = parser.parse(&mut ctx).expect("Failed to parse config");

    let emitter = KdlEmitter::new(EmitterOptions::default());
    emitter.emit(&output.config).expect("Failed to emit KDL")
}

#[test]
fn test_nginx_basic() {
    let kdl = convert_fixture("nginx/basic.conf");
    insta::assert_snapshot!("nginx_basic", kdl);
}

#[test]
fn test_nginx_with_includes() {
    let kdl = convert_fixture("nginx/with_includes.conf");
    insta::assert_snapshot!("nginx_with_includes", kdl);
}

#[test]
fn test_haproxy_basic() {
    let kdl = convert_fixture("haproxy/basic.cfg");
    insta::assert_snapshot!("haproxy_basic", kdl);
}

#[test]
fn test_traefik_basic() {
    let kdl = convert_fixture("traefik/basic.yaml");
    insta::assert_snapshot!("traefik_basic", kdl);
}

#[test]
fn test_caddy_basic() {
    let kdl = convert_fixture("caddy/Caddyfile");
    insta::assert_snapshot!("caddy_basic", kdl);
}
