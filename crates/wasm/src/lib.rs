//! WebAssembly bindings for sentinel-convert
//!
//! Enables running the config converter in the browser.

use serde::Serialize;
use std::path::Path;
use wasm_bindgen::prelude::*;

use sentinel_convert::{
    convert_string, AgentMode, ConvertOptions, ParseOptions, SourceFormat,
    emitter::EmitterOptions,
    parsers::ParserRegistry,
};

/// Initialize panic hook for better error messages in browser console
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Get the version of the WASM module
#[wasm_bindgen]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Get list of supported source formats
#[wasm_bindgen]
pub fn get_supported_formats() -> JsValue {
    let formats = vec!["nginx", "haproxy", "traefik", "caddy", "envoy"];
    serde_wasm_bindgen::to_value(&formats).unwrap_or(JsValue::NULL)
}

/// Result of format detection
#[derive(Serialize)]
struct DetectResult {
    format: Option<String>,
    confidence: f32,
    signatures_matched: Vec<String>,
}

/// Detect the format of a configuration string
#[wasm_bindgen]
pub fn detect_format(config: &str) -> JsValue {
    let registry = ParserRegistry::new();
    let path = Path::new("config");

    let result = if let Some(parser) = registry.detect_format(path, config) {
        // Collect matched signatures
        let mut signatures = Vec::new();
        for sig in parser.signatures() {
            if let Ok(re) = regex::Regex::new(sig.pattern) {
                if re.is_match(config) {
                    signatures.push(sig.description.to_string());
                }
            }
        }

        let confidence = if !signatures.is_empty() { 0.9 } else { 0.5 };

        DetectResult {
            format: Some(format!("{:?}", parser.format()).to_lowercase()),
            confidence,
            signatures_matched: signatures,
        }
    } else {
        DetectResult {
            format: None,
            confidence: 0.0,
            signatures_matched: vec![],
        }
    };

    serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL)
}

/// Result of conversion
#[derive(Serialize)]
struct ConvertResult {
    success: bool,
    kdl: Option<String>,
    format: Option<String>,
    error: Option<String>,
    warnings: Vec<Warning>,
    agents: Vec<AgentInfo>,
}

/// Warning from conversion
#[derive(Serialize)]
struct Warning {
    severity: String,
    message: String,
    source_directive: Option<String>,
    suggestion: Option<String>,
}

/// Detected agent info
#[derive(Serialize)]
struct AgentInfo {
    name: String,
    agent_type: String,
    confidence: String,
    patterns_matched: Vec<String>,
}

/// Convert a configuration string to Sentinel KDL format
///
/// # Arguments
/// * `config` - The source configuration content
/// * `format` - Optional format hint ("nginx", "haproxy", etc.). Auto-detects if not provided.
///
/// # Returns
/// A JavaScript object with:
/// - `success`: boolean indicating if conversion succeeded
/// - `kdl`: the generated KDL output (if successful)
/// - `format`: the detected/used source format
/// - `error`: error message (if failed)
/// - `warnings`: array of warnings from conversion
/// - `agents`: array of detected agents
#[wasm_bindgen]
pub fn convert(config: &str, format: Option<String>) -> JsValue {
    let source_format = format.as_ref().and_then(|f| parse_format(f));

    let options = ConvertOptions {
        format: source_format,
        agent_mode: AgentMode::Auto,
        parse_options: ParseOptions {
            follow_includes: false, // Can't follow includes in browser
            ..Default::default()
        },
        emitter_options: EmitterOptions {
            include_comments: true,
            ..Default::default()
        },
    };

    // Use a dummy path since we're working with strings
    let path = Path::new("config");

    match convert_string(config, path, options) {
        Ok(result) => {
            // Extract warnings
            let warnings: Vec<Warning> = result
                .diagnostics
                .warnings
                .iter()
                .map(|w| Warning {
                    severity: format!("{:?}", w.severity).to_lowercase(),
                    message: w.message.clone(),
                    source_directive: Some(w.source_directive.clone()),
                    suggestion: w.suggestion.clone(),
                })
                .collect();

            // Extract agent info
            let agents: Vec<AgentInfo> = result
                .config
                .agents
                .iter()
                .map(|a| {
                    let (confidence, patterns) = match &a.detection {
                        sentinel_convert::ir::AgentDetection::Explicit => {
                            ("explicit".to_string(), vec![])
                        }
                        sentinel_convert::ir::AgentDetection::Inferred { confidence, patterns_matched } => {
                            (format!("{:?}", confidence).to_lowercase(), patterns_matched.clone())
                        }
                        sentinel_convert::ir::AgentDetection::Suggested { reason } => {
                            ("suggested".to_string(), vec![reason.clone()])
                        }
                    };
                    AgentInfo {
                        name: a.name.clone(),
                        agent_type: format!("{:?}", a.agent_type).to_lowercase(),
                        confidence,
                        patterns_matched: patterns,
                    }
                })
                .collect();

            let convert_result = ConvertResult {
                success: true,
                kdl: Some(result.kdl_output),
                format: Some(format!("{:?}", result.source_format).to_lowercase()),
                error: None,
                warnings,
                agents,
            };

            serde_wasm_bindgen::to_value(&convert_result).unwrap_or(JsValue::NULL)
        }
        Err(e) => {
            let convert_result = ConvertResult {
                success: false,
                kdl: None,
                format: format.clone(),
                error: Some(e.to_string()),
                warnings: vec![],
                agents: vec![],
            };

            serde_wasm_bindgen::to_value(&convert_result).unwrap_or(JsValue::NULL)
        }
    }
}

/// Result of validation
#[derive(Serialize)]
struct ValidateResult {
    valid: bool,
    format: Option<String>,
    errors: Vec<ValidationError>,
    warnings: Vec<Warning>,
}

/// Validation error
#[derive(Serialize)]
struct ValidationError {
    message: String,
    line: Option<usize>,
    column: Option<usize>,
}

/// Validate a configuration string without full conversion
///
/// # Arguments
/// * `config` - The source configuration content
/// * `format` - Optional format hint
///
/// # Returns
/// A JavaScript object with validation results
#[wasm_bindgen]
pub fn validate(config: &str, format: Option<String>) -> JsValue {
    let source_format = format.as_ref().and_then(|f| parse_format(f));

    let options = ConvertOptions {
        format: source_format,
        agent_mode: AgentMode::None, // Skip agent detection for validation
        parse_options: ParseOptions {
            follow_includes: false,
            strict: true,
            ..Default::default()
        },
        emitter_options: EmitterOptions::default(),
    };

    let path = Path::new("config");

    match convert_string(config, path, options) {
        Ok(result) => {
            let warnings: Vec<Warning> = result
                .diagnostics
                .warnings
                .iter()
                .map(|w| Warning {
                    severity: format!("{:?}", w.severity).to_lowercase(),
                    message: w.message.clone(),
                    source_directive: Some(w.source_directive.clone()),
                    suggestion: w.suggestion.clone(),
                })
                .collect();

            let validate_result = ValidateResult {
                valid: true,
                format: Some(format!("{:?}", result.source_format).to_lowercase()),
                errors: vec![],
                warnings,
            };

            serde_wasm_bindgen::to_value(&validate_result).unwrap_or(JsValue::NULL)
        }
        Err(e) => {
            let error_msg = e.to_string();

            // Try to extract line/column from error message
            let (line, column) = extract_location_from_error(&error_msg);

            let validate_result = ValidateResult {
                valid: false,
                format: format.clone(),
                errors: vec![ValidationError {
                    message: error_msg,
                    line,
                    column,
                }],
                warnings: vec![],
            };

            serde_wasm_bindgen::to_value(&validate_result).unwrap_or(JsValue::NULL)
        }
    }
}

/// Parse format string to SourceFormat
fn parse_format(format: &str) -> Option<SourceFormat> {
    match format.to_lowercase().as_str() {
        "nginx" => Some(SourceFormat::Nginx),
        "haproxy" => Some(SourceFormat::HAProxy),
        "traefik" => Some(SourceFormat::Traefik),
        "caddy" => Some(SourceFormat::Caddy),
        "envoy" => Some(SourceFormat::Envoy),
        "apache" => Some(SourceFormat::Apache),
        _ => None,
    }
}

/// Extract line/column from error message if present
fn extract_location_from_error(error: &str) -> (Option<usize>, Option<usize>) {
    // Try to match patterns like "at line 5" or "line 5, column 10"
    let line = regex::Regex::new(r"(?:at |line )(\d+)")
        .ok()
        .and_then(|re| re.captures(error))
        .and_then(|cap| cap.get(1))
        .and_then(|m| m.as_str().parse::<usize>().ok());

    let column = regex::Regex::new(r"column (\d+)")
        .ok()
        .and_then(|re| re.captures(error))
        .and_then(|cap| cap.get(1))
        .and_then(|m| m.as_str().parse::<usize>().ok());

    (line, column)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_version() {
        let version = get_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn test_parse_format() {
        assert!(matches!(parse_format("nginx"), Some(SourceFormat::Nginx)));
        assert!(matches!(parse_format("NGINX"), Some(SourceFormat::Nginx)));
        assert!(matches!(parse_format("haproxy"), Some(SourceFormat::HAProxy)));
        assert!(parse_format("unknown").is_none());
    }
}
