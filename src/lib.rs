//! Sentinel Config Converter
//!
//! Convert reverse proxy configurations from nginx, Apache, HAProxy,
//! Traefik, Caddy, and Envoy to Sentinel KDL format.

pub mod agents;
pub mod cli;
pub mod emitter;
pub mod ir;
pub mod parsers;

pub use ir::{ConversionResult, Diagnostics, SentinelConfig, SourceFormat};
pub use parsers::{ParseContext, ParseOptions, Parser, ParserRegistry};

use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConvertError {
    #[error("Failed to read file: {0}")]
    FileRead(#[from] std::io::Error),

    #[error("Failed to detect configuration format")]
    FormatDetection,

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Emission error: {0}")]
    Emission(String),
}

pub type Result<T> = std::result::Result<T, ConvertError>;

/// Convert a configuration file to Sentinel KDL format
pub fn convert(path: &Path, options: ConvertOptions) -> Result<ConversionResult> {
    let content = std::fs::read_to_string(path)?;
    convert_string(&content, path, options)
}

/// Convert a configuration string to Sentinel KDL format
pub fn convert_string(content: &str, path: &Path, options: ConvertOptions) -> Result<ConversionResult> {
    let registry = ParserRegistry::new();

    // Detect or use specified format
    let parser = if let Some(format) = options.format {
        registry
            .get_parser(format)
            .ok_or(ConvertError::FormatDetection)?
    } else {
        registry
            .detect_format(path, content)
            .ok_or(ConvertError::FormatDetection)?
    };

    // Parse the configuration
    let mut ctx = ParseContext::new(path.to_path_buf(), content.to_string());
    ctx.options = options.parse_options;

    let mut output = parser.parse(&mut ctx).map_err(|e| ConvertError::Parse(e.to_string()))?;

    // Run agent detection if enabled
    if options.agent_mode != AgentMode::None {
        let detector = agents::AgentDetector::new();
        detector.detect(&mut output.config, &mut output.diagnostics, options.agent_mode);
    }

    // Generate KDL output
    let emitter = emitter::KdlEmitter::new(options.emitter_options);
    let kdl_output = emitter
        .emit(&output.config)
        .map_err(|e| ConvertError::Emission(e.to_string()))?;

    Ok(ConversionResult {
        source_format: parser.format(),
        source_files: vec![path.to_path_buf()],
        config: output.config,
        kdl_output,
        diagnostics: output.diagnostics,
    })
}

/// Options for conversion
#[derive(Debug, Clone, Default)]
pub struct ConvertOptions {
    /// Source format (auto-detect if None)
    pub format: Option<SourceFormat>,
    /// Agent detection mode
    pub agent_mode: AgentMode,
    /// Parser options
    pub parse_options: ParseOptions,
    /// Emitter options
    pub emitter_options: emitter::EmitterOptions,
}

/// Agent detection mode
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AgentMode {
    /// Auto-create agents for high-confidence detections
    Auto,
    /// Only suggest agents in diagnostics
    #[default]
    Suggest,
    /// Disable agent detection
    None,
}
