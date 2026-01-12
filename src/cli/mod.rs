//! CLI argument definitions and command handlers

use crate::ir::SourceFormat;
use crate::AgentMode;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Convert reverse proxy configurations to Sentinel KDL format
#[derive(Parser)]
#[command(name = "sentinel-convert")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Increase verbosity (can be repeated)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Suppress non-essential output
    #[arg(short, long)]
    pub quiet: bool,

    /// Color output
    #[arg(long, value_enum, default_value = "auto")]
    pub color: ColorChoice,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Convert configuration to Sentinel KDL
    Convert(ConvertArgs),

    /// Analyze configuration for agent opportunities
    Analyze(AnalyzeArgs),

    /// Detect source format of a configuration file
    Detect(DetectArgs),
}

#[derive(clap::Args)]
pub struct ConvertArgs {
    /// Input file(s)
    #[arg(required = true)]
    pub input: Vec<PathBuf>,

    /// Source format (auto-detect if not specified)
    #[arg(short, long, value_enum)]
    pub format: Option<SourceFormatArg>,

    /// Output file (stdout if not specified)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Follow include directives
    #[arg(long, default_value = "true")]
    pub follow_includes: bool,

    /// Maximum include depth
    #[arg(long, default_value = "10")]
    pub max_include_depth: usize,

    /// Fail on unknown directives
    #[arg(long)]
    pub strict: bool,

    /// Agent detection mode
    #[arg(long, value_enum, default_value = "suggest")]
    pub agents: AgentModeArg,

    /// Base directory for agent sockets
    #[arg(long, default_value = "/run/sentinel")]
    pub agent_socket_dir: PathBuf,

    /// Include explanatory comments
    #[arg(long, default_value = "true")]
    pub comments: bool,

    /// Include source file references
    #[arg(long)]
    pub source_refs: bool,

    /// Dry run (show output without writing)
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(clap::Args)]
pub struct AnalyzeArgs {
    /// Input file(s)
    #[arg(required = true)]
    pub input: Vec<PathBuf>,

    /// Source format (auto-detect if not specified)
    #[arg(short, long, value_enum)]
    pub format: Option<SourceFormatArg>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args)]
pub struct DetectArgs {
    /// Input file
    #[arg(required = true)]
    pub input: PathBuf,
}

#[derive(ValueEnum, Clone, Copy)]
pub enum SourceFormatArg {
    Nginx,
    Apache,
    Haproxy,
    Traefik,
    Caddy,
    Envoy,
}

impl From<SourceFormatArg> for SourceFormat {
    fn from(arg: SourceFormatArg) -> Self {
        match arg {
            SourceFormatArg::Nginx => SourceFormat::Nginx,
            SourceFormatArg::Apache => SourceFormat::Apache,
            SourceFormatArg::Haproxy => SourceFormat::HAProxy,
            SourceFormatArg::Traefik => SourceFormat::Traefik,
            SourceFormatArg::Caddy => SourceFormat::Caddy,
            SourceFormatArg::Envoy => SourceFormat::Envoy,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Default)]
pub enum AgentModeArg {
    /// Auto-create agents for high-confidence detections
    Auto,
    /// Only suggest agents in output
    #[default]
    Suggest,
    /// Disable agent detection
    None,
}

impl From<AgentModeArg> for AgentMode {
    fn from(arg: AgentModeArg) -> Self {
        match arg {
            AgentModeArg::Auto => AgentMode::Auto,
            AgentModeArg::Suggest => AgentMode::Suggest,
            AgentModeArg::None => AgentMode::None,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Default)]
pub enum ColorChoice {
    #[default]
    Auto,
    Always,
    Never,
}
