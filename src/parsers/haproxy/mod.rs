//! HAProxy configuration parser

mod mapping;
mod parser;

pub use parser::HAProxyParser;

use crate::ir::SourceLocation;
use std::path::PathBuf;

/// Parsed HAProxy configuration
#[derive(Debug, Clone, Default)]
pub struct HAProxyConfig {
    pub global: Option<Section>,
    pub defaults: Option<Section>,
    pub frontends: Vec<Section>,
    pub backends: Vec<Section>,
    pub listens: Vec<Section>,
}

/// A HAProxy configuration section
#[derive(Debug, Clone)]
pub struct Section {
    pub section_type: SectionType,
    pub name: Option<String>,
    pub directives: Vec<Directive>,
    pub location: SourceLocation,
}

/// Section type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    Global,
    Defaults,
    Frontend,
    Backend,
    Listen,
}

impl std::fmt::Display for SectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Global => write!(f, "global"),
            Self::Defaults => write!(f, "defaults"),
            Self::Frontend => write!(f, "frontend"),
            Self::Backend => write!(f, "backend"),
            Self::Listen => write!(f, "listen"),
        }
    }
}

/// A HAProxy directive
#[derive(Debug, Clone)]
pub struct Directive {
    pub name: String,
    pub args: Vec<String>,
    pub location: SourceLocation,
}

impl Directive {
    pub fn new(name: impl Into<String>, line: usize, file: PathBuf) -> Self {
        Self {
            name: name.into(),
            args: Vec::new(),
            location: SourceLocation::new(file, line),
        }
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Get the first argument
    pub fn first_arg(&self) -> Option<&str> {
        self.args.first().map(|s| s.as_str())
    }

    /// Get argument at index
    pub fn arg(&self, index: usize) -> Option<&str> {
        self.args.get(index).map(|s| s.as_str())
    }

    /// Check if directive has a specific argument
    pub fn has_arg(&self, value: &str) -> bool {
        self.args.iter().any(|a| a == value)
    }

    /// Get all arguments as a single string
    pub fn args_str(&self) -> String {
        self.args.join(" ")
    }
}

impl Section {
    /// Find directive by name
    pub fn find_directive(&self, name: &str) -> Option<&Directive> {
        self.directives.iter().find(|d| d.name == name)
    }

    /// Find all directives by name
    pub fn find_all_directives(&self, name: &str) -> Vec<&Directive> {
        self.directives.iter().filter(|d| d.name == name).collect()
    }

    /// Check if section has a directive
    pub fn has_directive(&self, name: &str) -> bool {
        self.directives.iter().any(|d| d.name == name)
    }
}
