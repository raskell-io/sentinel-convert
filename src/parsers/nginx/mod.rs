//! nginx configuration parser

mod lexer;
mod mapping;
mod parser;

pub use parser::NginxParser;

use crate::ir::SourceLocation;
use std::path::PathBuf;

/// Parsed nginx configuration
#[derive(Debug, Clone, Default)]
pub struct NginxConfig {
    pub directives: Vec<Directive>,
}

/// A nginx directive (simple or block)
#[derive(Debug, Clone)]
pub struct Directive {
    pub name: String,
    pub args: Vec<String>,
    pub block: Option<Vec<Directive>>,
    pub location: SourceLocation,
}

impl Directive {
    pub fn new(name: impl Into<String>, line: usize, file: PathBuf) -> Self {
        Self {
            name: name.into(),
            args: Vec::new(),
            block: None,
            location: SourceLocation::new(file, line),
        }
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    pub fn with_block(mut self, block: Vec<Directive>) -> Self {
        self.block = Some(block);
        self
    }

    /// Check if this is a block directive
    pub fn is_block(&self) -> bool {
        self.block.is_some()
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

    /// Find child directive by name
    pub fn find_directive(&self, name: &str) -> Option<&Directive> {
        self.block
            .as_ref()
            .and_then(|b| b.iter().find(|d| d.name == name))
    }

    /// Find all child directives by name
    pub fn find_all_directives(&self, name: &str) -> Vec<&Directive> {
        self.block
            .as_ref()
            .map(|b| b.iter().filter(|d| d.name == name).collect())
            .unwrap_or_default()
    }

    /// Get block children
    pub fn children(&self) -> &[Directive] {
        self.block.as_deref().unwrap_or(&[])
    }
}
