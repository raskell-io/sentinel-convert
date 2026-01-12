use clap::Parser;
use colored::*;
use sentinel_convert::cli::{Cli, Commands, ConvertArgs, AnalyzeArgs, DetectArgs};
use sentinel_convert::emitter::EmitterOptions;
use sentinel_convert::parsers::{ParseOptions, ParserRegistry};
use sentinel_convert::{convert, AgentMode, ConvertOptions};
use std::fs;
use std::io::{self, Write};
use std::process;

fn main() {
    let cli = Cli::parse();

    // Set up color output
    match cli.color {
        sentinel_convert::cli::ColorChoice::Always => colored::control::set_override(true),
        sentinel_convert::cli::ColorChoice::Never => colored::control::set_override(false),
        sentinel_convert::cli::ColorChoice::Auto => {}
    }

    let result = match cli.command {
        Commands::Convert(args) => run_convert(args, cli.verbose, cli.quiet),
        Commands::Analyze(args) => run_analyze(args, cli.verbose),
        Commands::Detect(args) => run_detect(args),
    };

    if let Err(e) = result {
        eprintln!("{}: {}", "error".red().bold(), e);
        process::exit(1);
    }
}

fn run_convert(args: ConvertArgs, verbose: u8, quiet: bool) -> Result<(), String> {
    for input_path in &args.input {
        if !input_path.exists() {
            return Err(format!("File not found: {}", input_path.display()));
        }

        let options = ConvertOptions {
            format: args.format.map(|f| f.into()),
            agent_mode: args.agents.into(),
            parse_options: ParseOptions {
                follow_includes: args.follow_includes,
                max_include_depth: args.max_include_depth,
                strict: args.strict,
                preserve_comments: args.comments,
            },
            emitter_options: EmitterOptions {
                include_comments: args.comments,
                include_source_refs: args.source_refs,
                indent: "    ".to_string(),
            },
        };

        let result = convert(input_path, options).map_err(|e| e.to_string())?;

        // Print diagnostics if not quiet
        if !quiet {
            print_diagnostics(&result.diagnostics, verbose);
        }

        // Output the KDL
        if args.dry_run {
            if !quiet {
                println!("\n{}", "Dry run - would write:".yellow());
            }
            println!("{}", result.kdl_output);
        } else if let Some(output_path) = &args.output {
            fs::write(output_path, &result.kdl_output)
                .map_err(|e| format!("Failed to write output: {}", e))?;
            if !quiet {
                println!(
                    "\n{} Wrote {} to {}",
                    "Success:".green().bold(),
                    result.source_format,
                    output_path.display()
                );
            }
        } else {
            // Write to stdout
            print!("{}", result.kdl_output);
        }
    }

    Ok(())
}

fn run_analyze(args: AnalyzeArgs, verbose: u8) -> Result<(), String> {
    for input_path in &args.input {
        if !input_path.exists() {
            return Err(format!("File not found: {}", input_path.display()));
        }

        let options = ConvertOptions {
            format: args.format.map(|f| f.into()),
            agent_mode: AgentMode::Suggest,
            ..Default::default()
        };

        let result = convert(input_path, options).map_err(|e| e.to_string())?;

        if args.json {
            let output = serde_json::json!({
                "file": input_path.display().to_string(),
                "format": result.source_format.to_string(),
                "agent_suggestions": result.diagnostics.agent_suggestions,
                "warnings": result.diagnostics.warnings,
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        } else {
            println!("{}: {}", "Analyzing".cyan().bold(), input_path.display());
            println!(
                "{}: {}",
                "Detected format".cyan(),
                result.source_format.to_string().bold()
            );
            println!();

            if result.diagnostics.agent_suggestions.is_empty() {
                println!("{}", "No agent opportunities detected.".yellow());
            } else {
                println!("{}", "Agent Opportunities Detected:".green().bold());
                println!();

                for suggestion in &result.diagnostics.agent_suggestions {
                    let confidence_str = match suggestion.confidence {
                        sentinel_convert::ir::Confidence::High => "High".green(),
                        sentinel_convert::ir::Confidence::Medium => "Medium".yellow(),
                        sentinel_convert::ir::Confidence::Low => "Low".red(),
                    };

                    println!(
                        "  {} Agent ({} confidence)",
                        format!("{:?}", suggestion.agent_type).cyan().bold(),
                        confidence_str
                    );
                    println!("    Reason: {}", suggestion.reason);
                    if !suggestion.routes.is_empty() {
                        println!("    Routes: {}", suggestion.routes.join(", "));
                    }
                    println!();
                }
            }

            // Print summary
            println!("{}", "Summary:".bold());
            println!(
                "  Converted: {} items",
                result.diagnostics.converted.len()
            );
            println!("  Warnings: {}", result.diagnostics.warnings.len());
            println!(
                "  Agent suggestions: {}",
                result.diagnostics.agent_suggestions.len()
            );
        }
    }

    Ok(())
}

fn run_detect(args: DetectArgs) -> Result<(), String> {
    if !args.input.exists() {
        return Err(format!("File not found: {}", args.input.display()));
    }

    let content = fs::read_to_string(&args.input)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    let registry = ParserRegistry::new();

    if let Some(parser) = registry.detect_format(&args.input, &content) {
        println!("{}", parser.format());
    } else {
        return Err("Could not detect configuration format".to_string());
    }

    Ok(())
}

fn print_diagnostics(diagnostics: &sentinel_convert::ir::Diagnostics, verbose: u8) {
    // Print warnings
    for warning in &diagnostics.warnings {
        let prefix = match warning.severity {
            sentinel_convert::ir::Severity::Info => "info".blue(),
            sentinel_convert::ir::Severity::Warning => "warning".yellow(),
            sentinel_convert::ir::Severity::Error => "error".red(),
        };

        eprintln!("{}: {}", prefix, warning.message);
        if let Some(loc) = &warning.source_location {
            eprintln!("  --> {}:{}", loc.file.display(), loc.line);
        }
        eprintln!("  | {}", warning.source_directive);

        if let Some(suggestion) = &warning.suggestion {
            eprintln!("  = {}: {}", "suggestion".green(), suggestion);
        }
        eprintln!();
    }

    // Print skipped items in verbose mode
    if verbose > 0 && !diagnostics.skipped.is_empty() {
        eprintln!("{}", "Skipped items:".yellow());
        for skipped in &diagnostics.skipped {
            eprintln!("  - {} ({})", skipped.directive, skipped.reason);
        }
        eprintln!();
    }

    // Print agent suggestions
    if !diagnostics.agent_suggestions.is_empty() {
        eprintln!("{}", "Agent suggestions:".cyan());
        for suggestion in &diagnostics.agent_suggestions {
            let confidence = match suggestion.confidence {
                sentinel_convert::ir::Confidence::High => "high".green(),
                sentinel_convert::ir::Confidence::Medium => "medium".yellow(),
                sentinel_convert::ir::Confidence::Low => "low".red(),
            };

            eprintln!(
                "  {:?} agent ({} confidence)",
                suggestion.agent_type, confidence
            );
            eprintln!("    Reason: {}", suggestion.reason);
            if !suggestion.routes.is_empty() {
                eprintln!("    Routes: {}", suggestion.routes.join(", "));
            }
        }
        eprintln!();
    }

    // Summary
    if verbose > 0 {
        eprintln!("{}", "Conversion summary:".bold());
        eprintln!("  Converted: {} items", diagnostics.converted.len());
        eprintln!("  Warnings: {}", diagnostics.warnings.len());
        eprintln!("  Skipped: {}", diagnostics.skipped.len());
        eprintln!(
            "  Agent suggestions: {}",
            diagnostics.agent_suggestions.len()
        );
    }
}
