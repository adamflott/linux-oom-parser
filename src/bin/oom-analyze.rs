//! Explain parsed OOM events using evidence-based heuristics.
use clap::Parser;
use linux_oom_parser::{AnalysisOptions, PageSize};
use std::{
    fs,
    io::{self, Read, Write},
    path::PathBuf,
    process::ExitCode,
};

/// Explain each OOM event: trigger, evidence, possible causes, and prevention.
#[derive(Debug, Parser)]
#[command(
    name = "oom-analyze",
    args_override_self = true,
    after_help = "Reads a UTF-8 kernel log or stdin (-). Does not inspect or modify the live system.\nPage conversions infer size from consistent buddy buckets, else use 4096 bytes.\nSource line numbers refer to the input. Hypotheses are not confirmed diagnoses.\nUse -- before a filename beginning with a dash."
)]
struct Cli {
    /// Include allocation flags, exact bytes, and page counts
    #[arg(long)]
    verbose: bool,

    /// Override the base page size (a power of two of at least 1024 bytes)
    #[arg(long, value_name = "BYTES")]
    page_size: Option<PageSize>,

    /// Input kernel log, or - for stdin
    #[arg(value_name = "INPUT|-")]
    input: PathBuf,
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    let mut out = io::BufWriter::new(io::stdout().lock());
    let mut input = String::new();
    if args.input.as_os_str() == "-" {
        io::stdin().read_to_string(&mut input)?;
    } else {
        input = fs::read_to_string(args.input)?;
    }
    let events = linux_oom_parser::parse_events(&input)?;
    writeln!(out, "{} OOM event(s) found.", events.len())?;
    for (i, event) in events.iter().enumerate() {
        let report = match args.page_size {
            Some(page_size) => linux_oom_parser::format_event_analysis(
                event,
                AnalysisOptions { page_size },
                args.verbose,
            ),
            None => linux_oom_parser::format_event_analysis_auto(event, args.verbose),
        };
        write!(out, "\nEvent {}: {}", i + 1, report)?;
    }
    out.flush()?;
    Ok(())
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("oom-analyze: {e}");
            ExitCode::FAILURE
        }
    }
}
