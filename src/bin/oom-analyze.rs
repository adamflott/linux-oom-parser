//! Explain parsed OOM events using evidence-based heuristics.
use std::{
    env, fs,
    io::{self, Read, Write},
    process::ExitCode,
};
const HELP: &str = "Usage: oom-analyze [--verbose] [--page-size BYTES] <INPUT|->\n\nExplain each OOM event: trigger, evidence, possible causes, and prevention.\nReads a UTF-8 kernel log or stdin (-). Does not inspect or modify the live system.\nPage conversions infer size from consistent buddy buckets, else use 4096 bytes; --page-size overrides.\nUse --verbose for allocation flags, exact bytes, and page counts.\nSource line numbers refer to the input. Hypotheses are not confirmed diagnoses.\n";
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let mut out = io::BufWriter::new(io::stdout().lock());
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        write!(out, "{HELP}")?;
        return Ok(());
    }
    let mut options = linux_oom_parser::AnalysisOptions::default();
    let mut input_path = None;
    let mut verbose = false;
    let mut explicit_page_size = false;
    let mut args = args.iter();
    let mut positional = false;
    while let Some(arg) = args.next() {
        if !positional && arg == "--" {
            positional = true;
        } else if !positional && arg == "--verbose" {
            verbose = true;
        } else if !positional && arg == "--page-size" {
            explicit_page_size = true;
            options.page_size = args
                .next()
                .and_then(|s| s.to_str())
                .ok_or("--page-size requires a positive byte count")?
                .parse()
                .map_err(|_| "page size must be a power of two of at least 1024 bytes")?;
        } else if !positional && arg != "-" && arg.to_string_lossy().starts_with('-') {
            return Err(format!("unknown option: {}", arg.to_string_lossy()).into());
        } else if input_path.replace(arg).is_some() {
            return Err(HELP.into());
        }
    }
    let input_path = input_path.ok_or(HELP)?;
    let mut input = String::new();
    if input_path == "-" {
        io::stdin().read_to_string(&mut input)?;
    } else {
        input = fs::read_to_string(input_path)?;
    }
    let events = linux_oom_parser::parse_events(&input)?;
    writeln!(out, "{} OOM event(s) found.", events.len())?;
    for (i, event) in events.iter().enumerate() {
        let report = if explicit_page_size {
            linux_oom_parser::format_event_analysis(event, options, verbose)
        } else {
            linux_oom_parser::format_event_analysis_auto(event, verbose)
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
