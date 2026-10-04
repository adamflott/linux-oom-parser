//! Compare memory use in two captured Linux OOM logs.
use clap::Parser;
use linux_oom_parser::{
    ComparisonOptions, OomEvent, PageSize, format_event_comparison, parse_events,
};
use std::{
    ffi::OsStr,
    fs,
    io::{self, Read, Write},
    path::PathBuf,
    process::ExitCode,
};

/// Compare memory use in two UTF-8 OOM logs and report findings to stdout.
#[derive(Debug, Parser)]
#[command(
    name = "oom-compare",
    args_override_self = true,
    after_help = "Deltas are AFTER - BEFORE. Use - for stdin on at most one side.\nMultiple OOM events are paired in log order; unmatched events are reported.\nOnly changed or one-sided measurements are shown, with source line numbers.\nProcesses are grouped by command and UID rather than PID.\n\nPage sizes are inferred independently per event from consistent buddy buckets,\nfalling back to 4096 bytes. Overrides must be powers of two of at least 1024.\nMissing measurements remain unknown. Overlapping categories are not summed.\nUse -- before a filename beginning with a dash."
)]
struct Cli {
    /// Override the base page size for both logs
    #[arg(long, value_name = "BYTES")]
    page_size: Option<PageSize>,

    /// Override only BEFORE (takes precedence over --page-size)
    #[arg(long, value_name = "BYTES")]
    before_page_size: Option<PageSize>,

    /// Override only AFTER (takes precedence over --page-size)
    #[arg(long, value_name = "BYTES")]
    after_page_size: Option<PageSize>,

    /// Before OOM log, or - for stdin
    #[arg(value_name = "BEFORE|-")]
    before: PathBuf,

    /// After OOM log, or - for stdin
    #[arg(value_name = "AFTER|-")]
    after: PathBuf,
}

fn read_events(path: &OsStr, side: &str) -> Result<Vec<OomEvent>, Box<dyn std::error::Error>> {
    let mut input = String::new();
    if path == "-" {
        io::stdin()
            .read_to_string(&mut input)
            .map_err(|error| format!("{side} input (stdin): {error}"))?;
    } else {
        input =
            fs::read_to_string(path).map_err(|error| format!("{side} input {path:?}: {error}"))?;
    }
    let events = parse_events(&input).map_err(|error| format!("{side} input {path:?}: {error}"))?;
    if events.is_empty() {
        return Err(format!("no OOM events found in {side} input {path:?}").into());
    }
    Ok(events)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    let before_path = args.before.as_os_str();
    let after_path = args.after.as_os_str();
    let mut options = ComparisonOptions::default();
    if before_path == "-" && after_path == "-" {
        return Err("stdin (-) can be used for only one input".into());
    }
    options.before_page_size = args.before_page_size.or(args.page_size);
    options.after_page_size = args.after_page_size.or(args.page_size);
    // Parse both complete inputs before writing reports so errors leave stdout clean.
    let before = read_events(before_path, "before")?;
    let after = read_events(after_path, "after")?;
    let mut out = io::BufWriter::new(io::stdout().lock());
    writeln!(out, "OOM memory comparison (after - before)")?;
    writeln!(
        out,
        "Before: {before_path:?}; {} OOM event(s).",
        before.len()
    )?;
    writeln!(out, "After:  {after_path:?}; {} OOM event(s).", after.len())?;
    writeln!(
        out,
        "Events are paired in log order; pairing does not establish the same workload."
    )?;
    for (index, (before_event, after_event)) in before.iter().zip(&after).enumerate() {
        writeln!(
            out,
            "\nEvent {} compared with event {}:",
            index + 1,
            index + 1
        )?;
        write!(
            out,
            "{}",
            format_event_comparison(before_event, after_event, options)
        )?;
    }
    let paired = before.len().min(after.len());
    for (side, events) in [("before", &before), ("after", &after)] {
        for (index, event) in events.iter().enumerate().skip(paired) {
            let lines = event
                .records
                .iter()
                .map(|record| record.line_number.to_string())
                .collect::<Vec<_>>()
                .join(",");
            writeln!(
                out,
                "\nUnmatched {side} event {} (source lines {lines}); no counterpart to compare.",
                index + 1
            )?;
        }
    }
    out.flush()?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("oom-compare: {error}");
            ExitCode::FAILURE
        }
    }
}
