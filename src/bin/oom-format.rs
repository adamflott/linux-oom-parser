//! Print an OOM log with readable memory sizes and percentages of RAM or swap.
use clap::Parser;
use linux_oom_parser::PageSize;
use std::{
    fs,
    io::{self, Read, Write},
    num::NonZeroU64,
    path::PathBuf,
    process::ExitCode,
};

/// Print a UTF-8 OOM log with IEC memory sizes and percentages of total system RAM.
#[derive(Debug, Parser)]
#[command(
    name = "oom-format",
    args_override_self = true,
    after_help = "The task swap column uses each event's Total swap; missing or zero swap totals\ndisplay swap unknown. Other text and line endings are preserved.\nRAM totals come from each event's pages RAM line, excluding swap. Missing or zero\nRAM totals display RAM unknown.\nPage size is inferred from buddy buckets, falling back to 4096 bytes.\nUse -- before a filename beginning with a dash."
)]
struct Cli {
    /// Override the base page size (a power of two of at least 1024 bytes)
    #[arg(long, value_name = "BYTES")]
    page_size: Option<PageSize>,

    /// Override total system RAM with a positive byte count
    #[arg(long, value_name = "BYTES")]
    total_memory: Option<NonZeroU64>,

    /// Input OOM log (read stdin if omitted or -)
    #[arg(value_name = "INPUT|-")]
    input: Option<PathBuf>,
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    let mut options = linux_oom_parser::FormatOptions::default();
    options.page_size = args.page_size;
    options.total_memory = args
        .total_memory
        .map(|bytes| linux_oom_parser::ByteSize::b(bytes.get()));
    let mut input = String::new();
    match args.input {
        Some(path) if path.as_os_str() != "-" => input = fs::read_to_string(path)?,
        _ => {
            io::stdin().read_to_string(&mut input)?;
        }
    }
    // Parse and format everything before writing, so errors never print half a log.
    let formatted = linux_oom_parser::format_log(&input, options)?;
    let mut out = io::BufWriter::new(io::stdout().lock());
    out.write_all(formatted.as_bytes())?;
    out.flush()?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("oom-format: {error}");
            ExitCode::FAILURE
        }
    }
}
