//! Print an OOM log with readable memory sizes and percentages of RAM or swap.
use std::{
    env, fs,
    io::{self, Read, Write},
    process::ExitCode,
};

const HELP: &str = "Usage: oom-format [--page-size BYTES] [--total-memory BYTES] [INPUT|-]\n\nPrint a UTF-8 OOM log with IEC memory sizes and percentages of total system RAM.\nThe task swap column uses each event's Total swap; missing or zero swap totals\ndisplay swap unknown. Read stdin when INPUT is omitted or is -.\nPreserve other text and line endings.\nRAM totals come from each event's pages RAM line, excluding swap. Missing or zero\nRAM totals display RAM unknown; --total-memory supplies a positive total in bytes.\nPage size is inferred from buddy buckets, falling back to 4096 bytes.\nUse --page-size to override it. Use -- before a filename beginning with a dash.\n";

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let mut options = linux_oom_parser::FormatOptions::default();
    let mut input_path = None;
    let mut positional = false;
    while let Some(arg) = args.next() {
        if !positional && (arg == "--help" || arg == "-h") {
            io::stdout().lock().write_all(HELP.as_bytes())?;
            return Ok(());
        } else if !positional && arg == "--" {
            positional = true;
        } else if !positional && arg == "--page-size" {
            options.page_size = Some(
                args.next()
                    .and_then(|value| value.into_string().ok())
                    .ok_or("--page-size requires a byte count")?
                    .parse()?,
            );
        } else if !positional && arg == "--total-memory" {
            let bytes: u64 = args
                .next()
                .and_then(|value| value.into_string().ok())
                .ok_or("--total-memory requires a positive byte count")?
                .parse()
                .map_err(|_| "--total-memory requires a positive byte count")?;
            if bytes == 0 {
                return Err("--total-memory requires a positive byte count".into());
            }
            options.total_memory = Some(linux_oom_parser::ByteSize::b(bytes));
        } else if !positional && arg != "-" && arg.to_string_lossy().starts_with('-') {
            return Err(format!("unknown option: {}", arg.to_string_lossy()).into());
        } else if input_path.replace(arg).is_some() {
            return Err(HELP.into());
        }
    }
    let mut input = String::new();
    match input_path {
        Some(path) if path != "-" => input = fs::read_to_string(path)?,
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
