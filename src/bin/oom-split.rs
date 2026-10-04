//! Split a continuous kernel log into losslessly preserved OOM event files.
use clap::Parser;
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::PathBuf,
    process::ExitCode,
};

/// Extract OOM events into oom-000001.log, oom-000002.log, ...
#[derive(Debug, Parser)]
#[command(
    name = "oom-split",
    after_help = "Original text and line endings are preserved; unrelated lines are excluded.\nPartial OOM events are retained. See the library documentation for boundary rules.\nUse -- before filenames beginning with a dash."
)]
struct Cli {
    /// Input UTF-8 kernel log, or - for stdin
    #[arg(value_name = "INPUT|-")]
    input: PathBuf,

    /// Output directory (must not exist)
    #[arg(value_name = "OUTPUT-DIRECTORY")]
    output_directory: PathBuf,
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    let mut input = String::new();
    if args.input.as_os_str() == "-" {
        io::stdin().read_to_string(&mut input)?;
    } else {
        input = fs::read_to_string(args.input)?;
    }
    // Validate the complete input before creating output files.
    let events = linux_oom_parser::parse_events(&input)?;
    let directory = args.output_directory;
    fs::create_dir(&directory)?;
    for (index, event) in events.iter().enumerate() {
        let path = directory.join(format!("oom-{:06}.log", index + 1));
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        write!(file, "{event}")?;
        file.flush()?;
    }
    eprintln!(
        "Wrote {} OOM event(s) to {}",
        events.len(),
        directory.display()
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("oom-split: {error}");
            ExitCode::FAILURE
        }
    }
}
