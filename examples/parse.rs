//! Run `cargo run --example parse -- path/to/kernel.log`, or pipe a log to stdin.
use clap::Parser;
use linux_oom_parser::{OomMessage, parse};
use std::{
    error::Error,
    io::{self, Read},
    path::PathBuf,
};

/// Print killed processes and their anonymous RSS from a kernel log.
#[derive(Debug, Parser)]
#[command(name = "parse")]
struct Cli {
    /// Input kernel log (read stdin if omitted)
    #[arg(value_name = "INPUT")]
    input: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();
    let text = match args.input {
        Some(path) => std::fs::read_to_string(path)?,
        None => {
            let mut text = String::new();
            io::stdin().read_to_string(&mut text)?;
            text
        }
    };
    for record in parse(text)? {
        if let OomMessage::Killed(process) = record.message {
            let anonymous_rss = process.memory.anon_rss.map_or_else(
                || "not reported".into(),
                |size| size.display().iec().to_string(),
            );
            println!(
                "line {}: killed {} ({}) with {} anonymous RSS",
                record.line_number, process.pid, process.name, anonymous_rss
            );
        }
    }
    Ok(())
}
