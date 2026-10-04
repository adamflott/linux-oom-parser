//! Summarize OOM events in a continuous kernel log.
use clap::Parser;
use linux_oom_parser::{OomMessage, parse_events};
use std::{error::Error, path::PathBuf};

/// Summarize OOM events in a continuous kernel log.
#[derive(Debug, Parser)]
#[command(name = "events")]
struct Cli {
    /// Input kernel log
    #[arg(value_name = "INPUT")]
    input: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();
    let events = parse_events(std::fs::read_to_string(args.input)?)?;
    println!("{} OOM events", events.len());
    for (index, event) in events.iter().enumerate() {
        println!(
            "Event {}: {} records, starting at line {}",
            index + 1,
            event.records.len(),
            event.records[0].line_number
        );
        for record in &event.records {
            if let OomMessage::Killed(victim) = &record.message {
                println!(
                    "  line {}: killed {} ({})",
                    record.line_number, victim.pid, victim.name
                );
            }
        }
    }
    Ok(())
}
