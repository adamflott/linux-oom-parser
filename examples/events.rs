//! Summarize OOM events in a continuous kernel log.
use linux_oom_parser::{OomMessage, parse_events};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: cargo run --example events -- path/to/kernel.log")?;
    let events = parse_events(std::fs::read_to_string(path)?)?;
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
