//! Run `cargo run --example parse -- path/to/kernel.log`, or pipe a log to stdin.
use linux_oom_parser::{OomMessage, parse};
use std::{
    error::Error,
    io::{self, Read},
};

fn main() -> Result<(), Box<dyn Error>> {
    let text = match std::env::args_os().nth(1) {
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
