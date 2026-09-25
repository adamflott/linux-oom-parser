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
            println!(
                "line {}: killed {} ({}) with {:?} KiB anonymous RSS",
                record.line_number, process.pid, process.name, process.memory.anon_rss
            );
        }
    }
    Ok(())
}
