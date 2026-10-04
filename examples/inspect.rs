//! Print every typed record: `cargo run --example inspect -- path/to/dmesg.log`.
use clap::Parser;
use linux_oom_parser::parse;
use std::{error::Error, path::PathBuf};

/// Print every typed OOM record in a kernel log.
#[derive(Debug, Parser)]
#[command(name = "inspect")]
struct Cli {
    /// Input kernel log
    #[arg(value_name = "INPUT")]
    input: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();
    for record in parse(std::fs::read_to_string(args.input)?)? {
        println!("{record:#?}");
    }
    Ok(())
}
