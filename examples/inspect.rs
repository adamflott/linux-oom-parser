//! Print every typed record: `cargo run --example inspect -- path/to/dmesg.log`.
use linux_oom_parser::parse;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: cargo run --example inspect -- path/to/dmesg.log")?;
    for record in parse(std::fs::read_to_string(path)?)? {
        println!("{record:#?}");
    }
    Ok(())
}
