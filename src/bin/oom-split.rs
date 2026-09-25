//! Split a continuous kernel log into losslessly preserved OOM event files.
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::PathBuf,
    process::ExitCode,
};

const HELP: &str = "Usage: oom-split <INPUT|-> <OUTPUT-DIRECTORY>\n\nExtract OOM events into oom-000001.log, oom-000002.log, ...\nUse - to read UTF-8 kernel logs from stdin. The output directory must not exist.\nOriginal text and line endings are preserved; unrelated lines are excluded.\nPartial OOM events are retained. See the library documentation for boundary rules.\n";

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        print!("{HELP}");
        return Ok(());
    }
    if args.len() != 2 {
        return Err(HELP.into());
    }
    let mut input = String::new();
    if args[0] == "-" {
        io::stdin().read_to_string(&mut input)?;
    } else {
        input = fs::read_to_string(&args[0])?;
    }
    // Validate the complete input before creating output files.
    let events = linux_oom_parser::parse_events(&input)?;
    let directory = PathBuf::from(&args[1]);
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
