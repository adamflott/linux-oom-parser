#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "fail the test when setup or assertions encounter an unexpected value"
)]

use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(std::path::PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "oom-split-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn splitter_writes_exact_events_and_refuses_existing_directory() {
    let temp = Temp::new();
    let output = temp.0.join("events");
    let input = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/prod-multiple-ooms.log"
    );
    let result = Command::new(env!("CARGO_BIN_EXE_oom-split"))
        .arg(input)
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let events = linux_oom_parser::parse_events(fs::read_to_string(input).unwrap()).unwrap();
    assert_eq!(fs::read_dir(&output).unwrap().count(), 22);
    for (index, event) in events.iter().enumerate() {
        let file = output.join(format!("oom-{:06}.log", index + 1));
        assert_eq!(fs::read_to_string(file).unwrap(), event.to_string());
    }
    let sentinel = output.join("oom-000001.log");
    fs::write(&sentinel, "keep this").unwrap();
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_oom-split"))
            .arg(input)
            .arg(&output)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(fs::read_to_string(sentinel).unwrap(), "keep this");
}

#[test]
fn stdin_help_and_parse_failure() {
    let temp = Temp::new();
    let help = Command::new(env!("CARGO_BIN_EXE_oom-split"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("Usage:"));
    for (index, input) in [
        "sysrq: Manual OOM execution\r\n",
        "Out of memory: Killed process invalid",
    ]
    .iter()
    .enumerate()
    {
        let output = temp.0.join(index.to_string());
        let mut child = Command::new(env!("CARGO_BIN_EXE_oom-split"))
            .arg("-")
            .arg(&output)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert_eq!(result.status.success(), index == 0);
        if index == 0 {
            assert_eq!(
                fs::read_to_string(output.join("oom-000001.log")).unwrap(),
                *input
            );
        } else {
            assert!(!output.exists());
        }
    }
}
