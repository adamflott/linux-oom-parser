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

#[test]
fn group_kills_produce_one_split_file_and_one_analysis_report() {
    let temp = Temp::new();
    let source = "worker invoked oom-killer: gfp_mask=0xcc0(GFP_KERNEL), order=0, oom_score_adj=0\nMemory cgroup out of memory: Killed process 7 (worker) total-vm:100kB, anon-rss:50kB, file-rss:0kB\nTasks in /service are going to be killed due to memory.oom.group set\nMemory cgroup out of memory: Killed process 8 (child) total-vm:100kB, anon-rss:50kB, file-rss:0kB\n";
    let input = temp.0.join("group.log");
    fs::write(&input, source).unwrap();
    let output = temp.0.join("events");
    let split = Command::new(env!("CARGO_BIN_EXE_oom-split"))
        .arg(&input)
        .arg(&output)
        .output()
        .unwrap();
    assert!(split.status.success());
    assert_eq!(fs::read_dir(&output).unwrap().count(), 1);
    assert_eq!(
        fs::read_to_string(output.join("oom-000001.log")).unwrap(),
        source
    );
    let analyzed = Command::new(env!("CARGO_BIN_EXE_oom-analyze"))
        .arg(input)
        .output()
        .unwrap();
    assert!(analyzed.status.success());
    let report = String::from_utf8(analyzed.stdout).unwrap();
    assert!(report.contains("1 OOM event(s) found"));
    assert!(report.contains("worker (PID 7)"));
    assert!(report.contains("child (PID 8)"));
}

fn format_stdin(args: &[&str], input: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_oom-format"))
        .args(args)
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
    child.wait_with_output().unwrap()
}

#[test]
fn format_cli_file_and_default_stdin_match_and_options_override_memory() {
    let temp = Temp::new();
    let input = "sysrq: Manual OOM execution\r\nactive_anon:512\r\n1024 pages RAM\r\n";
    let path = temp.0.join("oom.log");
    fs::write(&path, input).unwrap();
    let file = Command::new(env!("CARGO_BIN_EXE_oom-format"))
        .arg(&path)
        .output()
        .unwrap();
    assert!(file.status.success());
    assert!(file.stderr.is_empty());
    assert!(String::from_utf8_lossy(&file.stdout).contains("active_anon:2.0 MiB (50.00%)\r\n"));
    for args in [&[][..], &["-"][..]] {
        let stdin = format_stdin(args, input);
        assert!(stdin.status.success());
        assert_eq!(stdin.stdout, file.stdout);
        assert!(stdin.stderr.is_empty());
    }
    let overridden = Command::new(env!("CARGO_BIN_EXE_oom-format"))
        .arg(&path)
        .args(["--page-size", "65536", "--total-memory", "67108864"])
        .output()
        .unwrap();
    assert!(overridden.status.success());
    assert!(String::from_utf8_lossy(&overridden.stdout).contains("active_anon:32.0 MiB (50.00%)"));
    // Literal dash-prefixed paths work after --, even if they match an option.
    fs::write(temp.0.join("--help"), input).unwrap();
    let escaped = Command::new(env!("CARGO_BIN_EXE_oom-format"))
        .current_dir(&temp.0)
        .args(["--", "--help"])
        .output()
        .unwrap();
    assert!(escaped.status.success());
    assert_eq!(escaped.stdout, file.stdout);
}

#[test]
fn format_cli_help_passthrough_and_errors_have_clean_stdout() {
    let help = Command::new(env!("CARGO_BIN_EXE_oom-format"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("Usage: oom-format"));
    for input in ["", "unrelated 1024kB\r\nno newline"] {
        let result = format_stdin(&[], input);
        assert!(result.status.success());
        assert_eq!(result.stdout, input.as_bytes());
        assert!(result.stderr.is_empty());
    }
    let malformed = format_stdin(
        &[],
        "sysrq: Manual OOM execution\n1024 pages RAM\nOut of memory: Killed process invalid\n",
    );
    assert!(!malformed.status.success());
    assert!(malformed.stdout.is_empty());
    assert!(String::from_utf8_lossy(&malformed.stderr).contains("line 3"));
    for args in [
        &["--bad"][..],
        &["first", "second"],
        &["--page-size"],
        &["--page-size", "3"],
        &["--page-size", "0"],
        &["--total-memory"],
        &["--total-memory", "0"],
        &["--total-memory", "invalid"],
        &["--total-memory", "18446744073709551616"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_oom-format"))
            .args(args)
            .output()
            .unwrap();
        assert!(!result.status.success(), "{args:?}");
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8_lossy(&result.stderr).starts_with("oom-format:"));
    }
    let temp = Temp::new();
    let missing = Command::new(env!("CARGO_BIN_EXE_oom-format"))
        .arg(temp.0.join("missing.log"))
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(missing.stdout.is_empty());
}
