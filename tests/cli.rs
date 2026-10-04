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
