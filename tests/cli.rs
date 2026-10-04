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
fn all_clis_generate_help_and_reject_invalid_arguments_before_io() {
    for (name, binary, positional) in [
        (
            "oom-analyze",
            env!("CARGO_BIN_EXE_oom-analyze"),
            &["input"][..],
        ),
        (
            "oom-compare",
            env!("CARGO_BIN_EXE_oom-compare"),
            &["before", "after"][..],
        ),
        (
            "oom-format",
            env!("CARGO_BIN_EXE_oom-format"),
            &["input"][..],
        ),
        (
            "oom-split",
            env!("CARGO_BIN_EXE_oom-split"),
            &["input", "output"][..],
        ),
    ] {
        for flag in ["-h", "--help"] {
            for args in [&[][..], positional] {
                let output = Command::new(binary).args(args).arg(flag).output().unwrap();
                assert!(output.status.success(), "{name} {args:?} {flag}");
                assert!(
                    String::from_utf8_lossy(&output.stdout).contains(&format!("Usage: {name}"))
                );
                assert!(output.stderr.is_empty());
            }
        }
        for extra in ["--unknown", "extra"] {
            let output = Command::new(binary)
                .args(positional)
                .arg(extra)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(2), "{name} {extra}");
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).starts_with("error:"));
        }
        if name != "oom-format" {
            let output = Command::new(binary).output().unwrap();
            assert_eq!(output.status.code(), Some(2), "{name}");
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains("required arguments"));
        }
    }
}

#[test]
fn all_clis_accept_dash_prefixed_paths() {
    check_cli_paths(std::ffi::OsStr::new("--help"));
}

// macOS filesystems reject invalid UTF-8 filenames before the CLI can read them.
#[cfg(target_os = "linux")]
#[test]
fn all_clis_accept_non_utf8_paths() {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

    check_cli_paths(OsStr::from_bytes(b"oom-\xff.log"));
}

fn check_cli_paths(input_filename: &std::ffi::OsStr) {
    let temp = Temp::new();
    let input = "sysrq: Manual OOM execution\nactive_anon:16\n";
    let input_path = temp.0.join(input_filename);
    let output_directory = temp.0.join("events");
    fs::write(&input_path, input).unwrap();
    for (binary, second_path) in [
        (env!("CARGO_BIN_EXE_oom-analyze"), None),
        (env!("CARGO_BIN_EXE_oom-format"), None),
        (env!("CARGO_BIN_EXE_oom-compare"), Some(&input_path)),
        (env!("CARGO_BIN_EXE_oom-split"), Some(&output_directory)),
    ] {
        let mut command = Command::new(binary);
        command.current_dir(&temp.0).arg("--").arg(input_filename);
        if let Some(path) = second_path {
            command.arg(path);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{binary}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(
        fs::read_to_string(output_directory.join("oom-000001.log")).unwrap(),
        input
    );
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
        assert_eq!(result.status.code(), Some(2), "{args:?}");
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8_lossy(&result.stderr).starts_with("error:"));
    }
    let temp = Temp::new();
    let missing = Command::new(env!("CARGO_BIN_EXE_oom-format"))
        .arg(temp.0.join("missing.log"))
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(missing.stdout.is_empty());
}

fn compare_stdin(args: &[&std::ffi::OsStr], input: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_oom-compare"))
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
fn compare_cli_reports_to_stdout_and_supports_stdin_on_either_side() {
    let temp = Temp::new();
    let before = "sysrq: Manual OOM execution\nactive_anon:16\n";
    let after = "sysrq: Manual OOM execution\nactive_anon:32\n";
    let before_path = temp.0.join("before.log");
    let after_path = temp.0.join("after.log");
    fs::write(&before_path, before).unwrap();
    fs::write(&after_path, after).unwrap();
    let files = Command::new(env!("CARGO_BIN_EXE_oom-compare"))
        .arg(&before_path)
        .arg(&after_path)
        .output()
        .unwrap();
    let stdin_before = compare_stdin(&[std::ffi::OsStr::new("-"), after_path.as_os_str()], before);
    let stdin_after = compare_stdin(&[before_path.as_os_str(), std::ffi::OsStr::new("-")], after);
    for output in [files, stdin_before, stdin_after] {
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("OOM memory comparison (after - before)"));
        assert!(stdout.contains("+65536 bytes"));
        assert!(stdout.contains("+100.0%"));
    }
}

#[test]
fn compare_cli_page_overrides_and_dash_prefixed_paths() {
    let temp = Temp::new();
    let log = "sysrq: Manual OOM execution\nactive_anon:16\n";
    fs::write(temp.0.join("--help"), log).unwrap();
    fs::write(temp.0.join("after"), log).unwrap();
    let escaped = Command::new(env!("CARGO_BIN_EXE_oom-compare"))
        .current_dir(&temp.0)
        .args(["--", "--help", "after"])
        .output()
        .unwrap();
    assert!(escaped.status.success());
    assert!(
        String::from_utf8_lossy(&escaped.stdout)
            .contains("No differences in captured memory measurements.")
    );
    for args in [
        ["--page-size", "4096", "--after-page-size", "65536"],
        ["--after-page-size", "65536", "--page-size", "4096"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_oom-compare"))
            .current_dir(&temp.0)
            .args(args)
            .args(["--", "--help", "after"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let report = String::from_utf8_lossy(&output.stdout);
        assert!(report.contains("before 4096 bytes (explicit override)"));
        assert!(report.contains("after 65536 bytes (explicit override)"));
        assert!(report.contains("+983040 bytes"));
    }
    let common = Command::new(env!("CARGO_BIN_EXE_oom-compare"))
        .current_dir(&temp.0)
        .args(["--page-size", "65536", "--", "--help", "after"])
        .output()
        .unwrap();
    assert!(common.status.success());
    let report = String::from_utf8_lossy(&common.stdout);
    assert!(
        report.contains(
            "before 65536 bytes (explicit override); after 65536 bytes (explicit override)"
        )
    );
}

#[test]
fn compare_cli_pairs_events_in_order_and_reports_unmatched_events_on_either_side() {
    let temp = Temp::new();
    let one = temp.0.join("one.log");
    let three = temp.0.join("three.log");
    fs::write(&one, "sysrq: Manual OOM execution\nactive_anon:1\n").unwrap();
    fs::write(&three, "sysrq: Manual OOM execution\nactive_anon:2\nsysrq: Manual OOM execution\nactive_anon:1000\nsysrq: Manual OOM execution\nactive_anon:2000\n").unwrap();
    for (before, after, side, sign) in [(&one, &three, "after", '+'), (&three, &one, "before", '-')]
    {
        let output = Command::new(env!("CARGO_BIN_EXE_oom-compare"))
            .arg(before)
            .arg(after)
            .output()
            .unwrap();
        assert!(output.status.success());
        let report = String::from_utf8_lossy(&output.stdout);
        assert_eq!(report.matches("compared with event").count(), 1);
        assert!(report.contains(&format!("{sign}4096 bytes")));
        assert!(report.contains(&format!("Unmatched {side} event 2 (source lines 3,4)")));
        assert!(report.contains(&format!("Unmatched {side} event 3 (source lines 5,6)")));
    }
}

#[test]
fn compare_cli_help_and_failures_leave_stdout_clean() {
    for flag in ["--help", "-h"] {
        let output = Command::new(env!("CARGO_BIN_EXE_oom-compare"))
            .arg(flag)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("Usage: oom-compare"));
        assert!(output.stderr.is_empty());
    }
    for args in [
        &[][..],
        &["one"][..],
        &["one", "two", "three"][..],
        &["--unknown"],
        &["--page-size"],
        &["--before-page-size", "0", "one", "two"],
        &["--after-page-size", "3000", "one", "two"],
        &["--page-size", "bad", "one", "two"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_oom-compare"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).starts_with("error:"));
    }
    let both_stdin = Command::new(env!("CARGO_BIN_EXE_oom-compare"))
        .args(["-", "-"])
        .output()
        .unwrap();
    assert!(!both_stdin.status.success());
    assert!(both_stdin.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&both_stdin.stderr)
            .contains("oom-compare: stdin (-) can be used for only one input")
    );
    let temp = Temp::new();
    let before = temp.0.join("before.log");
    let after = temp.0.join("after.log");
    fs::write(&before, "sysrq: Manual OOM execution\nactive_anon:1\n").unwrap();
    for log in [
        "",
        "unrelated kernel log",
        "sysrq: Manual OOM execution\nOut of memory: Killed process invalid\n",
    ] {
        fs::write(&after, log).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_oom-compare"))
            .arg(&before)
            .arg(&after)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("after input"));
    }
    let missing = Command::new(env!("CARGO_BIN_EXE_oom-compare"))
        .arg(temp.0.join("missing.log"))
        .arg(after)
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(missing.stdout.is_empty());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("before input"));
}
