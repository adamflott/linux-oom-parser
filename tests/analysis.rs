use linux_oom_parser::{OomReason, analyze_event, parse_events};
fn analyze(log: &str) -> linux_oom_parser::OomAnalysis {
    analyze_event(&parse_events(log).unwrap()[0])
}
const INVOKE: &str =
    "worker invoked oom-killer: gfp_mask=0xcc0(GFP_KERNEL), order=0, oom_score_adj=0\n";
fn context(constraint: &str, scope: &str) -> String {
    format!(
        "oom-kill:constraint={constraint},nodemask=(null),cpuset=/,mems_allowed=0,{scope},task_memcg=/service,task=worker,pid=7,uid=0\n"
    )
}
#[test]
fn scope_classification_and_manual_precedence() {
    for (constraint, scope, reason) in [
        ("CONSTRAINT_NONE", "global_oom", OomReason::Global),
        ("CONSTRAINT_CPUSET", "global_oom", OomReason::Cpuset),
        (
            "CONSTRAINT_MEMORY_POLICY",
            "global_oom",
            OomReason::MemoryPolicy,
        ),
        (
            "CONSTRAINT_MEMCG",
            "oom_memcg=/service",
            OomReason::MemoryCgroup,
        ),
    ] {
        let log = format!("{INVOKE}{}", context(constraint, scope));
        let report = analyze(&log);
        assert_eq!(report.reason, reason);
        assert!(report.evidence.iter().any(|e| e.lines == [2]));
        assert!(!report.recommendations.is_empty());
        let manual = analyze(&format!("sysrq: Manual OOM execution\n{log}"));
        assert_eq!(manual.reason, OomReason::Manual);
        assert!(
            !manual
                .recommendations
                .iter()
                .any(|s| s.contains("Increase limits"))
        );
    }
    assert_eq!(
        analyze(&INVOKE.replace("order=0", "order=-1")).reason,
        OomReason::Manual
    );
}
#[test]
fn incomplete_events_do_not_invent_a_cause() {
    assert_eq!(analyze(INVOKE).reason, OomReason::AllocationFailure);
    let report = analyze("oom_reaper: reaped process 7 (worker), now anon-rss:0kB, file-rss:0kB\n");
    assert_eq!(report.reason, OomReason::Unknown);
    assert!(report.limitations.iter().any(|s| s.contains("No kill")));
    assert!(
        report
            .to_string()
            .contains("Possible causes (not confirmed)")
    );
}
#[test]
fn swap_and_zone_evidence_is_conditional() {
    for (swap, expected) in [
        ("Free swap = 0kB\nTotal swap = 0kB\n", "No swap capacity"),
        ("Free swap = 0kB\nTotal swap = 1024kB\n", "Exhausted swap"),
    ] {
        let report = analyze(&format!("{INVOKE}{swap}"));
        assert!(report.possible_causes.iter().any(|s| s.contains(expected)));
    }
    let report = analyze(&format!("{INVOKE}Free swap = 512kB\nTotal swap = 1024kB\n"));
    assert!(!report.possible_causes.iter().any(|s| s.contains("swap")));
    let report = analyze(&format!("{INVOKE}Node 0 Normal free:1kB min:2kB\n"));
    assert!(
        report
            .evidence
            .iter()
            .any(|e| e.description.contains("below the printed minimum"))
    );
}
#[test]
fn fixtures_produce_evidence_without_leak_diagnoses() {
    let report = analyze(include_str!("../examples/nixos-linux-6.18.log"));
    assert_eq!(report.reason, OomReason::Manual);
    assert!(
        report
            .explanation
            .contains("does not establish memory exhaustion")
    );
    for log in [
        include_str!("../examples/prod-multiple-ooms.log"),
        include_str!("../examples/prod-6.12.log"),
    ] {
        for event in parse_events(log).unwrap() {
            let report = analyze_event(&event);
            assert_eq!(report.reason, OomReason::Global);
            assert!(
                report
                    .evidence
                    .iter()
                    .any(|e| e.description.starts_with("Killed PID"))
            );
            for evidence in report.evidence {
                assert!(
                    evidence
                        .lines
                        .iter()
                        .all(|n| event.records.iter().any(|r| r.line_number == *n))
                );
            }
        }
    }
}
#[test]
fn cli_file_stdin_empty_and_malformed() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let binary = env!("CARGO_BIN_EXE_oom-analyze");
    let output = Command::new(binary)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/nixos-linux-6.18.log"
        ))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("manual SysRq"));
    assert!(
        Command::new(binary)
            .arg("--help")
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(!Command::new(binary).output().unwrap().status.success());
    for (input, success, expected) in [
        ("", true, "0 OOM event(s)"),
        (INVOKE, true, "1 OOM event(s)"),
        ("Out of memory: Killed process invalid", false, ""),
    ] {
        let mut child = Command::new(binary)
            .arg("-")
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
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.success(), success);
        if success {
            assert!(String::from_utf8_lossy(&output.stdout).contains(expected));
        } else {
            assert!(output.stdout.is_empty());
            assert!(!output.stderr.is_empty());
        }
    }
}

#[test]
fn page_counts_include_human_sizes_and_exact_bytes() {
    use linux_oom_parser::{AnalysisOptions, OomMessage, analyze_event_with_options};
    let mut event = parse_events(include_str!("../examples/nixos-linux-6.18.log"))
        .unwrap()
        .remove(0);
    event
        .records
        .retain(|r| matches!(r.message, OomMessage::Task(_)));
    event.records.truncate(1);
    if let OomMessage::Task(task) = &mut event.records[0].message {
        task.rss_pages = 256;
    }
    let default = analyze_event(&event).to_string();
    assert!(
        default.contains("256 pages (1.0 MiB (1048576 bytes))"),
        "{default}"
    );
    let options = AnalysisOptions {
        page_size: std::num::NonZeroU64::new(65536).unwrap(),
    };
    let custom = analyze_event_with_options(&event, options).to_string();
    assert!(custom.contains("256 pages (16.0 MiB (16777216 bytes))"));
    assert!(custom.contains("base page size of 64.0 KiB (65536 bytes)"));
    if let OomMessage::Task(task) = &mut event.records[0].message {
        task.rss_pages = u64::MAX;
    }
    let large = analyze_event_with_options(&event, options).to_string();
    assert!(large.contains(&format!("{} bytes", u128::from(u64::MAX) * 65536)));
}

#[test]
fn cli_validates_page_size_and_formats_rss() {
    use std::process::Command;
    let binary = env!("CARGO_BIN_EXE_oom-analyze");
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/nixos-linux-6.18.log");
    for size in ["0", "invalid", "-1", "18446744073709551616"] {
        assert!(
            !Command::new(binary)
                .args(["--page-size", size, fixture])
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    let output = Command::new(binary)
        .args(["--verbose", "--page-size", "65536", fixture])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("64.0 KiB (65536 bytes)"));
    assert!(text.contains("anonymous RSS 0 B (0 bytes)"), "{text}");
    assert!(!text.contains("RSS Some("));
}

#[test]
fn readable_report_preserves_evidence_and_verbose_details() {
    use linux_oom_parser::{AnalysisOptions, format_event_analysis};
    let events = parse_events(include_str!("../examples/prod-multiple-ooms.log")).unwrap();
    let event = &events[21];
    let report = format_event_analysis(event, AnalysisOptions::default(), false);
    for expected in [
        "System-wide memory pressure",
        "The kernel killed bigapp (PID 15217)",
        "one memory page (4.0 KiB)",
        "Swap was full: 4.0 GiB",
        "1.8 MiB below",
        "Largest processes",
        "bigapp",
        "swans",
        "edgedata",
        "[lines 20113–20114]",
        "What to do next",
        "3. Review swap",
    ] {
        assert!(report.contains(expected), "missing {expected}: {report}");
    }
    for unwanted in [
        "Some(",
        "NodeRange",
        "FlagComp",
        "5454278656",
        "1331611 pages",
        "4. Collect",
    ] {
        assert!(!report.contains(unwanted), "unexpected {unwanted}");
    }
    let verbose = format_event_analysis(event, AnalysisOptions::default(), true);
    for expected in [
        "5454278656 bytes",
        "1331611 pages",
        "GFP_HIGHUSER_MOVABLE | __GFP_COMP",
        "Constraint: none; cpuset: default; allowed nodes: 0",
        "Technical details",
    ] {
        assert!(verbose.contains(expected), "missing {expected}: {verbose}");
    }
    assert!(!verbose.contains("Some("));
}

#[test]
fn report_handles_manual_partial_and_cli_options() {
    use linux_oom_parser::{AnalysisOptions, format_event_analysis};
    let options = AnalysisOptions::default();
    let manual = parse_events(include_str!("../examples/nixos-linux-6.18.log")).unwrap();
    let output = format_event_analysis(&manual[0], options, false);
    assert!(output.starts_with("Manual OOM request"));
    assert!(!output.contains("requested one memory page"));
    assert!(!output.contains("More swap"));
    let partial = parse_events(INVOKE).unwrap();
    assert!(format_event_analysis(&partial[0], options, false).contains("No kill record"));
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/nixos-linux-6.18.log");
    for args in [
        vec![fixture, "--verbose", "--page-size", "65536"],
        vec!["--page-size", "65536", "--verbose", fixture],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_oom-analyze"))
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("Technical details"));
    }
    for args in [
        vec!["--page-size"],
        vec!["--unknown"],
        vec![fixture, fixture],
    ] {
        assert!(
            !std::process::Command::new(env!("CARGO_BIN_EXE_oom-analyze"))
                .args(args)
                .output()
                .unwrap()
                .status
                .success()
        );
    }
}
