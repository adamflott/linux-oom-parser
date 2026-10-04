#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "fail the test when setup or assertions encounter an unexpected value"
)]

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

#[test]
fn cgroup_budgets_keep_the_dump_and_distinguish_ancestor_limits() {
    use linux_oom_parser::{AnalysisOptions, CgroupStatValue, OomMessage, format_event_analysis};
    let log = format!(
        "{INVOKE}memory: usage 1024kB, limit 1024kB, failcnt 20\nswap: usage 0kB, limit 0kB, failcnt 0\nMemory cgroup stats for /parent:\nanon 1048576\n pgscan 30\n vendor_metric 42\nTasks state (memory values in pages):\n[ pid ] uid tgid total_vm rss pgtables_bytes swapents oom_score_adj name\n[ 7] 0 7 256 256 4096 0 0 worker\n{}Memory cgroup out of memory: Killed process 7 (worker) total-vm:1024kB, anon-rss:1024kB, file-rss:0kB\n",
        context("CONSTRAINT_MEMCG", "oom_memcg=/parent")
    );
    let events = parse_events(&log).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].to_string(), log);
    let report = analyze_event(&events[0]);
    assert_eq!(report.reason, OomReason::MemoryCgroup);
    let text = format_event_analysis(&events[0], AnalysisOptions::default(), false)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(text.contains("at or above the printed limit"));
    assert!(text.contains("swap allowance is zero"));
    assert!(text.contains("Limiting OOM cgroup"));
    assert!(text.contains("/parent"));
    assert!(text.contains("victim membership"));
    assert!(text.contains("unit unknown"));
    let stats: Vec<_> = events[0]
        .records
        .iter()
        .filter_map(|r| match &r.message {
            OomMessage::CgroupStat(s) => Some(&s.value),
            _ => None,
        })
        .collect();
    assert!(matches!(stats[0], CgroupStatValue::Bytes(_)));
    assert_eq!(*stats[1], CgroupStatValue::Count(30));
    assert_eq!(*stats[2], CgroupStatValue::Unknown(42));
    assert!(!report.limitations.iter().any(|s| s.contains("No kill")));
    assert!(
        parse_events("anon 1048576\npgscan 30\n")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn v1_cgroup_limits_and_invalid_budget_values() {
    let report = analyze(&format!(
        "{INVOKE}memory+swap: usage 512kB, limit 1024kB, failcnt 2\nkmem: usage 128kB, limit 1024kB, failcnt 0\n"
    ));
    assert!(report.to_string().contains("memory + swap"));
    assert!(report.to_string().contains("kernel memory"));
    assert!(report.to_string().contains("below the printed limit"));
    assert!(
        parse_events(format!(
            "{INVOKE}memory: usage 18446744073709551615kB, limit 0kB, failcnt 0\n"
        ))
        .is_err()
    );
    assert!(
        parse_events(format!(
            "{INVOKE}Memory cgroup stats for /parent:\nanon invalid\n"
        ))
        .is_err()
    );
}

#[test]
fn buddy_page_size_inference_and_explicit_conflicts() {
    use linux_oom_parser::{
        AnalysisOptions, PageSizeInference, analyze_event_with_options, infer_page_size,
    };
    let log = format!(
        "{INVOKE}Node 0 Normal: 1*64kB 0*128kB = 64kB\n[ pid ] uid tgid total_vm rss pgtables_bytes swapents oom_score_adj name\n[ 7] 0 7 256 256 4096 0 0 worker\n"
    );
    let event = parse_events(&log).unwrap().remove(0);
    assert!(
        matches!(infer_page_size(&event), Some(PageSizeInference::Consistent { page_size, .. }) if page_size.get() == 65536)
    );
    assert!(analyze_event(&event).to_string().contains("16777216 bytes"));
    let overridden = analyze_event_with_options(&event, AnalysisOptions::default()).to_string();
    assert!(overridden.contains("CONFLICTS"));
    assert!(overridden.contains("1048576 bytes"));
    for buddy in [
        "Node 1 Normal: 1*4kB 0*8kB = 4kB",
        "Node 1 Normal: 1*64kB 0*256kB = 64kB",
    ] {
        let event = parse_events(format!("{log}{buddy}\n")).unwrap().remove(0);
        assert!(matches!(
            infer_page_size(&event),
            Some(PageSizeInference::Inconsistent { .. })
        ));
        assert!(
            analyze_event(&event)
                .to_string()
                .contains("no base page size was inferred")
        );
    }
    assert_eq!(infer_page_size(&parse_events(INVOKE).unwrap()[0]), None);
}

#[test]
fn buddy_findings_show_shortages_availability_and_node_restrictions() {
    let invocation = INVOKE.replace("order=0", "order=2");
    let ctx = context("CONSTRAINT_MEMORY_POLICY", "global_oom");
    let ctx = ctx.replace("mems_allowed=0", "mems_allowed=1");
    let report = analyze(&format!(
        "{invocation}{ctx}Node 0 Normal: 0*4kB 0*8kB 2*16kB 0*32kB = 32kB\nNode 1 Normal: 3*4kB 1*8kB 0*16kB 0*32kB = 20kB\n"
    ));
    let findings: Vec<_> = report
        .evidence
        .iter()
        .filter(|e| {
            e.kind == linux_oom_parser::EvidenceKind::Allocation
                && e.description.starts_with("Node")
        })
        .collect();
    assert_eq!(findings.len(), 2);
    assert!(
        findings[0]
            .description
            .contains("no printed free block is large enough")
    );
    assert!(findings[0].description.contains("Node 1"));
    assert!(findings[0].lines.contains(&4));
    assert!(!findings.iter().any(|e| e.description.contains("Node 0")));
    assert!(
        findings[1]
            .description
            .contains("fragmentation or depletion")
    );
    let report = analyze(&format!(
        "{invocation}Node 0 Normal: 0*4kB 0*8kB 0*16kB 1*32kB = 32kB\n"
    ));
    assert!(
        report
            .to_string()
            .contains("does not guarantee allocation success")
    );
    assert!(!report.to_string().contains("has no printed free blocks"));
    let manual = analyze(&format!(
        "sysrq: Manual OOM execution\n{invocation}Node 0 Normal: 0*4kB 0*8kB = 0kB\n"
    ));
    assert!(
        !manual
            .evidence
            .iter()
            .any(|e| e.kind == linux_oom_parser::EvidenceKind::Allocation)
    );
    let huge_order = analyze(&format!(
        "{}Node 0 Normal: 1*4kB = 4kB\n",
        INVOKE.replace("order=0", "order=128")
    ));
    assert!(
        huge_order
            .limitations
            .iter()
            .any(|s| s.contains("converted safely"))
    );
}

#[test]
fn low_watermarks_and_adjacent_reserves_are_shared_report_findings() {
    use linux_oom_parser::{AnalysisOptions, format_event_analysis};
    let log = format!(
        "{INVOKE}Node 0 Normal free:8kB min:4kB low:12kB high:16kB reserved_highatomic:2kB free_cma:1kB\nlowmem_reserve[]: 0 10 20\nNode 1 Normal free:24kB min:4kB low:12kB high:16kB\n"
    );
    let event = parse_events(log).unwrap().remove(0);
    let analysis = analyze_event(&event);
    let finding = analysis
        .evidence
        .iter()
        .find(|e| e.description.contains("lowmem_reserve[]"))
        .unwrap();
    assert_eq!(finding.lines, [2, 3]);
    assert!(
        finding
            .description
            .contains("below the printed low watermark")
    );
    assert!(
        finding
            .description
            .contains("cannot prove the exact failure reason")
    );
    assert!(finding.description.contains("high-atomic reserve"));
    let text = format_event_analysis(&event, AnalysisOptions::default(), false)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(text.contains("lowmem_reserve[]"));
    assert!(text.contains("before changing VM tuning"));
    let second = analysis
        .evidence
        .iter()
        .find(|e| e.description.contains("Node 1 zone Normal: free"))
        .unwrap();
    assert!(!second.description.contains("lowmem_reserve[]"));
    assert!(
        !second
            .description
            .contains("below the printed low watermark")
    );
    let gap = parse_events(format!("{INVOKE}Node 0 Normal free:8kB min:4kB low:12kB\nactive_anon:1\nlowmem_reserve[]: 0 10 20\n")).unwrap().remove(0);
    assert!(
        !analyze_event(&gap)
            .evidence
            .iter()
            .any(|e| e.description.contains("lowmem_reserve[]"))
    );
}
