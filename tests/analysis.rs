#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "fail the test when setup or assertions encounter an unexpected value"
)]

use linux_oom_parser::{FindingCode, FindingData, OomReason, analyze_event, parse_events};
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
        (
            "Free swap = 0kB\nTotal swap = 0kB\n",
            FindingCode::SwapUnavailable,
        ),
        (
            "Free swap = 0kB\nTotal swap = 1024kB\n",
            FindingCode::SwapExhausted,
        ),
    ] {
        let report = analyze(&format!("{INVOKE}{swap}"));
        assert!(
            report
                .structured_findings
                .iter()
                .any(|finding| finding.code() == expected)
        );
    }
    let report = analyze(&format!("{INVOKE}Free swap = 512kB\nTotal swap = 1024kB\n"));
    assert!(!report.possible_causes.iter().any(|s| s.contains("swap")));
    let report = analyze(&format!("{INVOKE}Node 0 Normal free:1kB min:2kB\n"));
    assert!(
        report
            .structured_findings
            .iter()
            .any(|e| e.code() == FindingCode::ZoneBelowMinimum)
    );
}
#[test]
fn structured_swap_covers_capacity_missing_fields_and_manual_snapshots() {
    use linux_oom_parser::ByteSize;
    for manual in [false, true] {
        for (swap, code, total_kib, free_kib, lines) in [
            (
                "Free swap = 512kB\nTotal swap = 1024kB\n",
                FindingCode::SwapCapacity,
                1024,
                Some(512),
                vec![3, 2],
            ),
            (
                "Free swap = 1024kB\nTotal swap = 1024kB\n",
                FindingCode::SwapCapacity,
                1024,
                Some(1024),
                vec![3, 2],
            ),
            (
                "Total swap = 1024kB\n",
                FindingCode::SwapCapacity,
                1024,
                None,
                vec![2],
            ),
            (
                "Free swap = 0kB\nTotal swap = 1024kB\n",
                FindingCode::SwapExhausted,
                1024,
                Some(0),
                vec![3, 2],
            ),
            (
                "Free swap = 0kB\nTotal swap = 0kB\n",
                FindingCode::SwapUnavailable,
                0,
                Some(0),
                vec![3, 2],
            ),
            (
                "Total swap = 0kB\n",
                FindingCode::SwapUnavailable,
                0,
                None,
                vec![2],
            ),
        ] {
            let invocation = if manual {
                INVOKE.replace("order=0", "order=-1")
            } else {
                INVOKE.into()
            };
            let report = analyze(&format!("{invocation}{swap}"));
            let findings: Vec<_> = report
                .structured_findings
                .iter()
                .filter(|f| matches!(f.data, FindingData::Swap { .. }))
                .collect();
            assert_eq!(findings.len(), 1, "manual={manual}, {swap}");
            let finding = findings[0];
            assert_eq!(finding.code(), code);
            assert_eq!(finding.lines, lines);
            assert_eq!(
                finding.data,
                FindingData::Swap {
                    total: ByteSize::kib(total_kib),
                    free: free_kib.map(ByteSize::kib)
                }
            );
            assert!(
                report
                    .evidence
                    .iter()
                    .any(|e| e.lines == lines && e.description.contains("Printed swap capacity"))
            );
            if manual {
                assert_eq!(report.reason, OomReason::Manual);
            }
            if manual || code == FindingCode::SwapCapacity {
                assert!(
                    !report
                        .possible_causes
                        .iter()
                        .chain(&report.recommendations)
                        .any(|s| s.contains("swap"))
                );
            }
        }
    }
    for swap in ["", "Free swap = 0kB\n", "Free swap = 512kB\n"] {
        let report = analyze(&format!("{INVOKE}{swap}"));
        assert!(
            !report
                .structured_findings
                .iter()
                .any(|f| matches!(f.data, FindingData::Swap { .. }))
        );
        assert!(!report.possible_causes.iter().any(|s| s.contains("swap")));
    }
    for swap in [
        "Free swap = 1024kB\nTotal swap = 512kB\n",
        "Free swap = 1kB\nTotal swap = 0kB\n",
    ] {
        let report = analyze(&format!("{INVOKE}{swap}"));
        assert!(
            !report
                .structured_findings
                .iter()
                .any(|f| matches!(f.data, FindingData::Swap { .. }))
        );
        assert!(
            report
                .limitations
                .iter()
                .any(|s| s.contains("free swap exceeds total swap"))
        );
        assert!(
            report
                .evidence
                .iter()
                .any(|e| e.lines == [3, 2] && e.description.contains("these totals disagree"))
        );
        assert!(
            !report
                .possible_causes
                .iter()
                .chain(&report.recommendations)
                .any(|s| s.contains("swap"))
        );
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
        page_size: linux_oom_parser::PageSize::new(65536).unwrap(),
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
    for size in [
        "0",
        "invalid",
        "-1",
        "512",
        "4095",
        "6144",
        "18446744073709551616",
    ] {
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
        vec![
            fixture,
            "--page-size=4096",
            "--page-size=65536",
            "--verbose",
            "--verbose",
        ],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_oom-analyze"))
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("Technical details"));
        assert!(text.contains("64.0 KiB (65536 bytes)"));
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
fn buddy_totals_must_match_before_shortage_or_availability_findings() {
    use linux_oom_parser::{PageSizeInference, infer_page_size};
    let invocation = INVOKE.replace("order=0", "order=1");
    for (buddy, expected) in [
        ("0*4kB 0*8kB = 1024kB", None),
        ("0*4kB 1*8kB = 0kB", None),
        ("1*4kB 1*8kB = 8kB", None),
        ("18446744073709551615*4kB 0*8kB = 0kB", None),
        ("0*4kB 0*8kB = 0kB", Some(FindingCode::BuddyShortage)),
        ("0*4kB 1*8kB = 8kB", Some(FindingCode::BuddyAvailability)),
    ] {
        let log = format!("{invocation}Node 0 Normal: {buddy}\n");
        let event = parse_events(&log).unwrap().remove(0);
        assert_eq!(event.to_string(), log);
        assert!(matches!(
            infer_page_size(&event),
            Some(PageSizeInference::Consistent { .. })
        ));
        let report = analyze_event(&event);
        let findings: Vec<_> = report
            .structured_findings
            .iter()
            .filter(|f| matches!(f.data, FindingData::Buddy { .. }))
            .collect();
        if let Some(expected) = expected {
            assert_eq!(findings.len(), 1, "{buddy}");
            assert_eq!(findings[0].code(), expected);
            assert!(
                !report
                    .limitations
                    .iter()
                    .any(|s| s.contains("totals") || s.contains("bucket sum"))
            );
        } else {
            assert!(findings.is_empty(), "{buddy}");
            assert!(
                report
                    .limitations
                    .iter()
                    .any(|s| s.contains("bucket sum disagrees"))
            );
            let raw = report
                .evidence
                .iter()
                .find(|e| e.description.contains("printed buddy buckets"))
                .unwrap();
            assert_eq!(raw.lines, [2]);
            assert!(raw.description.contains("Bucket sum:"));
            assert!(raw.description.contains("printed total:"));
            assert!(
                !report
                    .evidence
                    .iter()
                    .any(|e| e.description.contains("fragmentation or depletion")
                        || e.description.contains("blocks at this size or larger"))
            );
        }
    }

    let report = analyze(&format!(
        "{invocation}Node 0 Normal: 0*4kB 1*8kB = 0kB\nNode 1 Normal: 0*4kB 1*8kB = 8kB\n"
    ));
    let findings: Vec<_> = report
        .structured_findings
        .iter()
        .filter(|f| matches!(f.data, FindingData::Buddy { .. }))
        .collect();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code(), FindingCode::BuddyAvailability);
    assert_eq!(findings[0].lines, [1, 3]);
    assert!(
        !report
            .limitations
            .iter()
            .any(|s| s.contains("No buddy distribution"))
    );
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

#[test]
fn memory_composition_preserves_units_and_does_not_sum_overlapping_categories() {
    use linux_oom_parser::{AnalysisOptions, analyze_event_with_options};
    let log = format!(
        "{INVOKE}Mem-Info:\nactive_anon:10 inactive_anon:2 shmem:5 slab_unreclaimable:3 unevictable:1 pagetables:2\nNode 0 active_anon:40kB\n100 pages RAM\n10 pages HighMem/MovableOnly\n2 pages reserved\n4 pages in swap cache\nSwap cache stats: add 20, delete 16, find 10/12\nFree swap = 40kB\nTotal swap = 100kB\nOut of memory: Killed process 7 (worker) total-vm:1024kB, anon-rss:20kB, file-rss:4kB, shmem-rss:4kB\n"
    );
    let event = parse_events(&log).unwrap().remove(0);
    assert_eq!(event.to_string(), log);
    let report = analyze_event(&event).to_string();
    assert!(report.contains("10 pages (40.0 KiB"));
    assert!(report.contains("printed RAM capacity: 400.0 KiB"));
    assert!(report.contains("Total victim RSS: 28.0 KiB"));
    assert!(report.contains("7.0% of printed RAM capacity"));
    assert!(report.contains("Occupied swap: 60.0 KiB"));
    assert!(!report.contains("Node 0 memory:"));
    assert!(report.contains("Categories may overlap"));
    let options = AnalysisOptions {
        page_size: linux_oom_parser::PageSize::new(65536).unwrap(),
    };
    assert!(
        analyze_event_with_options(&event, options)
            .to_string()
            .contains("10 pages (640.0 KiB")
    );
    let partial = analyze(&format!("{INVOKE}Out of memory: Killed process 7 (worker) total-vm:100kB, anon-rss:20kB, file-rss:4kB\n")).to_string();
    assert!(partial.contains("partial; missing components are unknown"));
    assert!(!partial.contains("Total victim RSS:"));
    let invalid = analyze(&format!("{INVOKE}Free swap = 100kB\nTotal swap = 40kB\n"));
    assert!(
        invalid
            .limitations
            .iter()
            .any(|s| s.contains("exceeds total swap"))
    );
}

#[test]
fn cli_infers_per_event_page_size_and_exposes_override_conflicts() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let log = format!(
        "{INVOKE}Node 0 Normal: 1*64kB 0*128kB = 64kB\n100 pages RAM\nOut of memory: Killed process 7 (worker) total-vm:100kB, anon-rss:20kB, file-rss:4kB\n{INVOKE}Node 0 Normal: 1*4kB 0*8kB = 4kB\n100 pages RAM\n"
    );
    for (args, conflict) in [(vec!["-"], false), (vec!["--page-size", "4096", "-"], true)] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_oom-analyze"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(log.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout)
            .unwrap()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains("2 OOM event(s)"));
        assert_eq!(text.contains("CONFLICTS"), conflict);
        if conflict {
            assert!(text.contains("Buddy page-size evidence conflicts"));
            assert!(!text.contains("printed RAM capacity: 6.2 MiB"));
        } else {
            assert!(text.contains("printed RAM capacity: 6.2 MiB"));
            assert!(text.contains("printed RAM capacity: 400.0 KiB"));
        }
    }
}

#[test]
fn report_shares_missing_data_limits_and_cgroup_partial_events() {
    use linux_oom_parser::{AnalysisOptions, format_event_analysis};
    let log = "memory: usage 1024kB, limit 1024kB, failcnt 1\nMemory cgroup stats for /parent:\nanon 1048576\nMemory cgroup out of memory: Killed process 7 (worker) total-vm:1024kB, anon-rss:1024kB, file-rss:0kB\n";
    let events = parse_events(log).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].to_string(), log);
    assert_eq!(analyze_event(&events[0]).reason, OomReason::MemoryCgroup);
    let event = parse_events(INVOKE.replace("(GFP_KERNEL)", ""))
        .unwrap()
        .remove(0);
    let text = format_event_analysis(&event, AnalysisOptions::default(), false)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(text.contains("Numeric GFP mask was not decoded"));
    assert!(text.contains("contiguous-block availability is unknown"));
    assert!(text.contains("No kill record was captured"));
}

#[test]
fn explicit_dma_flags_exclude_higher_zones_from_allocation_findings() {
    let log = format!(
        "{}Node 0 DMA: 0*4kB 0*8kB = 0kB\nNode 0 Normal: 0*4kB 1*8kB = 8kB\nNode 0 DMA free:0kB min:4kB low:8kB\nNode 0 Normal free:16kB min:4kB low:8kB\n",
        INVOKE
            .replace("GFP_KERNEL", "GFP_DMA")
            .replace("order=0", "order=1")
    );
    let report = analyze(&log);
    let findings: Vec<_> = report
        .evidence
        .iter()
        .filter(|e| {
            e.kind == linux_oom_parser::EvidenceKind::Allocation
                && e.description.starts_with("Node")
        })
        .collect();
    assert!(findings.iter().any(|e| e.description.contains("zone DMA")));
    assert!(
        !findings
            .iter()
            .any(|e| e.description.contains("zone Normal"))
    );
    let unknown = analyze(&log.replace("GFP_DMA", "GFP_VENDOR"));
    assert!(
        unknown
            .evidence
            .iter()
            .any(|e| e.kind == linux_oom_parser::EvidenceKind::Allocation
                && e.description.contains("zone Normal buddy"))
    );
}

#[test]
fn minimum_pressure_respects_node_zone_and_cgroup_constraints() {
    for log in [
        format!(
            "{INVOKE}{}Node 1 Normal free:1kB min:2kB low:3kB\n",
            context("CONSTRAINT_CPUSET", "global_oom")
        ),
        format!(
            "{}Node 0 Normal free:1kB min:2kB low:3kB\n",
            INVOKE.replace("GFP_KERNEL", "GFP_DMA")
        ),
    ] {
        let report = analyze(&log);
        assert!(
            !report
                .evidence
                .iter()
                .any(|e| e.description.contains("below the printed minimum"))
        );
        assert!(
            !report
                .possible_causes
                .iter()
                .any(|s| s.contains("Local zone pressure"))
        );
    }
    let report = analyze(&format!(
        "{INVOKE}{}Node 0 Normal free:1kB min:2kB low:3kB\n",
        context("CONSTRAINT_MEMCG", "oom_memcg=/service")
    ));
    assert!(
        report
            .evidence
            .iter()
            .any(|e| e.description.contains("below the printed minimum"))
    );
    assert!(
        !report
            .possible_causes
            .iter()
            .any(|s| s.contains("Local zone pressure"))
    );
    assert!(
        !report
            .recommendations
            .iter()
            .any(|s| s.contains("Track per-node/zone pressure"))
    );
    let permitted = analyze(&format!(
        "{INVOKE}{}Node 0 Normal free:1kB min:2kB low:3kB\n",
        context("CONSTRAINT_CPUSET", "global_oom")
    ));
    assert!(
        permitted
            .possible_causes
            .iter()
            .any(|s| s.contains("Local zone pressure"))
    );
}

#[test]
fn rendered_minimum_warnings_share_analysis_eligibility_and_counts() {
    use linux_oom_parser::{AnalysisOptions, format_event_analysis, format_event_analysis_auto};
    for source in [
        format!(
            "{INVOKE}{}Node 1 Normal free:1kB min:2kB low:3kB\n",
            context("CONSTRAINT_CPUSET", "global_oom")
        ),
        format!(
            "{}Node 0 Normal free:1kB min:2kB low:3kB\n",
            INVOKE.replace("GFP_KERNEL", "GFP_DMA")
        ),
    ] {
        let event = parse_events(&source).unwrap().remove(0);
        assert!(
            !analyze_event(&event)
                .structured_findings
                .iter()
                .any(|f| f.code() == FindingCode::ZoneBelowMinimum)
        );
        for verbose in [false, true] {
            for report in [
                format_event_analysis_auto(&event, verbose),
                format_event_analysis(&event, AnalysisOptions::default(), verbose),
            ] {
                assert!(!report.contains("below its minimum threshold"));
                assert!(!report.contains("additional zones were below"));
            }
        }
    }
    let mut source = format!(
        "{INVOKE}{}",
        context("CONSTRAINT_CPUSET", "global_oom").replace("mems_allowed=0", "mems_allowed=0-3")
    );
    for node in 0..=4 {
        source.push_str(&format!("Node {node} Normal free:1kB min:2kB\n"));
    }
    let event = parse_events(&source).unwrap().remove(0);
    let analysis = analyze_event(&event);
    assert_eq!(
        analysis
            .structured_findings
            .iter()
            .filter(|f| f.code() == FindingCode::ZoneBelowMinimum)
            .count(),
        4
    );
    let report = format_event_analysis_auto(&event, true);
    assert_eq!(report.matches("below its minimum threshold").count(), 3);
    assert!(report.contains("1 additional zone was below"));
    assert!(!report.contains("Node 4's"));
    let normalized = report.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized.contains("1.0 KiB (1024 bytes) below its minimum threshold"));
    assert!(report.contains("[line 3]"));
}

#[test]
fn unreliable_buddy_geometry_retains_buckets_without_availability_claims() {
    use linux_oom_parser::{AnalysisOptions, analyze_event_with_options};
    for buddy in [
        "Node 0 Normal: 1*64kB 0*128kB = 64kB\n",
        "Node 0 Normal: 1*4kB 0*16kB = 4kB\n",
        "Node 0 Normal: 1*4kB 0*8kB = 4kB\nNode 1 Normal: 1*64kB 0*128kB = 64kB\n",
    ] {
        let event = parse_events(format!("{INVOKE}{buddy}")).unwrap().remove(0);
        let report = analyze_event_with_options(&event, AnalysisOptions::default());
        assert!(
            report
                .limitations
                .iter()
                .any(|s| s.contains("Buddy availability"))
        );
        let buckets: Vec<_> = report
            .evidence
            .iter()
            .filter(|e| e.description.contains("printed buddy buckets"))
            .collect();
        assert!(!buckets.is_empty());
        assert_eq!(buckets[0].lines, [2]);
        assert!(buckets[0].description.contains("1 blocks of"));
        assert!(
            !report
                .evidence
                .iter()
                .any(|e| e.description.contains("blocks at this size or larger")
                    || e.description.contains("fragmentation or depletion"))
        );
    }
}

#[test]
fn allocation_helpers_share_intersected_node_restrictions() {
    let invocation = INVOKE.replace("order=0", "nodemask=1-2, order=0");
    let ctx = context("CONSTRAINT_MEMORY_POLICY", "global_oom")
        .replace("mems_allowed=0", "mems_allowed=0-2")
        .replace("nodemask=(null)", "nodemask=0-1");
    let mut log = format!("{invocation}worker cpuset=/ mems_allowed=0-2\n{ctx}");
    for node in 0..=2 {
        log.push_str(&format!(
            "Node {node} Normal free:0kB min:4kB low:8kB\nNode {node} Normal: 0*4kB 0*8kB = 0kB\n"
        ));
    }
    let report = analyze(&log);
    for label in [
        "below the printed minimum",
        "low watermark",
        "zone Normal buddy",
    ] {
        let findings: Vec<_> = report
            .evidence
            .iter()
            .filter(|e| e.description.starts_with("Node") && e.description.contains(label))
            .collect();
        assert_eq!(findings.len(), 1, "{label}: {findings:?}");
        assert!(findings[0].description.starts_with("Node 1 "));
    }
}

#[test]
fn structured_findings_preserve_measurements_and_source_lines() {
    use linux_oom_parser::{ByteSize, CgroupResource, MemoryMetric, MemoryZone};
    let report = analyze(&format!(
        "{INVOKE}Free swap = 0kB\nTotal swap = 1024kB\nNode 0 Normal free:1kB min:2kB low:3kB\nNode 0 Normal: 0*4kB 1*8kB = 8kB\n"
    ));
    let swap = report
        .structured_findings
        .iter()
        .find(|f| f.code() == FindingCode::SwapExhausted)
        .unwrap();
    assert_eq!(swap.lines, [3, 2]);
    assert_eq!(
        swap.data,
        FindingData::Swap {
            total: ByteSize::b(1048576),
            free: Some(ByteSize::b(0))
        }
    );
    let minimum = report
        .structured_findings
        .iter()
        .find(|f| f.code() == FindingCode::ZoneBelowMinimum)
        .unwrap();
    assert_eq!(minimum.lines, [4]);
    assert_eq!(
        minimum.data,
        FindingData::ZoneWatermark {
            node: 0,
            zone: MemoryZone::Normal,
            free: ByteSize::b(1024),
            threshold: ByteSize::b(2048),
            metric: MemoryMetric::Min
        }
    );
    let low = report
        .structured_findings
        .iter()
        .find(|f| f.code() == FindingCode::ZoneBelowLow)
        .unwrap();
    assert_eq!(low.lines, [4]);
    let buddy = report
        .structured_findings
        .iter()
        .find(|f| f.code() == FindingCode::BuddyAvailability)
        .unwrap();
    assert_eq!(buddy.lines, [1, 5]);
    assert_eq!(
        buddy.data,
        FindingData::Buddy {
            node: 0,
            zone: MemoryZone::Normal,
            request_bytes: 4096,
            fitting_blocks: 1,
            largest_block: Some(ByteSize::b(8192))
        }
    );
    let cgroup = analyze(&format!(
        "{INVOKE}memory: usage 512kB, limit 1024kB, failcnt 20\n"
    ));
    assert_eq!(cgroup.structured_findings.len(), 1);
    assert_eq!(
        cgroup.structured_findings[0].code(),
        FindingCode::CgroupBudget
    );
    assert_eq!(cgroup.structured_findings[0].lines, [2]);
    assert_eq!(
        cgroup.structured_findings[0].data,
        FindingData::CgroupBudget {
            resource: CgroupResource::Memory,
            usage: ByteSize::b(524288),
            limit: ByteSize::b(1048576),
            fail_count: 20
        }
    );
}

#[test]
fn structured_findings_respect_uncertainty_and_eligibility() {
    use linux_oom_parser::{AnalysisOptions, analyze_event_with_options};
    let event = parse_events(format!("{INVOKE}Node 0 Normal: 1*64kB 0*128kB = 64kB\n"))
        .unwrap()
        .remove(0);
    assert!(
        analyze_event_with_options(&event, AnalysisOptions::default())
            .structured_findings
            .is_empty()
    );
    let excluded = analyze(&format!(
        "{INVOKE}{}Node 1 Normal free:1kB min:2kB low:3kB\nNode 1 Normal: 0*4kB 0*8kB = 0kB\n",
        context("CONSTRAINT_CPUSET", "global_oom")
    ));
    assert!(excluded.structured_findings.is_empty());
    let shortage = analyze(&format!("{INVOKE}Node 0 Normal: 0*4kB 0*8kB = 0kB\n"));
    assert_eq!(
        shortage.structured_findings[0].code(),
        FindingCode::BuddyShortage
    );
    let above = analyze(&format!("{INVOKE}Node 0 Normal free:8kB min:2kB low:3kB\n"));
    assert_eq!(
        above.structured_findings[0].code(),
        FindingCode::ZoneWatermark
    );
    let manual = analyze(&format!(
        "sysrq: Manual OOM execution\n{INVOKE}Free swap = 0kB\nTotal swap = 1024kB\nNode 0 Normal: 0*4kB = 0kB\n"
    ));
    assert_eq!(manual.structured_findings.len(), 1);
    assert_eq!(
        manual.structured_findings[0].code(),
        FindingCode::SwapExhausted
    );
}

#[test]
fn page_size_validation_and_provenance_cover_every_selection_path() {
    use linux_oom_parser::{
        AnalysisOptions, PageSize, PageSizeEvidence, PageSizeSource, analyze_event_with_options,
    };
    for invalid in [0, 1, 512, 1023, 4095, 6144, u64::MAX] {
        assert!(PageSize::new(invalid).is_err());
        assert!(invalid.to_string().parse::<PageSize>().is_err());
    }
    for valid in [1024, 4096, 65536, 1 << 63] {
        assert_eq!(PageSize::try_from(valid).unwrap().get(), valid);
        assert_eq!(valid.to_string().parse::<PageSize>().unwrap().get(), valid);
    }
    let missing = parse_events(INVOKE).unwrap().remove(0);
    let fallback = analyze_event(&missing);
    assert_eq!(fallback.page_size.page_size.get(), 4096);
    assert_eq!(fallback.page_size.source, PageSizeSource::Fallback);
    assert_eq!(fallback.page_size.evidence, PageSizeEvidence::Missing);
    assert!(!fallback.to_string().contains("--page-size"));
    let explicit = analyze_event_with_options(&missing, AnalysisOptions::default());
    assert_eq!(explicit.page_size.source, PageSizeSource::Explicit);
    assert_eq!(explicit.page_size.evidence, PageSizeEvidence::Missing);
    let buddy = parse_events(format!("{INVOKE}Node 0 Normal: 1*64kB 0*128kB = 64kB\n"))
        .unwrap()
        .remove(0);
    let inferred = analyze_event(&buddy);
    assert_eq!(inferred.page_size.page_size.get(), 65536);
    assert_eq!(inferred.page_size.source, PageSizeSource::Buddy);
    assert_eq!(
        inferred.page_size.evidence,
        PageSizeEvidence::Consistent { lines: vec![2] }
    );
    let matched = analyze_event_with_options(
        &buddy,
        AnalysisOptions {
            page_size: PageSize::new(65536).unwrap(),
        },
    );
    assert_eq!(matched.page_size.source, PageSizeSource::Explicit);
    assert_eq!(matched.page_size.evidence, inferred.page_size.evidence);
    let conflict = analyze_event_with_options(&buddy, AnalysisOptions::default());
    assert_eq!(conflict.page_size.source, PageSizeSource::Explicit);
    assert_eq!(conflict.page_size.page_size.get(), 4096);
    assert_eq!(
        conflict.page_size.evidence,
        PageSizeEvidence::Conflicting {
            inferred: PageSize::new(65536).unwrap(),
            lines: vec![2]
        }
    );
    let inconsistent = parse_events(format!("{INVOKE}Node 0 Normal: 1*4kB 0*16kB = 4kB\n"))
        .unwrap()
        .remove(0);
    let fallback = analyze_event(&inconsistent);
    assert_eq!(fallback.page_size.source, PageSizeSource::Fallback);
    assert_eq!(
        fallback.page_size.evidence,
        PageSizeEvidence::Inconsistent { lines: vec![2] }
    );
    let explicit = analyze_event_with_options(
        &inconsistent,
        AnalysisOptions {
            page_size: PageSize::new(65536).unwrap(),
        },
    );
    assert_eq!(explicit.page_size.source, PageSizeSource::Explicit);
    assert_eq!(explicit.page_size.page_size.get(), 65536);
    assert_eq!(explicit.page_size.evidence, fallback.page_size.evidence);
    assert!(linux_oom_parser::format_event_analysis_auto(&buddy, true).contains("65536 bytes"));
    assert!(
        linux_oom_parser::format_event_analysis_auto(&missing, false).contains("--page-size BYTES")
    );
}
