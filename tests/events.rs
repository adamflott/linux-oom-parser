#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "fail the test when setup or assertions encounter an unexpected value"
)]

use linux_oom_parser::*;

const INVOKE: &str =
    "worker invoked oom-killer: gfp_mask=0xcc0(GFP_KERNEL), order=0, oom_score_adj=0";
const KILL: &str =
    "Out of memory: Killed process 7 (worker) total-vm:100kB, anon-rss:50kB, file-rss:0kB";
const REAP: &str =
    "oom_reaper: reaped process 7 (worker), now anon-rss:0kB, file-rss:0kB, shmem-rss:0kB";
const OLD_HEADER: &str = "[ pid ] uid tgid total_vm rss pgtables_bytes swapents oom_score_adj name";
const NEW_HEADER: &str = "[ pid ] uid tgid total_vm rss rss_anon rss_file rss_shmem pgtables_bytes swapents oom_score_adj name";

#[test]
fn allocating_task_kills_are_retained_and_close_capture() {
    let kill = KILL.replace(
        "Out of memory:",
        "Out of memory (oom_kill_allocating_task):",
    );
    let OomMessage::Killed(victim) = parse_line(&kill).unwrap().unwrap().message else {
        panic!()
    };
    assert_eq!(victim.pid, 7);
    assert!(!victim.memory_cgroup);
    assert_eq!(parse_events(&kill).unwrap()[0].to_string(), kill);
    let source = format!("{INVOKE}\n{kill}\nCPU: unrelated malformed warning\n{REAP}\n");
    let events = parse_events(&source).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].records.len(), 3);
    assert!(matches!(
        events[0].records[1].message,
        OomMessage::Killed(_)
    ));
    assert!(matches!(
        events[0].records[2].message,
        OomMessage::Reaped(_)
    ));
    assert!(parse_line(kill.replace("process 7", "process invalid")).is_err());
}

#[test]
fn group_kills_preserve_one_operation_and_report_every_victim() {
    for (constraint, scope, prefix, reason) in [
        (
            "CONSTRAINT_MEMCG",
            "oom_memcg=/service",
            "Memory cgroup out of memory:",
            OomReason::MemoryCgroup,
        ),
        (
            "CONSTRAINT_NONE",
            "global_oom",
            "Out of memory:",
            OomReason::Global,
        ),
    ] {
        let ctx = format!(
            "oom-kill:constraint={constraint},nodemask=(null),cpuset=/,mems_allowed=0,{scope},task_memcg=/service,task=worker,pid=7,uid=0"
        );
        let first = KILL.replace("Out of memory:", prefix);
        let second = first.replace("process 7 (worker)", "process 8 (child-one)");
        let third = first.replace("process 7 (worker)", "process 9 (child-two)");
        let reap = REAP.replace("process 7 (worker)", "process 9 (child-two)");
        let source = format!(
            "{INVOKE}\n{ctx}\n{first}\n{REAP}\nTasks in /service are going to be killed due to memory.oom.group set\n{second}\n{third}\n{reap}\n"
        );
        let events = parse_events(&source).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].records.len(), 8);
        assert_eq!(events[0].to_string(), source);
        assert_eq!(parse_events(events[0].to_string()).unwrap(), events);
        assert!(
            matches!(&events[0].records[4].message, OomMessage::GroupKill(path) if path == "/service")
        );
        let analysis = analyze_event(&events[0]);
        assert_eq!(analysis.reason, reason);
        for pid in [7, 8, 9] {
            assert!(
                analysis
                    .evidence
                    .iter()
                    .any(|e| e.description.starts_with(&format!("Killed PID {pid} ")))
            );
            assert!(
                analysis
                    .evidence
                    .iter()
                    .any(|e| e.description.starts_with(&format!("Victim PID {pid} ")))
            );
        }
        let report = format_event_analysis_auto(&events[0], true);
        assert!(report.contains("killed 3 processes during this OOM operation"));
        for name in ["worker", "child-one", "child-two"] {
            assert!(report.contains(name));
        }
        assert_eq!(report.matches("Victim memory (PID").count(), 3);
    }
}

#[test]
fn group_kill_capture_obeys_boundaries_and_supports_partial_logs() {
    let group = "Tasks in /service are going to be killed due to memory.oom.group set";
    let second = KILL.replace("process 7", "process 8");
    let ctx = "oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=/service,task=worker,pid=7,uid=0";
    for boundary in ["Linux version 6.18.0", "unrelated traffic", INVOKE, ctx] {
        let source = format!("{INVOKE}\n{KILL}\n{group}\n{boundary}\n{second}");
        let events = parse_events(source).unwrap();
        assert_eq!(events.len(), 2, "{boundary}");
        assert_eq!(events[0].records.len(), 3);
        assert!(
            matches!(&events[1].records.last().unwrap().message, OomMessage::Killed(k) if k.pid == 8)
        );
    }
    let source = format!("{group}\n{second}\n");
    let events = parse_events(&source).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].to_string(), source);
    assert!(parse_line(format!("{group} unexpected")).is_err());
    let separated = parse_events(format!("{KILL}\nunrelated traffic\n{source}")).unwrap();
    assert_eq!(separated.len(), 2);
}

#[test]
fn compaction_notice_preserves_diagnostics_and_manual_classification() {
    let notice = "COMPACTION is disabled!!!";
    assert!(matches!(
        parse_line(notice).unwrap().unwrap().message,
        OomMessage::CompactionDisabled
    ));
    assert!(parse_events(notice).unwrap().is_empty());
    for (order, reason) in [(-1, OomReason::Manual), (2, OomReason::Global)] {
        let invoke = INVOKE.replace("order=0", &format!("order={order}"));
        let source = format!(
            "{invoke}\n{notice}\nCPU: 0 PID: 7 Comm: worker Not tainted 6.18.0 #1\nMem-Info:\nactive_anon:100\noom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=/service,task=worker,pid=7,uid=0\n{KILL}\n"
        );
        let events = parse_events(&source).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].records.len(), 7);
        assert_eq!(events[0].to_string(), source);
        let analysis = analyze_event(&events[0]);
        assert_eq!(analysis.reason, reason);
        assert!(
            analysis
                .evidence
                .iter()
                .any(|e| e.lines == [2] && e.description.contains("compaction is disabled"))
        );
        assert_eq!(
            analysis
                .recommendations
                .iter()
                .any(|s| s.contains("CONFIG_COMPACTION")),
            order > 0
        );
        let report = format_event_analysis_auto(&events[0], false);
        assert!(report.contains("compaction is disabled"));
        if order == -1 {
            assert!(report.contains("Manual OOM request"));
        }
    }
    assert!(parse_events(format!("{INVOKE}\nCOMPACTION is disabled! malformed")).is_err());
}

#[test]
fn scopes_shared_diagnostics_to_ooms_and_preserves_partial_events() {
    let log = format!(
        "CPU: malformed unrelated warning\nMem-Info:\nactive_anon:9\n{INVOKE}\nMem-Info:\nactive_anon:10\n{KILL}\nCPU: malformed unrelated warning\nMem-Info:\n{INVOKE}\nactive_anon:20"
    );
    let events = parse_events(log).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0]
            .records
            .iter()
            .map(|r| r.line_number)
            .collect::<Vec<_>>(),
        [4, 5, 6, 7]
    );
    assert_eq!(
        events[1]
            .records
            .iter()
            .map(|r| r.line_number)
            .collect::<Vec<_>>(),
        [10, 11]
    );
    assert!(
        parse("CPU: malformed unrelated warning\nMem-Info:\nactive_anon:9")
            .unwrap()
            .is_empty()
    );
    // Context-free line parsing remains available for diagnostic snippets.
    assert!(parse_line("Mem-Info:").unwrap().is_some());
    assert!(parse(format!("{INVOKE}\nCPU: malformed OOM context")).is_err());
}

#[test]
fn unknown_lines_end_capture_and_new_invocations_start_fresh_events() {
    let log = format!(
        "{INVOKE}\nMem-Info:\nWARNING: unrelated diagnostic\nCPU: malformed\n{INVOKE}\n{INVOKE}\n{KILL}"
    );
    let events = parse_events(log).unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(
        events.iter().map(|e| e.records.len()).collect::<Vec<_>>(),
        [2, 1, 2]
    );
}

#[test]
fn groups_sysrq_and_detached_oom_specific_messages() {
    let events = parse_events(format!("sysrq: Manual OOM execution\n{INVOKE}\n{KILL}")).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].records.len(), 3);
    assert_eq!(parse_events(KILL).unwrap().len(), 1);
    assert_eq!(parse_events(REAP).unwrap().len(), 1);
    assert!(parse_events("").unwrap().is_empty());
}

#[test]
fn reapers_attach_by_victim_and_flat_records_stay_in_source_order() {
    let other_kill = KILL.replace("process 7", "process 8");
    let log = format!("{INVOKE}\n{KILL}\n{INVOKE}\n{other_kill}\nunrelated traffic\n{REAP}");
    let events = parse_events(&log).unwrap();
    assert_eq!(events.len(), 2);
    assert!(matches!(
        events[0].records.last().unwrap().message,
        OomMessage::Reaped(_)
    ));
    let flat = parse(log).unwrap();
    assert_eq!(
        flat.iter().map(|r| r.line_number).collect::<Vec<_>>(),
        [1, 2, 3, 4, 6]
    );
    // Mismatched name must not match a reused PID.
    let events = parse_events(format!("{KILL}\n{}", REAP.replace("(worker)", "(other)"))).unwrap();
    assert_eq!(events.len(), 2);
}

#[test]
fn reboot_and_backwards_timestamps_prevent_stale_reaper_matches() {
    for boundary in ["Linux version 6.6.0", "unrelated"] {
        let events = parse_events(format!("[1000.0] {KILL}\n{boundary}\n[1.0] {REAP}")).unwrap();
        assert_eq!(events.len(), 2);
    }
    let events = parse_events(format!("{KILL}\nLinux version 6.18.0\n{REAP}")).unwrap();
    assert_eq!(events.len(), 2);
}

#[test]
fn uptime_on_unrelated_lines_sets_boot_boundaries_outside_capture() {
    for (traffic, expected_events) in [
        ("[1.0] unrelated traffic", 2),
        ("[5000.0] unrelated traffic", 2),
        ("[939.999] unrelated traffic", 2),
        ("[940.0] unrelated traffic", 1),
        ("[999.9] unrelated traffic", 1),
        ("[1..2] unrelated traffic", 1),
        ("unrelated traffic", 1),
    ] {
        let log = format!("[1000.0] {KILL}\n{traffic}\n[1001.0] {REAP}\n");
        let events = parse_events(&log).unwrap();
        assert_eq!(events.len(), expected_events, "{traffic}");
        let flat = parse(&log).unwrap();
        assert_eq!(
            flat.iter().map(|r| r.line_number).collect::<Vec<_>>(),
            [1, 3]
        );
        assert_eq!(
            flat.iter().map(ToString::to_string).collect::<String>(),
            format!("[1000.0] {KILL}\n[1001.0] {REAP}\n")
        );
        assert_eq!(
            events[0].records.len(),
            if expected_events == 1 { 2 } else { 1 }
        );
    }
}

#[test]
fn headers_select_both_layouts_and_preserve_numeric_task_names() {
    let legacy = "[ 7] 0 7 100 80 4096 2 -1000 123 456 789 name";
    let modern = "[ 8] 0 8 100 80 60 20 0 4096 2 -1000 name";
    let log = format!(
        "{INVOKE}\n{OLD_HEADER}\n{legacy}\n{KILL}\n{INVOKE}\n{NEW_HEADER}\n{modern}\n{KILL}"
    );
    let events = parse_events(log).unwrap();
    assert_eq!(events.len(), 2);
    let OomMessage::Task(old) = &events[0].records[2].message else {
        panic!()
    };
    assert_eq!(old.rss_anon_pages, None);
    assert_eq!(old.page_tables, Some(bytesize::ByteSize::b(4096)));
    assert_eq!(old.swap_entries, 2);
    assert_eq!(old.oom_score_adj, -1000);
    assert_eq!(old.name, "123 456 789 name");
    let OomMessage::Task(new) = &events[1].records[2].message else {
        panic!()
    };
    assert_eq!(
        (new.rss_anon_pages, new.rss_file_pages, new.rss_shmem_pages),
        (Some(60), Some(20), Some(0))
    );
    assert_eq!(
        parse_task_line(legacy, TaskLayout::TotalRss)
            .unwrap()
            .message,
        events[0].records[2].message
    );
    // An incorrect/truncated modern row must not fall back to the old layout.
    assert!(
        parse(format!(
            "{INVOKE}\n{NEW_HEADER}\n[ 7] 0 7 100 80 4096 0 0 worker"
        ))
        .is_err()
    );
    assert!(parse_task_line("Mem-Info:", TaskLayout::TotalRss).is_err());
}

#[test]
fn standalone_task_layout_detection_and_malformed_machine_state() {
    let OomMessage::Task(task) = parse_line("[ 7] 0 7 100 80 4096 0 0 worker")
        .unwrap()
        .unwrap()
        .message
    else {
        panic!()
    };
    assert_eq!(task.rss_anon_pages, None);
    for line in [
        "RIP: 10000:0x1",
        "RIP: 0033:0xzz",
        "Code: 0g",
        "Code: <01> <02>",
        "RAX: 10000000000000000",
        "RSP: 10000:1234",
        "Code: Unable to access opcode bytes at 0xzz.",
    ] {
        assert!(parse_line(line).is_err(), "accepted {line}");
    }
    let record = parse_line("RIP: 0010:work+0x1/0x20 [module]")
        .unwrap()
        .unwrap();
    let OomMessage::InstructionPointer(ip) = record.message else {
        panic!()
    };
    let InstructionLocation::Symbol(frame) = ip.location else {
        panic!()
    };
    assert_eq!(frame.symbol, "work");
    assert_eq!(frame.module.as_deref(), Some("module"));
}
