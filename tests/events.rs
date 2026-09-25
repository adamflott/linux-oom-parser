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
    assert_eq!(old.page_tables, bytesize::ByteSize::b(4096));
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
