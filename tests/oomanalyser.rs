#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test assertions")]
use linux_oom_parser::*;

#[test]
fn complete_external_examples_stay_in_one_event_and_roundtrip() {
    for (source, expected_reason, victim) in [
        (
            include_str!("fixtures/oomanalyser/archlinux_6_1_1.log"),
            OomReason::Global,
            "doxygen",
        ),
        (
            include_str!("fixtures/oomanalyser/proxmox_cgroup_oom.log"),
            OomReason::MemoryCgroup,
            "php-fpm",
        ),
        (
            include_str!("fixtures/oomanalyser/rhel7.log"),
            OomReason::AllocationFailure,
            "mysqld",
        ),
        (
            include_str!("fixtures/oomanalyser/ubuntu2110.log"),
            OomReason::Manual,
            "unattended-upgr",
        ),
    ] {
        let events = parse_events(source).unwrap();
        assert_eq!(events.len(), 1, "{victim}");
        let event = &events[0];
        assert_eq!(event.to_string(), source, "{victim}");
        assert_eq!(event.records.len(), source.lines().count(), "{victim}");
        let analysis = analyze_event(event);
        assert_eq!(analysis.reason, expected_reason, "{victim}");
        assert!(
            event
                .records
                .iter()
                .any(|r| matches!(&r.message, OomMessage::Killed(k) if k.name == victim))
        );
        assert!(!analysis.limitations.iter().any(|s| s.contains("No kill")));
        assert!(format_event_analysis(event, AnalysisOptions::default(), false).contains(victim));
    }
}

#[test]
fn legacy_selection_is_not_kill_confirmation_and_page_tables_keep_units() {
    let source = "worker invoked oom-killer: gfp_mask=0x201da, nodemask=0-2,4, order=0, oom_score_adj=0\nworker cpuset=/jobs mems_allowed=0-2,4\n[ pid ] uid tgid total_vm rss nr_ptes nr_pmds nr_puds swapents oom_score_adj name\n[ 7] 0 7 100 20 3 2 1 0 0 worker\nOut of memory: Kill process 7 (worker) score 651 or sacrifice child\n";
    let events = parse_events(source).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].to_string(), source);
    let OomMessage::Invoked(i) = &events[0].records[0].message else {
        panic!()
    };
    assert_eq!(i.nodemask.as_ref().unwrap().len(), 2);
    let OomMessage::Task(t) = &events[0].records[3].message else {
        panic!()
    };
    assert_eq!(t.page_tables, None);
    assert_eq!(t.page_table_pages, Some(3));
    assert_eq!(t.pmd_table_pages, Some(2));
    assert_eq!(t.pud_table_pages, Some(1));
    let analysis = analyze_event(&events[0]);
    assert!(analysis.limitations.iter().any(|s| s.contains("No kill")));
    assert!(analysis.to_string().contains("printed badness score 651"));
    assert!(analysis.to_string().contains("nr_ptes 3 pages (12.0 KiB"));
    let cgroup = parse_events(
        "Memory cgroup out of memory: Kill process 7 (worker) score 100 or sacrifice child\n",
    )
    .unwrap();
    assert_eq!(analyze_event(&cgroup[0]).reason, OomReason::MemoryCgroup);
}
