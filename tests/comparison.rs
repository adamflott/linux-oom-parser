#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "fail the test when setup or assertions encounter an unexpected value"
)]

use linux_oom_parser::{ComparisonOptions, PageSize, format_event_comparison, parse_events};

fn report(before: &str, after: &str, options: ComparisonOptions) -> String {
    let before = parse_events(before).unwrap();
    let after = parse_events(after).unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(after.len(), 1);
    format_event_comparison(&before[0], &after[0], options)
}

fn row<'a>(report: &'a str, name: &str) -> &'a str {
    report
        .lines()
        .find(|line| line.trim_start().starts_with(name))
        .unwrap()
}

#[test]
fn system_categories_compare_pages_to_bytes_and_do_not_sum_overlaps() {
    let before = "unrelated boot line\nsysrq: Manual OOM execution\nactive_anon:256 inactive_file:512 shmem:8 slab_unreclaimable:0 free:128\nFree swap = 1024kB\nTotal swap = 2048kB\n";
    let after = "sysrq: Manual OOM execution\nactive_anon:2048kB inactive_file:256 shmem:8 slab_unreclaimable:16 free:64\nFree swap = 0kB\nTotal swap = 2048kB\n";
    let actual = report(before, after, ComparisonOptions::default());
    assert!(row(&actual, "active_anon").contains("+1048576 bytes"));
    assert!(row(&actual, "inactive_file").contains("-1048576 bytes"));
    assert!(row(&actual, "free ").contains("-262144 bytes"));
    assert!(row(&actual, "slab_unreclaimable").contains("baseline zero"));
    assert!(row(&actual, "Free swap").contains("-1048576 bytes"));
    assert!(actual.contains("Source lines: before 3; after 2."));
    assert!(!actual.contains("Total swap"));
    assert!(!actual.contains("shmem"));
    assert!(actual.contains("memory categories can overlap"));
}

#[test]
fn page_size_is_inferred_independently_and_conflicting_overrides_are_visible() {
    let before = "sysrq: Manual OOM execution\nactive_anon:16\nNode 0 Normal: 1*4kB 0*8kB = 4kB\n";
    let after =
        "sysrq: Manual OOM execution\nactive_anon:1\nNode 0 Normal: 1*64kB 0*128kB = 64kB\n";
    let auto = report(before, after, ComparisonOptions::default());
    assert!(auto.contains("before 4096 bytes (inferred from buddy buckets)"));
    assert!(auto.contains("after 65536 bytes (inferred from buddy buckets)"));
    assert!(!auto.contains("active_anon")); // Both snapshots actually contain 64 KiB.
    let explicit = report(
        before,
        after,
        ComparisonOptions {
            before_page_size: None,
            after_page_size: Some(PageSize::new(4096).unwrap()),
        },
    );
    assert!(explicit.contains("conflicts with inferred 65536 bytes"));
    assert!(row(&explicit, "active_anon").contains("-61440 bytes"));
}

#[test]
fn process_groups_handle_pid_churn_multiple_workers_uid_and_breakdowns() {
    let before = concat!(
        "sysrq: Manual OOM execution\n",
        "[ pid ] uid tgid total_vm rss rss_anon rss_file rss_shmem pgtables_bytes swapents oom_score_adj name\n",
        "[ 10 ] 1000 10 100 10 6 3 1 4096 2 0 worker\n",
        "[ 11 ] 1000 11 100 20 12 6 2 4096 2 0 worker\n",
        "[ 12 ] 2000 12 100 1 1 0 0 4096 0 0 worker\n",
    );
    let after = concat!(
        "sysrq: Manual OOM execution\n",
        "[ pid ] uid tgid total_vm rss rss_anon rss_file rss_shmem pgtables_bytes swapents oom_score_adj name\n",
        "[ 90 ] 1000 90 300 60 40 15 5 12288 8 0 worker\n",
        "[ 91 ] 2000 91 100 1 1 0 0 4096 0 0 worker\n",
    );
    let actual = report(before, after, ComparisonOptions::default());
    assert!(actual.contains("Process worker (UID 1000; grouped by command)"));
    assert!(!actual.contains("Process worker (UID 2000"));
    assert!(row(&actual, "Resident memory (RSS)").contains("+122880 bytes"));
    assert!(row(&actual, "Anonymous RSS").contains("+90112 bytes"));
    assert!(row(&actual, "File RSS").contains("+24576 bytes"));
    assert!(row(&actual, "Shared RSS").contains("+8192 bytes"));
    assert!(row(&actual, "Captured tasks").contains("-1 count"));
    assert!(row(&actual, "Page tables").contains("+4096 bytes"));
    assert!(row(&actual, "Swap ").contains("+16384 bytes"));
    assert!(actual.contains("Source lines: before 3-4; after 3."));
}

#[test]
fn missing_counters_and_one_sided_processes_are_not_treated_as_zero() {
    let before =
        "sysrq: Manual OOM execution\nslab_unreclaimable:0\n[ 1 ] 0 1 20 10 4096 0 0 old\n";
    let after = "sysrq: Manual OOM execution\nactive_anon:16\n[ 2 ] 0 2 40 20 4096 0 0 new\n";
    let actual = report(before, after, ComparisonOptions::default());
    for name in ["active_anon", "slab_unreclaimable"] {
        let line = row(&actual, name);
        assert!(line.contains("not reported"));
        assert!(line.contains("not comparable (missing measurement)"));
        assert!(!line.contains("bytes)"));
    }
    assert!(actual.contains("Process groups captured only before"));
    assert!(actual.contains("Process groups captured only after"));
    assert!(actual.contains("Process new (UID 0; grouped by command): RSS 80.0 KiB (81920 bytes)"));
    assert!(!actual.contains("Largest measured memory changes"));
}

#[test]
fn legacy_and_new_task_layouts_preserve_unknown_rss_breakdowns_and_table_units() {
    let before = "sysrq: Manual OOM execution\n[ pid ] uid tgid total_vm rss nr_ptes swapents oom_score_adj name\n[ 1 ] 0 1 100 10 2 0 0 worker\n";
    let after = "sysrq: Manual OOM execution\n[ pid ] uid tgid total_vm rss rss_anon rss_file rss_shmem pgtables_bytes swapents oom_score_adj name\n[ 2 ] 0 2 100 10 6 3 1 8192 0 0 worker\n";
    let actual = report(before, after, ComparisonOptions::default());
    assert!(row(&actual, "Anonymous RSS").contains("not comparable (missing measurement)"));
    assert!(row(&actual, "Page tables (legacy nr_ptes)").contains("8.0 KiB"));
    assert!(row(&actual, "Page tables ").contains("not reported"));
    assert!(!actual.contains("Resident memory (RSS)"));
}

#[test]
fn numa_nodes_zones_buddy_hugepages_and_profiling_keep_separate_scopes() {
    let before = concat!(
        "sysrq: Manual OOM execution\n",
        "free:10\n",
        "Node 0 active_anon:0kB free:40kB\n",
        "Node 0 Normal free:40kB pages_scanned:10 all_unreclaimable? no\n",
        "Node 1 Normal free:40kB\n",
        "Node 0 Normal: 2*4kB 1*8kB = 16kB\n",
        "Node 0 hugepages_total=2 hugepages_free=1 hugepages_surp=0 hugepages_size=2048kB\n",
        "1.00 MiB 100 mm/file.c:12 func:alloc\n",
    );
    let after = before
        .replace(
            "free:40kB pages_scanned:10 all_unreclaimable? no",
            "free:20kB pages_scanned:30 all_unreclaimable? yes",
        )
        .replace("2*4kB 1*8kB = 16kB", "4*4kB 0*8kB = 16kB")
        .replace("hugepages_free=1", "hugepages_free=0")
        .replace("1.00 MiB 100", "2.00 MiB 150");
    let actual = report(before, &after, ComparisonOptions::default());
    assert!(actual.contains("Node 0, Normal zone"));
    assert!(!actual.contains("Node 1"));
    assert!(!actual.contains("System memory categories"));
    assert!(row(&actual, "free ").contains("-20480 bytes"));
    assert!(row(&actual, "pages_scanned").contains("+20 count"));
    assert!(row(&actual, "all_unreclaimable").contains("false -> true"));
    assert!(row(&actual, "Largest available block").contains("-4096 bytes"));
    assert!(row(&actual, "Free pool").contains("-2097152 bytes"));
    assert!(row(&actual, "mm/file.c:12 alloc: size").contains("+1048576 bytes"));
    assert!(row(&actual, "mm/file.c:12 alloc: allocations").contains("+50 count"));
    assert!(actual.contains("rounded measurements"));
}

#[test]
fn cgroup_deltas_distinguish_memory_cumulative_counts_and_unknown_units() {
    let before = "memory: usage 1024kB, limit 4096kB, failcnt 10\nMemory cgroup stats for /service:\nanon 1048576\npgfault 10\nfuture_field 100\n";
    let after = "memory: usage 2048kB, limit 4096kB, failcnt 15\nMemory cgroup stats for /service:\nanon 2097152\npgfault 30\nfuture_field 200\n";
    let actual = report(before, after, ComparisonOptions::default());
    assert!(actual.contains("before cgroup /service; after cgroup /service"));
    assert!(row(&actual, "memory usage").contains("+1048576 bytes"));
    assert!(row(&actual, "memory failcnt").contains("+5 count"));
    assert!(row(&actual, "pgfault").contains("+20 count"));
    assert!(row(&actual, "future_field").contains("not comparable (unit unknown)"));
    assert!(!actual.contains("memory limit"));
    let different_path = report(
        before,
        &after.replace("/service", "/other"),
        ComparisonOptions::default(),
    );
    assert!(row(&different_path, "anon ").contains("not comparable (missing measurement)"));
}

#[test]
fn kill_memory_is_compared_before_reaping_and_group_kills_are_aggregated() {
    let before = concat!(
        "Out of memory: Killed process 1 (worker) total-vm:100kB, anon-rss:50kB, file-rss:0kB\n",
        "Tasks in /service are going to be killed due to memory.oom.group set\n",
        "Out of memory: Killed process 2 (worker) total-vm:100kB, anon-rss:50kB, file-rss:0kB\n",
        "oom_reaper: reaped process 1 (worker), now anon-rss:0kB, file-rss:0kB, shmem-rss:0kB\n",
    );
    let after =
        "Out of memory: Killed process 10 (worker) total-vm:300kB, anon-rss:150kB, file-rss:0kB\n";
    let actual = report(before, after, ComparisonOptions::default());
    assert!(actual.contains("Killed process worker"));
    assert!(row(&actual, "Anonymous RSS").contains("+51200 bytes"));
    assert!(row(&actual, "Killed tasks").contains("-1 count"));
}

#[test]
fn unchanged_and_unmeasured_logs_report_distinct_results() {
    let log = "sysrq: Manual OOM execution\nactive_anon:16\n";
    assert!(
        report(log, log, ComparisonOptions::default())
            .contains("No differences in captured memory measurements.")
    );
    let empty = "sysrq: Manual OOM execution\n";
    assert!(
        report(empty, empty, ComparisonOptions::default())
            .contains("No memory measurements were captured in either event.")
    );
}

#[test]
fn control_characters_are_escaped_and_large_counts_do_not_wrap() {
    let before = "sysrq: Manual OOM execution\nactive_anon:18446744073709551615\n[ 1 ] 0 1 20 10 4096 0 0 worker\u{1b}[31m\n";
    let after =
        "sysrq: Manual OOM execution\nactive_anon:0\n[ 2 ] 0 2 40 20 4096 0 0 worker\u{1b}[31m\n";
    let actual = report(before, after, ComparisonOptions::default());
    assert!(row(&actual, "active_anon").contains("-75557863725914323415040 bytes"));
    assert!(actual.contains("worker\\u{1b}[31m"));
    assert!(!actual.contains('\u{1b}'));
}

#[test]
fn real_fixtures_compare_to_themselves_without_false_differences() {
    for log in [
        include_str!("../examples/nixos-linux-6.18.log"),
        include_str!("fixtures/oomanalyser/archlinux_6_1_1.log"),
        include_str!("fixtures/oomanalyser/rhel7.log"),
        include_str!("fixtures/oomanalyser/proxmox_cgroup_oom.log"),
    ] {
        let actual = report(log, log, ComparisonOptions::default());
        assert!(actual.contains("No differences in captured memory measurements."));
    }
}

#[test]
fn repeated_counters_use_the_latest_measurement_and_overflow_is_reported() {
    let before = "sysrq: Manual OOM execution\nactive_anon:1\nactive_anon:2\n";
    let after = "sysrq: Manual OOM execution\nactive_anon:3\n";
    let actual = report(before, after, ComparisonOptions::default());
    assert!(row(&actual, "active_anon").contains("+4096 bytes"));
    assert!(actual.contains("Repeated counters in a scope use the last captured value."));
    let before = concat!(
        "sysrq: Manual OOM execution\n",
        "[ 1 ] 0 1 0 18446744073709551615 0 0 0 worker\n",
        "[ 2 ] 0 2 0 18446744073709551615 0 0 0 worker\n",
        "[ 3 ] 0 3 0 18446744073709551615 0 0 0 worker\n",
    );
    let after = "sysrq: Manual OOM execution\n[ 4 ] 0 4 0 0 0 0 0 worker\n";
    let options = ComparisonOptions {
        before_page_size: Some(PageSize::new(1 << 63).unwrap()),
        after_page_size: None,
    };
    let actual = report(before, after, options);
    assert!(actual.contains("Process totals exceeding the supported byte range were omitted."));
    assert!(row(&actual, "Resident memory (RSS)").contains("not comparable (missing measurement)"));
}
