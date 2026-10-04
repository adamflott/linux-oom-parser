#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "fail the test when setup or assertions encounter an unexpected value"
)]

use linux_oom_parser::{ByteSize, FormatOptions, PageSize, format_log};

#[test]
fn rewrites_memory_diagnostics_with_total_ram_and_preserves_other_values() {
    let source = concat!(
        "boot: 100kB 200 pages\r\n",
        "[1.000] sysrq: Manual OOM execution\r\n",
        "[1.001] Mem-Info:\r\n",
        "[1.002] active_anon:512 inactive_anon:0#012 free:256\r\n",
        "[1.003] Node 0 Normal free:1024kB min:512KB pages_scanned:42 all_unreclaimable? no Balloon:0kB\r\n",
        "[1.004] lowmem_reserve[]: 0 256\r\n",
        "[1.005] Node 0 Normal: 2*4kB (UM) 0*8kB = 8kB\r\n",
        "[1.006] Node 0 hugepages_total=2 hugepages_free=1 hugepages_surp=0 hugepages_size=2048kB\r\n",
        "[1.007] 128 total pagecache pages\r\n",
        "[1.008] 64 pages in swap cache\r\n",
        "[1.009] Free swap  = 0kB\r\n",
        "[1.010] Total swap = 8192kB\r\n",
        "[1.011] 1024 pages RAM\r\n",
        "[1.012] 32 pages reserved\r\n",
        "[1.013] 1.21 MiB 42 mm/file.c:12 func:alloc\r\n",
        "[1.014] Out of memory: Killed process 42 (工作 anon-rss:99kB) total-vm:8192kB, anon-rss:2048kB, file-rss:1024kB, shmem-rss:0kB, UID:1000 pgtables:4kB oom_score_adj:-1000  \r\n",
        "unrelated: 2048kB\r\n",
        "[1.020] oom_reaper: reaped process 42 (工作 anon-rss:99kB), now anon-rss:1024kB, file-rss:0kB, shmem-rss:0kB"
    );
    let actual = format_log(source, FormatOptions::default()).unwrap();
    assert_eq!(
        actual,
        concat!(
            "boot: 100kB 200 pages\r\n",
            "[1.000] sysrq: Manual OOM execution\r\n",
            "[1.001] Mem-Info:\r\n",
            "[1.002] active_anon:2.0 MiB (50.00%) inactive_anon:0 B (0.00%)#012 free:1.0 MiB (25.00%)\r\n",
            "[1.003] Node 0 Normal free:1.0 MiB (25.00%) min:512.0 KiB (12.50%) pages_scanned:42 all_unreclaimable? no Balloon:0 B (0.00%)\r\n",
            "[1.004] lowmem_reserve[]: 0 B (0.00%) 1.0 MiB (25.00%)\r\n",
            "[1.005] Node 0 Normal: 2*4.0 KiB (0.10%) (UM) 0*8.0 KiB (0.20%) = 8.0 KiB (0.20%)\r\n",
            "[1.006] Node 0 hugepages_total=4.0 MiB (100.00%) hugepages_free=2.0 MiB (50.00%) hugepages_surp=0 B (0.00%) hugepages_size=2.0 MiB (50.00%)\r\n",
            "[1.007] 512.0 KiB (12.50%) total pagecache\r\n",
            "[1.008] 256.0 KiB (6.25%) in swap cache\r\n",
            "[1.009] Free swap  = 0 B (0.00%)\r\n",
            "[1.010] Total swap = 8.0 MiB (200.00%)\r\n",
            "[1.011] 4.0 MiB (100.00%) RAM\r\n",
            "[1.012] 128.0 KiB (3.12%) reserved\r\n",
            "[1.013] 1.2 MiB (30.25%) 42 mm/file.c:12 func:alloc\r\n",
            "[1.014] Out of memory: Killed process 42 (工作 anon-rss:99kB) total-vm:8.0 MiB (200.00%), anon-rss:2.0 MiB (50.00%), file-rss:1.0 MiB (25.00%), shmem-rss:0 B (0.00%), UID:1000 pgtables:4.0 KiB (0.10%) oom_score_adj:-1000  \r\n",
            "unrelated: 2048kB\r\n",
            "[1.020] oom_reaper: reaped process 42 (工作 anon-rss:99kB), now anon-rss:1.0 MiB (25.00%), file-rss:0 B (0.00%), shmem-rss:0 B (0.00%)"
        )
    );
}

#[test]
fn each_event_uses_its_own_ram_and_inferred_page_size() {
    let source = concat!(
        "sysrq: Manual OOM execution\n",
        "active_anon:128\n",
        "Node 0 Normal: 1*64kB 0*128kB = 64kB\n",
        "1024 pages RAM\n",
        "Out of memory: Killed process 1 (a) total-vm:8192kB, anon-rss:0kB, file-rss:0kB\n",
        "sysrq: Manual OOM execution\n",
        "active_anon:128\n",
        "Node 0 Normal: 1*4kB 0*8kB = 4kB\n",
        "512 pages RAM\n",
        "Out of memory: Killed process 2 (b) total-vm:8192kB, anon-rss:0kB, file-rss:0kB\n",
        "sysrq: Manual OOM execution\n",
        "active_anon:128\n",
        "Out of memory: Killed process 3 (c) total-vm:8192kB, anon-rss:0kB, file-rss:0kB\n"
    );
    let actual = format_log(source, FormatOptions::default()).unwrap();
    assert!(actual.contains("active_anon:8.0 MiB (12.50%)"));
    assert!(actual.contains("active_anon:512.0 KiB (25.00%)"));
    assert!(actual.contains("active_anon:512.0 KiB (RAM unknown)"));
    let mut options = FormatOptions::default();
    options.page_size = Some(PageSize::new(16384).unwrap());
    options.total_memory = Some(ByteSize::mib(16));
    let actual = format_log(source, options).unwrap();
    assert_eq!(actual.matches("active_anon:2.0 MiB (12.50%)").count(), 3);
    assert_eq!(actual.matches("total-vm:8.0 MiB (50.00%)").count(), 3);
}

#[test]
fn cgroup_byte_quantities_use_host_ram_and_counters_keep_their_units() {
    let source = concat!(
        "memory: usage 2048kB, limit 4096kB, failcnt 7\n",
        "Memory cgroup stats for /service:\n",
        "anon 1048576\n",
        "total_cache 2097152\n",
        "pgfault 8192\n",
        "workingset_refault_anon 42\n",
        "future_field 1048576\n"
    );
    let actual = format_log(source, FormatOptions::default()).unwrap();
    assert!(actual.contains("usage 2.0 MiB (RAM unknown), limit 4.0 MiB (RAM unknown), failcnt 7"));
    let mut options = FormatOptions::default();
    options.total_memory = Some(ByteSize::mib(8));
    let actual = format_log(source, options).unwrap();
    assert!(actual.contains("usage 2.0 MiB (25.00%), limit 4.0 MiB (50.00%), failcnt 7"));
    assert!(actual.contains("anon 1.0 MiB (12.50%)\n"));
    assert!(actual.contains("total_cache 2.0 MiB (25.00%)\n"));
    assert!(actual.ends_with("pgfault 8192\nworkingset_refault_anon 42\nfuture_field 1048576\n"));
}

#[test]
fn task_tables_convert_breakdown_and_legacy_units_and_keep_numeric_names() {
    let source = concat!(
        "sysrq: Manual OOM execution\n",
        "1024 pages RAM\n",
        "Total swap = 8192kB\n",
        "Tasks state (memory values in pages):\n",
        "[ pid ] uid tgid total_vm rss rss_anon rss_file rss_shmem pgtables_bytes swapents oom_score_adj name\n",
        "[ 42 ] 1000 42 2048 512 256 128 128 4096 64 -1000 123 工作 2048kB\n",
        "[ 43 ] 1000 43 1024 256 256 0 0 8192 0 100 sibling\n",
        "[ pid ] uid tgid total_vm rss nr_ptes nr_pmds nr_puds swapents oom_score_adj name\n",
        "[ 44 ] 1000 44 2048 512 256 128 64 64 -1000 legacy\n"
    );
    let actual = format_log(source, FormatOptions::default()).unwrap();
    assert!(
        actual.contains("Tasks state (memory values: size and % of RAM, swap: % of total swap):")
    );
    assert!(!actual.contains("pgtables_bytes"));
    let rows: Vec<_> = actual
        .lines()
        .filter(|line| line.starts_with('['))
        .collect();
    assert_eq!(rows.len(), 5);
    assert!(rows[1].contains("8.0 MiB (200.00%)"));
    assert!(rows[1].contains("4.0 KiB (0.10%)"));
    assert!(rows[1].contains("256.0 KiB (3.12%)"));
    assert!(rows[1].ends_with("-1000  123 工作 2048kB"));
    assert_eq!(rows[0].find("name"), rows[1].find("123 工作"));
    assert_eq!(rows[0].find("name"), rows[2].find("sibling"));
    assert!(rows[4].contains("1.0 MiB (25.00%)"));
    assert!(rows[4].contains("512.0 KiB (12.50%)"));
    assert_eq!(rows[4].matches("256.0 KiB (6.25%)").count(), 1);
    assert!(rows[4].contains("256.0 KiB (3.12%)"));
    // Without a header, the parser infers the older total-RSS layout.
    let standalone = "sysrq: Manual OOM execution\n1024 pages RAM\n[ 42 ] 1000 42 2048 512 4096 64 -1000 worker\n";
    assert!(
        format_log(standalone, FormatOptions::default())
            .unwrap()
            .contains("4.0 KiB (0.10%)")
    );
}

#[test]
fn task_swap_uses_event_totals_and_page_sizes_independently_of_ram() {
    let source = concat!(
        "sysrq: Manual OOM execution\n",
        "1024 pages RAM\n",
        "Node 0 Normal: 1*64kB 0*128kB = 64kB\n",
        "Total swap = 8192kB\n",
        "[ pid ] uid tgid total_vm rss pgtables_bytes swapents oom_score_adj name\n",
        "[ 7 ] 0 7 2048 512 4096 64 0 first\n",
        "sysrq: Manual OOM execution\n",
        "Node 0 Normal: 1*4kB 0*8kB = 4kB\n",
        "Total swap = 1024kB\n",
        "[ 8 ] 0 8 2048 512 4096 64 0 second\n",
        "sysrq: Manual OOM execution\n",
        "1024 pages RAM\n",
        "Free swap = 1024kB\n",
        "[ 9 ] 0 9 2048 512 4096 64 0 missing\n",
        "sysrq: Manual OOM execution\n",
        "1024 pages RAM\n",
        "Total swap = 0kB\n",
        "[ 10 ] 0 10 2048 512 4096 64 0 zero\n",
        "[ 11 ] 0 11 2048 512 4096 0 0 empty\n"
    );
    let actual = format_log(source, FormatOptions::default()).unwrap();
    let actual = actual.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(actual.contains("4.0 MiB (50.00%) 0 first"));
    assert!(actual.contains("256.0 KiB (25.00%) 0 second"));
    assert!(actual.contains("2.0 MiB (RAM unknown)"));
    assert!(actual.contains("256.0 KiB (swap unknown) 0 missing"));
    assert!(actual.contains("256.0 KiB (swap unknown) 0 zero"));
    assert!(actual.contains("0 B (swap unknown) 0 empty"));

    let mut options = FormatOptions::default();
    options.page_size = Some(PageSize::new(16384).unwrap());
    options.total_memory = Some(ByteSize::mib(16));
    let actual = format_log(source, options).unwrap();
    let actual = actual.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(actual.contains("1.0 MiB (12.50%) 0 first"));
    assert!(actual.contains("1.0 MiB (100.00%) 0 second"));
    assert!(actual.contains("8.0 MiB (50.00%)"));
    assert!(actual.contains("1.0 MiB (swap unknown) 0 missing"));
    assert!(actual.contains("1.0 MiB (swap unknown) 0 zero"));
    assert!(actual.contains("0 B (swap unknown) 0 empty"));
}

#[test]
fn zero_missing_tiny_and_very_large_values_are_explicit_and_do_not_overflow() {
    let source = "sysrq: Manual OOM execution\nactive_anon:0 free:1\n0 pages RAM\n";
    let actual = format_log(source, FormatOptions::default()).unwrap();
    assert!(actual.contains("active_anon:0 B (RAM unknown) free:4.0 KiB (RAM unknown)"));
    let mut options = FormatOptions::default();
    options.total_memory = Some(ByteSize::gib(64));
    assert!(
        format_log(source, options)
            .unwrap()
            .contains("free:4.0 KiB (<0.01%)")
    );
    options.total_memory = None;
    options.page_size = Some(PageSize::new(1 << 63).unwrap());
    let huge = "sysrq: Manual OOM execution\nactive_anon:18446744073709551615\n18446744073709551615 pages RAM\n";
    let actual = format_log(huge, options).unwrap();
    assert!(actual.contains("EiB (100.00%)"));
    assert!(!actual.contains("inf"));
    assert!(!actual.contains("NaN"));
    // A reaper's name may contain the kill message's memory delimiter.
    let reaper = "oom_reaper: reaped process 7 (worker) total-vm:1kB anon-rss:9kB), now anon-rss:1024kB, file-rss:0kB\n";
    let actual = format_log(reaper, FormatOptions::default()).unwrap();
    assert!(
        actual.contains("(worker) total-vm:1kB anon-rss:9kB), now anon-rss:1.0 MiB (RAM unknown)")
    );
}

#[test]
fn real_fixtures_keep_line_count_prefixes_and_non_memory_records() {
    for source in [
        include_str!("../examples/nixos-linux-6.18.log"),
        include_str!("fixtures/oomanalyser/archlinux_6_1_1.log"),
        include_str!("fixtures/oomanalyser/proxmox_cgroup_oom.log"),
        include_str!("fixtures/oomanalyser/rhel7.log"),
        include_str!("fixtures/oomanalyser/ubuntu2110.log"),
    ] {
        let actual = format_log(source, FormatOptions::default()).unwrap();
        assert_eq!(source.lines().count(), actual.lines().count());
        assert_eq!(source.ends_with('\n'), actual.ends_with('\n'));
        assert!(actual.contains("total-vm:"));
        assert!(!actual.contains("pages RAM"));
        for (original, formatted) in source.lines().zip(actual.lines()) {
            if original.contains(" invoked oom-killer:")
                || original.contains("+0x")
                || original.contains("Hardware name:")
                || original.contains("oom-kill:")
                || original.contains("Swap cache stats:")
                || original.contains("pgfault ")
            {
                assert_eq!(original, formatted);
            }
            if let Some((stamp, _)) = original.split_once("] ") {
                assert!(formatted.starts_with(stamp));
            }
        }
    }
}
