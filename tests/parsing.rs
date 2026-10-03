#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "fail the test when setup or assertions encounter an unexpected value"
)]

use linux_oom_parser::{GfpFlag, OomMessage, parse, parse_line};
use std::{borrow::Cow, sync::Arc};

const OLD: &str = "Killed process 7 (worker (pool)) total-vm:4096kB, anon-rss:128kB, file-rss:4kB";

#[test]
fn mixed_fixture_retains_order_locations_and_values() {
    let records = parse(include_str!("fixtures/mixed.log")).unwrap();
    assert_eq!(
        records.iter().map(|r| r.line_number).collect::<Vec<_>>(),
        [2, 3, 4, 5]
    );
    let OomMessage::Invoked(i) = &records[0].message else {
        panic!()
    };
    assert_eq!(i.name, "worker");
    assert_eq!(i.gfp_mask, 0x140cca);
    assert_eq!(
        i.gfp_flags.as_deref(),
        Some([GfpFlag::HighuserMovable, GfpFlag::FlagComp].as_slice())
    );
    assert_eq!((i.order, i.oom_score_adj), (0, 0));
    let OomMessage::Killed(k) = &records[2].message else {
        panic!()
    };
    assert_eq!(
        (k.pid, k.uid, k.oom_score_adj),
        (42, Some(1000), Some(-100))
    );
    assert_eq!(k.memory.total_vm, Some(bytesize::ByteSize::kib(4096)));
    assert_eq!(k.memory.anon_rss, Some(bytesize::ByteSize::kib(2048)));
    assert_eq!(k.memory.file_rss, Some(bytesize::ByteSize::kib(64)));
    assert_eq!(k.memory.shmem_rss, Some(bytesize::ByteSize::kib(4)));
    assert_eq!(k.memory.page_tables, Some(bytesize::ByteSize::kib(32)));
    assert!(!k.memory_cgroup);
    assert_eq!(
        records[2].prefix,
        "Sep 18 12:00:01 host kernel: [ 123.002] "
    );
    let OomMessage::Reaped(r) = &records[3].message else {
        panic!()
    };
    assert_eq!(r.pid, 42);
    assert_eq!(r.memory.anon_rss, Some(bytesize::ByteSize::kib(0)));
    assert_eq!(r.memory.total_vm, None);
}

#[test]
fn older_kernels_and_names_with_parentheses() {
    let record = parse_line(OLD).unwrap().unwrap();
    let OomMessage::Killed(k) = record.message else {
        panic!()
    };
    assert_eq!(k.name, "worker (pool)");
    assert_eq!(k.uid, None);
    assert_eq!(k.oom_score_adj, None);
    assert_eq!(k.memory.shmem_rss, None);
    assert_eq!(k.memory.page_tables, None);
}

#[test]
#[allow(
    clippy::unnecessary_to_owned,
    clippy::needless_borrows_for_generic_args
)] // Exercise each input type explicitly.
fn accepts_string_containers_and_owns_results() {
    let expected = parse(OLD).unwrap();
    assert_eq!(parse(OLD.to_owned()).unwrap(), expected);
    assert_eq!(parse(&OLD.to_owned()).unwrap(), expected);
    assert_eq!(parse(Box::<str>::from(OLD)).unwrap(), expected);
    assert_eq!(parse(Cow::Borrowed(OLD)).unwrap(), expected);
    assert_eq!(parse(Cow::<str>::Owned(OLD.to_owned())).unwrap(), expected);
    assert_eq!(parse(Arc::<str>::from(OLD)).unwrap(), expected);
    assert_eq!(
        parse_line(OLD.to_owned()).unwrap(),
        Some(expected[0].clone())
    );
}

#[test]
fn prefixes_and_line_endings() {
    for prefix in [
        "",
        "  ",
        "[123.456] ",
        "<3>[ 123.456] ",
        "Sep 18 12:00:00 host kernel: ",
    ] {
        let r = parse_line(format!("{prefix}{OLD}\r\n")).unwrap().unwrap();
        assert_eq!(r.prefix, prefix);
        assert_eq!(r.line_number, 1);
    }
    assert_eq!(parse(format!("\r\n{OLD}\r\n{OLD}")).unwrap().len(), 2);
    assert!(parse_line(format!("{OLD}\n{OLD}")).is_err());
}

#[test]
fn cgroup_and_unicode_names() {
    let text = format!(
        "Memory cgroup out of memory: {}",
        OLD.replace("worker (pool)", "工作 pool")
    );
    let OomMessage::Killed(k) = parse_line(text).unwrap().unwrap().message else {
        panic!()
    };
    assert!(k.memory_cgroup);
    assert_eq!(k.name, "工作 pool");
}

#[test]
fn zero_mask_and_negative_order() {
    let text = "task name invoked oom-killer: gfp_mask=0, order=-1, oom_score_adj=-1000";
    let OomMessage::Invoked(i) = parse_line(text).unwrap().unwrap().message else {
        panic!()
    };
    assert_eq!(i.gfp_mask, 0);
    assert_eq!(i.gfp_flags, None);
    assert_eq!(i.order, -1);
    assert_eq!(i.name, "task name");
}

#[test]
fn ignores_unsupported_and_unrelated_lines() {
    for text in [
        "",
        "hello",
        "application: Killed process 7",
        "oom_reaper: unable to reap pid:7 (worker)",
    ] {
        assert_eq!(parse_line(text).unwrap(), None);
        assert!(parse(text).unwrap().is_empty());
    }
}

#[test]
fn rejects_malformed_truncated_overflow_and_unknown_fields() {
    for text in [
        OLD.replace("process 7", "process 4294967296"),
        OLD.replace("4096kB", "18446744073709551616kB"),
        OLD.replace("4096kB", "-1kB"),
        OLD.replace("4096kB", "4096MB"),
        OLD.replace("file-rss:4kB", "file-rss:"),
        format!("{OLD}, shmem-rss:bad"),
        format!("{OLD}, UID:4294967296"),
        format!("{OLD} oom_score_adj:2147483648"),
        format!("{OLD} unexpected:1"),
        "Killed process".into(),
        "task invoked oom-killer: gfp_mask=0x1, order=0".into(),
        "oom_reaper: reaped process 7 (worker), now anon-rss:0kB".into(),
    ] {
        assert!(parse_line(&text).is_err(), "accepted: {text}");
    }
}

#[test]
fn errors_include_source_and_line_number() {
    let error = parse(format!("unrelated\n{OLD}\nKilled process bad")).unwrap_err();
    assert_eq!(error.line_number, 3);
    assert_eq!(error.input, "Killed process bad");
    assert!(error.to_string().contains("line 3"));
    let _: &dyn std::error::Error = &error;
}

#[test]
fn all_unicode_truncations_are_panic_free() {
    let text = OLD.replace("worker (pool)", "工作 (pool)");
    for (end, _) in text.char_indices() {
        let _ = parse_line(&text[..end]);
    }
}
