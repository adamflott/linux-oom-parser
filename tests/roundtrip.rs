#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "fail the test when setup or assertions encounter an unexpected value"
)]

use linux_oom_parser::{ByteSize, OomMessage, WallTime, parse, parse_events, parse_line};

const NIXOS: &str = include_str!("../examples/nixos-linux-6.18.log");

#[test]
fn linux_6_18_roundtrips_exactly() {
    for source in [
        NIXOS.to_owned(),
        NIXOS.replace('\n', "\r\n"),
        format!("{NIXOS}\n"),
    ] {
        let events = parse_events(&source).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].records.len(), 126);
        let printed = events[0].to_string();
        assert_eq!(printed, source);
        assert_eq!(parse_events(&printed).unwrap(), events);
        assert_eq!(
            parse(&source)
                .unwrap()
                .iter()
                .map(ToString::to_string)
                .collect::<String>(),
            source
        );
    }
}

#[test]
fn individual_lines_preserve_whitespace_and_endings() {
    for line in [
        "  sysrq: Manual OOM execution  ",
        "sysrq: Manual OOM execution\r\n",
        "sysrq: Manual OOM execution\n",
    ] {
        let record = parse_line(line).unwrap().unwrap();
        assert_eq!(record.to_string(), line);
    }
}

#[test]
fn parses_calendar_and_uptime_independently() {
    let record =
        parse_line("Sep  5 23:56:15 host kernel: [1082356.857652] sysrq: Manual OOM execution")
            .unwrap()
            .unwrap();
    assert_eq!(
        record.timestamp,
        Some(jiff::SignedDuration::new(1082356, 857652000))
    );
    assert_eq!(
        record.wall_time,
        Some(WallTime::Syslog {
            month: 9,
            day: 5,
            time: jiff::civil::time(23, 56, 15, 0)
        })
    );
    for prefix in [
        "2026-09-18T12:34:56.123Z host kernel: ",
        "2026-09-18T08:34:56.123-04:00 ",
        "<4>2026-09-18T12:34:56.123Z ",
    ] {
        let record = parse_line(format!("{prefix}sysrq: Manual OOM execution"))
            .unwrap()
            .unwrap_or_else(|| panic!("unparsed prefix: {prefix}"));
        assert_eq!(
            record.wall_time,
            Some(WallTime::Instant(
                "2026-09-18T12:34:56.123Z".parse().unwrap()
            ))
        );
        assert_eq!(record.timestamp, None);
    }
    for prefix in [
        "[Fri Sep 18 12:34:56 2026] ",
        "2026-09-18 12:34:56 ",
        "[2026-09-18T12:34:56] ",
    ] {
        let record = parse_line(format!("{prefix}sysrq: Manual OOM execution"))
            .unwrap()
            .unwrap_or_else(|| panic!("unparsed prefix: {prefix}"));
        assert_eq!(
            record.wall_time,
            Some(WallTime::Local("2026-09-18T12:34:56".parse().unwrap()))
        );
    }
}

#[test]
fn byte_sizes_convert_without_overflow_or_page_assumptions() {
    let line =
        "Out of memory: Killed process 42 (worker) total-vm:1024kB, anon-rss:512kB, file-rss:0kB";
    let OomMessage::Killed(killed) = parse_line(line).unwrap().unwrap().message else {
        panic!()
    };
    assert_eq!(killed.memory.total_vm, Some(ByteSize::mib(1)));
    assert!(parse_line(line.replace("1024kB", "18446744073709551615kB")).is_err());
    assert!(parse_line("Node 0 Normal free:18446744073709551615kB").is_err());
    assert!(parse_line("[18446744073709551615.1] sysrq: Manual OOM execution").is_err());
    let OomMessage::Allocation(a) = parse_line("0.01 KiB 1 source.c:2 func:allocate")
        .unwrap()
        .unwrap()
        .message
    else {
        panic!()
    };
    assert_eq!(a.size.bytes, ByteSize::b(10));
}
