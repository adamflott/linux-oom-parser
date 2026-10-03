#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "fail the test when setup or assertions encounter an unexpected value"
)]

use linux_oom_parser::*;

const LOG: &str = include_str!("../examples/prod-multiple-ooms.log");
// Independently identified invocation-to-kill boundaries in the source capture.
const EVENTS: [(usize, usize, u32); 22] = [
    (3306, 3485, 13289),
    (3486, 3650, 1402549),
    (3651, 3815, 1403081),
    (3816, 3990, 1403651),
    (3991, 4170, 1404235),
    (4171, 4343, 1404601),
    (4344, 4512, 1405038),
    (4513, 4680, 1405562),
    (4681, 4848, 1406014),
    (4849, 5016, 1406629),
    (5017, 5226, 1407130),
    (5227, 5393, 1407649),
    (5394, 5558, 1408215),
    (6986, 7188, 1408703),
    (7204, 7372, 1409391),
    (11971, 12147, 15376),
    (17713, 17883, 12629),
    (18251, 18418, 3474973),
    (18426, 18595, 1173316),
    (18621, 18794, 2313456),
    (18814, 18984, 3946437),
    (20061, 20229, 15217),
];

#[test]
fn captures_all_22_ooms_and_nothing_outside_their_diagnostics() {
    assert_eq!(LOG.lines().count(), 30541);
    let events = parse_events(LOG).unwrap();
    assert_eq!(events.len(), 22);
    for (event, &(start, end, pid)) in events.iter().zip(&EVENTS) {
        assert_eq!(event.records[0].line_number, start);
        assert!(matches!(event.records[0].message, OomMessage::Invoked(_)));
        let kills: Vec<_> = event
            .records
            .iter()
            .filter_map(|r| match &r.message {
                OomMessage::Killed(k) => Some((r.line_number, k)),
                _ => None,
            })
            .collect();
        assert_eq!(kills.len(), 1);
        assert_eq!((kills[0].0, kills[0].1.pid), (end, pid));
        assert_eq!(
            event
                .records
                .iter()
                .filter(|r| matches!(r.message, OomMessage::CpuContext(_)))
                .count(),
            1
        );
        // Every line in each OOM dump is typed, including RIP/Code/registers.
        let expected: Vec<_> = (start..=end)
            .chain(if pid == 15376 { Some(12238) } else { None })
            .collect();
        assert_eq!(
            event
                .records
                .iter()
                .map(|r| r.line_number)
                .collect::<Vec<_>>(),
            expected
        );
    }
    let records = parse(LOG).unwrap();
    let expected: Vec<_> = (1..=30541)
        .filter(|line| {
            *line == 12238
                || EVENTS
                    .iter()
                    .any(|(start, end, _)| (start..=end).contains(&line))
        })
        .collect();
    assert_eq!(
        records.iter().map(|r| r.line_number).collect::<Vec<_>>(),
        expected
    );
    // Allocation failures and the trip2 warning also contain CPU/stack/memory
    // dumps. They must not leak into OOM records.
    assert!(
        records
            .iter()
            .all(|r| !(7373..11971).contains(&r.line_number))
    );
    assert!(
        records
            .iter()
            .all(|r| !(12148..12238).contains(&r.line_number))
    );
}

#[test]
fn older_task_columns_and_memory_counters_retain_correct_units() {
    let events = parse_events(LOG).unwrap();
    let records = &events[0].records;
    let header = records
        .iter()
        .find_map(|r| {
            if let OomMessage::TaskColumns(c) = &r.message {
                Some(c)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(header.len(), 9);
    assert!(!header.contains(&TaskColumn::RssAnon));
    let tasks: Vec<_> = records
        .iter()
        .filter_map(|r| {
            if let OomMessage::Task(t) = &r.message {
                Some(t)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(tasks.len(), 104);
    let t = tasks[0];
    assert_eq!((t.pid, t.uid, t.tgid), (1725, 0, 1725));
    assert_eq!((t.total_vm_pages, t.rss_pages), (18329, 538));
    assert_eq!(
        (t.page_tables, t.swap_entries, t.oom_score_adj),
        (bytesize::ByteSize::b(155648), 288, -250)
    );
    assert_eq!(t.name, "systemd-journal");
    assert!(tasks.iter().all(|t| t.rss_anon_pages.is_none()
        && t.rss_file_pages.is_none()
        && t.rss_shmem_pages.is_none()));
    let node = records
        .iter()
        .find_map(|r| match &r.message {
            OomMessage::NodeMemory(n) if n.zone.is_none() => Some(n),
            _ => None,
        })
        .unwrap();
    let temporary = node
        .counters
        .iter()
        .find(|c| c.metric == MemoryMetric::WritebackTmp)
        .unwrap();
    assert_eq!(
        temporary.value,
        MemoryValue::Bytes(bytesize::ByteSize::kib(0))
    );
    let cpu = records
        .iter()
        .find_map(|r| {
            if let OomMessage::CpuContext(c) = &r.message {
                Some(c)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(cpu.uid, None);
    assert_eq!(cpu.pid, 71765);
    assert_eq!(cpu.kernel_release, "6.6.63-6.6.0.4-amd64-866326b08df73f16");
    assert_eq!(cpu.taints, [TaintFlag::OutOfTreeModule]);
}

#[test]
fn instruction_bytes_registers_and_delayed_reaper_are_typed() {
    let events = parse_events(LOG).unwrap();
    let record = |line| {
        events
            .iter()
            .flat_map(|e| &e.records)
            .find(|r| r.line_number == line)
            .unwrap()
    };
    let OomMessage::InstructionPointer(rip) = &record(3340).message else {
        panic!()
    };
    assert_eq!(rip.segment, 0x33);
    assert_eq!(rip.location, InstructionLocation::Address(0x7f796a114abf));
    let OomMessage::InstructionCode(InstructionCode::Bytes {
        bytes,
        instruction_index,
    }) = &record(3341).message
    else {
        panic!()
    };
    assert_eq!(bytes.len(), 64);
    assert_eq!(*instruction_index, Some(42));
    assert_eq!(bytes[42], 0x48);
    let OomMessage::Registers(registers) = &record(3342).message else {
        panic!()
    };
    assert_eq!(registers.len(), 3);
    assert_eq!(registers[0].register, Register::Rsp);
    assert_eq!(registers[0].segment, Some(0x2b));
    assert_eq!(registers[0].value, 0x7f4150a05540);
    assert_eq!(registers[1].register, Register::Eflags);
    assert_eq!(registers[1].value, 0x293);
    assert_eq!(registers[2].register, Register::OrigRax);
    let OomMessage::Registers(registers) = &record(3343).message else {
        panic!()
    };
    assert_eq!(registers[0].value, 0xffffffffffffffda);
    assert_eq!(
        record(11992).message,
        OomMessage::InstructionCode(InstructionCode::Unavailable(0x7fecf83912dd))
    );
    let OomMessage::Reaped(reaper) = &events[15].records.last().unwrap().message else {
        panic!()
    };
    assert_eq!(reaper.pid, 15376);
    assert_eq!(reaper.memory.file_rss, Some(bytesize::ByteSize::kib(66624)));
}
