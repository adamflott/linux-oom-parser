#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "fail the test when setup or assertions encounter an unexpected value"
)]

use linux_oom_parser::{GfpFlag, OomMessage, parse};

#[test]
fn parses_nixos_linux_6_18_dmesg() {
    // Use the original capture, including its unterminated final line.
    let records = parse(include_str!("../examples/nixos-linux-6.18.log"))
        .expect("the NixOS Linux 6.18 capture should parse successfully");

    assert_eq!(
        records.len(),
        126,
        "every source line should be represented"
    );
    for (index, record) in records.iter().enumerate() {
        assert_eq!(record.line_number, index + 1);
    }

    let invocation = &records[1];
    assert_eq!(invocation.line_number, 2);
    assert_eq!(invocation.prefix, "[77541.814161] ");
    let OomMessage::Invoked(task) = &invocation.message else {
        panic!("expected an invocation, got {:?}", invocation.message);
    };
    assert_eq!(task.name, "kworker/13:1");
    assert_eq!(task.gfp_mask, 0xcc0);
    assert_eq!(
        task.gfp_flags.as_deref(),
        Some([GfpFlag::Kernel].as_slice())
    );
    assert_eq!(task.order, -1);
    assert_eq!(task.oom_score_adj, 0);

    let kill = &records[125];
    assert_eq!(kill.line_number, 126);
    assert_eq!(kill.prefix, "[77541.815788] ");
    let OomMessage::Killed(process) = &kill.message else {
        panic!("expected a killed process, got {:?}", kill.message);
    };
    assert_eq!(process.pid, 55817);
    assert_eq!(process.name, "stress");
    assert_eq!(process.uid, Some(0));
    assert_eq!(process.oom_score_adj, Some(1000));
    assert!(!process.memory_cgroup);
    assert_eq!(process.memory.total_vm, Some(bytesize::ByteSize::kib(3676)));
    assert_eq!(process.memory.anon_rss, Some(bytesize::ByteSize::kib(0)));
    assert_eq!(process.memory.file_rss, Some(bytesize::ByteSize::kib(2248)));
    assert_eq!(process.memory.shmem_rss, Some(bytesize::ByteSize::kib(0)));
    assert_eq!(
        process.memory.page_tables,
        Some(bytesize::ByteSize::kib(48))
    );
}

#[test]
fn captures_every_diagnostic_section_with_typed_values() {
    use jiff::SignedDuration as Duration;
    use linux_oom_parser::*;
    let log = include_str!("../examples/nixos-linux-6.18.log");
    let records = parse(log).unwrap();
    assert_eq!(records.len(), log.lines().count());
    // The absence of a catch-all text variant makes this a coverage assertion:
    // every line must have the appropriate structured representation.
    for r in &records {
        let correct_kind = match r.line_number {
            1 => matches!(r.message, OomMessage::ManualOom),
            2 => matches!(r.message, OomMessage::Invoked(_)),
            3 => matches!(r.message, OomMessage::CpuContext(_)),
            4 => matches!(r.message, OomMessage::TaintDescriptions(_)),
            5 => matches!(r.message, OomMessage::Hardware(_)),
            6 => matches!(r.message, OomMessage::Workqueue(_)),
            7 | 26 | 56 | 67 => matches!(r.message, OomMessage::Section(_)),
            8 | 25 => matches!(r.message, OomMessage::StackBoundary(_)),
            9..=24 => matches!(r.message, OomMessage::StackFrame(_)),
            27..=34 => matches!(r.message, OomMessage::MemoryCounters(_)),
            35 | 36 | 38 | 40 => matches!(r.message, OomMessage::NodeMemory(_)),
            37 | 39 | 41 => matches!(r.message, OomMessage::LowmemReserves(_)),
            42..=44 => matches!(r.message, OomMessage::BuddyInfo(_)),
            45 | 46 => matches!(r.message, OomMessage::HugePages(_)),
            47..=55 => matches!(r.message, OomMessage::MemoryTotal(_)),
            57..=66 => matches!(r.message, OomMessage::Allocation(_)),
            68 => matches!(r.message, OomMessage::TaskColumns(_)),
            69..=124 => matches!(r.message, OomMessage::Task(_)),
            125 => matches!(r.message, OomMessage::OomContext(_)),
            126 => matches!(r.message, OomMessage::Killed(_)),
            _ => false,
        };
        assert!(correct_kind, "unexpected record: {r:?}");
        assert_eq!(r.timestamp.is_none(), (28..=34).contains(&r.line_number));
    }
    assert_eq!(records[0].timestamp, Some(Duration::new(77541, 813863000)));
    assert_eq!(
        records[125].timestamp,
        Some(Duration::new(77541, 815788000))
    );

    let OomMessage::CpuContext(cpu) = &records[2].message else {
        panic!()
    };
    assert_eq!((cpu.cpu, cpu.uid, cpu.pid), (13, Some(0), 194));
    assert_eq!(cpu.command, "kworker/13:1");
    assert_eq!(
        cpu.taints,
        [TaintFlag::ProprietaryModule, TaintFlag::OutOfTreeModule]
    );
    assert_eq!(cpu.kernel_release, "6.18.52");
    assert_eq!(cpu.kernel_build, "#1-NixOS");
    assert_eq!(cpu.preemption, Some(Preemption::Lazy));
    assert!(cpu.build_flags.is_empty());
    let OomMessage::TaintDescriptions(taints) = &records[3].message else {
        panic!()
    };
    assert_eq!(taints.len(), 2);
    assert_eq!(taints[0].flag, TaintFlag::ProprietaryModule);
    assert_eq!(taints[0].identifier, "PROPRIETARY_MODULE");
    assert_eq!(taints[1].flag, TaintFlag::OutOfTreeModule);
    assert_eq!(taints[1].identifier, "OOT_MODULE");
    let OomMessage::Hardware(hardware) = &records[4].message else {
        panic!()
    };
    assert_eq!(
        hardware.name,
        "System manufacturer System Product Name/PRIME X570-PRO"
    );
    assert_eq!(hardware.bios_version, "5044");
    assert_eq!(hardware.bios_date, "01/04/2026");
    let OomMessage::Workqueue(queue) = &records[5].message else {
        panic!()
    };
    assert_eq!(queue.name, "events");
    assert_eq!(queue.function, "moom_callback");
    assert_eq!(records[6].message, OomMessage::Section(Section::CallTrace));
    assert_eq!(
        records[7].message,
        OomMessage::StackBoundary(StackBoundary::TaskStart)
    );
    assert_eq!(
        records[24].message,
        OomMessage::StackBoundary(StackBoundary::TaskEnd)
    );
    assert_eq!(
        records[25].message,
        OomMessage::Section(Section::MemoryInfo)
    );
    assert_eq!(
        records[55].message,
        OomMessage::Section(Section::Allocations { enabled: true })
    );
    assert_eq!(records[66].message, OomMessage::Section(Section::Tasks));

    let frames: Vec<_> = records
        .iter()
        .filter_map(|r| {
            if let OomMessage::StackFrame(f) = &r.message {
                Some(f)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(frames.len(), 16);
    assert_eq!(frames[0].symbol, "dump_stack_lvl");
    assert_eq!(
        (frames[0].offset, frames[0].size, frames[0].uncertain),
        (
            bytesize::ByteSize::b(0x5d),
            bytesize::ByteSize::b(0x80),
            false
        )
    );
    assert_eq!(frames[7].symbol, "__pfx_worker_thread");
    assert!(frames[7].uncertain);
    assert_eq!(frames.iter().filter(|f| f.uncertain).count(), 6);
    assert!(frames.iter().all(|f| f.module.is_none()));

    let globals: Vec<_> = records
        .iter()
        .filter_map(|r| {
            if let OomMessage::MemoryCounters(c) = &r.message {
                Some(c)
            } else {
                None
            }
        })
        .flatten()
        .collect();
    assert_eq!(globals.len(), 20);
    let global = |metric| {
        globals
            .iter()
            .find(|c| c.metric == metric)
            .unwrap()
            .value
            .clone()
    };
    assert_eq!(global(MemoryMetric::ActiveAnon), MemoryValue::Pages(310908));
    assert_eq!(global(MemoryMetric::Free), MemoryValue::Pages(15064645));
    assert_eq!(global(MemoryMetric::SecPagetables), MemoryValue::Pages(915));
    assert_eq!(global(MemoryMetric::Dirty), MemoryValue::Pages(90));
    assert_eq!(
        global(MemoryMetric::SlabUnreclaimable),
        MemoryValue::Pages(59490)
    );
    assert!(
        globals
            .iter()
            .all(|c| matches!(c.value, MemoryValue::Pages(_)))
    );

    let OomMessage::NodeMemory(node) = &records[34].message else {
        panic!()
    };
    assert_eq!(node.node, 0);
    assert_eq!(node.zone, None);
    assert_eq!(node.counters.len(), 19);
    assert_eq!(
        node.counters[0].value,
        MemoryValue::Bytes(bytesize::ByteSize::kib(1243632))
    );
    assert_eq!(node.counters[17].metric, MemoryMetric::AllUnreclaimable);
    assert_eq!(node.counters[17].value, MemoryValue::State(false));
    for (index, zone, free, min) in [
        (35, MemoryZone::Dma, 11260, 12),
        (37, MemoryZone::Dma32, 3236244, 3308),
        (39, MemoryZone::Normal, 57011076, 64256),
    ] {
        let OomMessage::NodeMemory(node) = &records[index].message else {
            panic!()
        };
        assert_eq!(node.node, 0);
        assert_eq!(node.zone, Some(zone));
        assert_eq!(node.counters.len(), 21);
        assert_eq!(
            node.counters[0].value,
            MemoryValue::Bytes(bytesize::ByteSize::kib(free))
        );
        assert_eq!(node.counters[2].metric, MemoryMetric::Min);
        assert_eq!(
            node.counters[2].value,
            MemoryValue::Bytes(bytesize::ByteSize::kib(min))
        );
        assert!(
            node.counters
                .iter()
                .all(|c| matches!(c.value, MemoryValue::Bytes(_)))
        );
    }
    assert_eq!(
        records[36].message,
        OomMessage::LowmemReserves(vec![0, 3168, 64195, 64195, 64195])
    );
    assert_eq!(
        records[38].message,
        OomMessage::LowmemReserves(vec![0, 0, 61027, 61027, 61027])
    );
    assert_eq!(records[40].message, OomMessage::LowmemReserves(vec![0; 5]));
    for (index, total) in [(41, 11260), (42, 3236244), (43, 57011396)] {
        let OomMessage::BuddyInfo(buddy) = &records[index].message else {
            panic!()
        };
        assert_eq!(buddy.node, 0);
        assert_eq!(buddy.blocks.len(), 11);
        assert_eq!(buddy.total, bytesize::ByteSize::kib(total));
        assert_eq!(buddy.blocks[0].size, bytesize::ByteSize::kib(4));
        assert_eq!(buddy.blocks[10].size, bytesize::ByteSize::kib(4096));
    }
    let OomMessage::BuddyInfo(buddy) = &records[43].message else {
        panic!()
    };
    assert_eq!(buddy.zone, MemoryZone::Normal);
    assert_eq!(buddy.blocks[0].count, 1979);
    assert_eq!(
        buddy.blocks[0].migration_types,
        [MigrationType::Movable, MigrationType::Reclaimable]
    );
    assert_eq!(buddy.blocks[10].count, 13669);
    for (index, size) in [(44, 1048576), (45, 2048)] {
        let OomMessage::HugePages(huge) = &records[index].message else {
            panic!()
        };
        assert_eq!(
            (huge.node, huge.total, huge.free, huge.surplus, huge.size),
            (0, 0, 0, 0, bytesize::ByteSize::kib(size))
        );
    }
    for (index, kind, value) in [
        (46, TotalKind::PageCache, MemoryValue::Pages(518968)),
        (47, TotalKind::SwapCache, MemoryValue::Pages(0)),
        (
            48,
            TotalKind::FreeSwap,
            MemoryValue::Bytes(bytesize::ByteSize::kib(9227468)),
        ),
        (
            49,
            TotalKind::TotalSwap,
            MemoryValue::Bytes(bytesize::ByteSize::kib(9227468)),
        ),
        (50, TotalKind::Ram, MemoryValue::Pages(16753710)),
        (51, TotalKind::HighMemMovable, MemoryValue::Pages(0)),
        (52, TotalKind::Reserved, MemoryValue::Pages(315705)),
        (53, TotalKind::CmaReserved, MemoryValue::Pages(0)),
        (54, TotalKind::HardwarePoisoned, MemoryValue::Pages(0)),
    ] {
        let OomMessage::MemoryTotal(total) = &records[index].message else {
            panic!()
        };
        assert_eq!(total.kind, kind);
        assert_eq!(total.value, value);
    }
    let OomMessage::Allocation(allocation) = &records[56].message else {
        panic!()
    };
    assert_eq!(
        (allocation.size.mantissa, allocation.size.decimal_places),
        (121, 2)
    );
    assert_eq!(allocation.size.unit, SizeUnit::GiB);
    assert_eq!(allocation.count, 237476);
    assert_eq!(allocation.file, "mm/readahead.c");
    assert_eq!(allocation.line, 189);
    assert_eq!(allocation.function, "ractl_alloc_folio");
    assert_eq!(allocation.module, None);
    let OomMessage::Allocation(allocation) = &records[63].message else {
        panic!()
    };
    assert_eq!(allocation.module.as_deref(), Some("spl_kmem"));
    assert_eq!(
        allocation.file,
        "/build/source/module/os/linux/spl/spl-kmem.c"
    );
    assert_eq!(
        (allocation.size.mantissa, allocation.size.decimal_places),
        (721, 1)
    );
    assert_eq!(allocation.size.unit, SizeUnit::MiB);

    let OomMessage::TaskColumns(columns) = &records[67].message else {
        panic!()
    };
    assert_eq!(
        columns,
        &[
            TaskColumn::Pid,
            TaskColumn::Uid,
            TaskColumn::Tgid,
            TaskColumn::TotalVm,
            TaskColumn::Rss,
            TaskColumn::RssAnon,
            TaskColumn::RssFile,
            TaskColumn::RssShmem,
            TaskColumn::PageTablesBytes,
            TaskColumn::SwapEntries,
            TaskColumn::OomScoreAdj,
            TaskColumn::Name
        ]
    );
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
    assert_eq!(tasks.len(), 56);
    let jellyfin = tasks.iter().find(|t| t.pid == 2154).unwrap();
    assert_eq!((jellyfin.uid, jellyfin.tgid), (988, 2154));
    assert_eq!(jellyfin.total_vm_pages, 68895385);
    assert_eq!(jellyfin.rss_pages, 129402);
    assert_eq!(jellyfin.rss_anon_pages, Some(82237));
    assert_eq!(jellyfin.rss_file_pages, Some(29027));
    assert_eq!(jellyfin.rss_shmem_pages, Some(18138));
    assert_eq!(jellyfin.page_tables, Some(bytesize::ByteSize::b(1736704)));
    assert_eq!(jellyfin.swap_entries, 0);
    assert_eq!(jellyfin.oom_score_adj, 0);
    assert_eq!(jellyfin.name, "jellyfin");
    assert_eq!(tasks[0].oom_score_adj, -250);
    assert_eq!(
        tasks.iter().find(|t| t.pid == 50713).unwrap().name,
        "(sd-pam)"
    );
    assert_eq!(
        tasks.iter().find(|t| t.pid == 55817).unwrap().oom_score_adj,
        1000
    );
    let OomMessage::OomContext(context) = &records[124].message else {
        panic!()
    };
    assert_eq!(context.constraint, Constraint::None);
    assert_eq!(context.nodemask, None);
    assert_eq!(context.cpuset, "/");
    assert_eq!(context.mems_allowed.len(), 1);
    assert_eq!(
        (context.mems_allowed[0].start, context.mems_allowed[0].end),
        (0, 0)
    );
    assert_eq!(context.scope, OomScope::Global);
    assert_eq!(
        context.task_memcg,
        "/user.slice/user-1000.slice/session-80.scope"
    );
    assert_eq!(context.task, "stress");
    assert_eq!((context.pid, context.uid), (55817, 0));
}
