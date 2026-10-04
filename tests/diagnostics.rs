#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "fail the test when setup or assertions encounter an unexpected value"
)]

use jiff::SignedDuration as Duration;
use linux_oom_parser::*;

fn message(line: &str) -> OomMessage {
    parse_line(line)
        .unwrap()
        .expect("recognized message")
        .message
}

#[test]
fn gfp_classes_modifiers_and_unknown_bits_are_typed() {
    let OomMessage::Invoked(invocation) = message(
        "worker invoked oom-killer: gfp_mask=0x140cca(GFP_HIGHUSER_MOVABLE|__GFP_COMP|__GFP_ZERO|GFP_VENDOR|0x80000000), order=0, oom_score_adj=0",
    ) else {
        panic!()
    };
    assert_eq!(invocation.gfp_mask, 0x140cca);
    assert_eq!(
        invocation.gfp_flags.unwrap(),
        [
            GfpFlag::HighuserMovable,
            GfpFlag::FlagComp,
            GfpFlag::FlagZero,
            GfpFlag::Unknown("GFP_VENDOR".into()),
            GfpFlag::UnknownBits(0x80000000)
        ]
    );
    for flags in [
        "GFP_KERNEL|",
        "|GFP_KERNEL",
        "GFP_KERNEL||__GFP_IO",
        "GFP_KERNEL trailing",
        "0xnothex",
    ] {
        assert!(
            parse_line(format!(
                "worker invoked oom-killer: gfp_mask=0xcc0({flags}), order=0, oom_score_adj=0"
            ))
            .is_err()
        );
    }
}

#[test]
fn taints_decode_known_flags_without_treating_g_as_tainted() {
    let expected = [
        TaintFlag::ProprietaryModule,
        TaintFlag::ForcedModule,
        TaintFlag::OutOfSpecification,
        TaintFlag::ForcedUnload,
        TaintFlag::MachineCheck,
        TaintFlag::BadPage,
        TaintFlag::Userspace,
        TaintFlag::KernelDied,
        TaintFlag::AcpiOverride,
        TaintFlag::Warning,
        TaintFlag::StagingDriver,
        TaintFlag::FirmwareWorkaround,
        TaintFlag::OutOfTreeModule,
        TaintFlag::UnsignedModule,
        TaintFlag::SoftLockup,
        TaintFlag::LivePatch,
        TaintFlag::Auxiliary,
        TaintFlag::Randstruct,
        TaintFlag::Test,
        TaintFlag::FwctlDebug,
    ];
    let OomMessage::CpuContext(cpu) = message(
        "CPU: 0 PID: 1 Comm: worker pool Tainted: PFSRMBUDAWCIOELKXTNJ 6.18.0 #1 SMP PREEMPT PTI",
    ) else {
        panic!()
    };
    assert_eq!(cpu.taints, expected);
    assert_eq!(cpu.command, "worker pool");
    assert_eq!(cpu.uid, None);
    assert_eq!(cpu.preemption, Some(Preemption::Full));
    assert_eq!(cpu.build_flags, ["SMP", "PTI"]);
    for taint_text in ["Not tainted", "Tainted: G                 "] {
        let OomMessage::CpuContext(cpu) = message(&format!(
            "CPU: 1 PID: 2 Comm: worker {taint_text} 6.18.0 #1"
        )) else {
            panic!()
        };
        assert!(cpu.taints.is_empty());
    }
    assert_eq!(TaintFlag::from_code('Z'), Some(TaintFlag::Unknown('Z')));
    assert_eq!(TaintFlag::from_code('G'), None);
}

#[test]
fn timestamps_preserve_fractional_precision_and_do_not_consume_task_pids() {
    for (stamp, nanos) in [
        ("0.000001", 1000),
        ("123.001", 1_000_000),
        ("123.123456789", 123_456_789),
    ] {
        let record = parse_line(format!("[{stamp}] Mem-Info:")).unwrap().unwrap();
        assert_eq!(record.timestamp.unwrap().subsec_nanos(), nanos);
    }
    let record = parse_line("[123.000000] Mem-Info:").unwrap().unwrap();
    assert_eq!(record.timestamp, Some(Duration::from_secs(123)));
    let bare_task = "[ 7] 0 7 100 80 60 20 0 4096 0 -1000 name with spaces";
    let record = parse_line(bare_task).unwrap().unwrap();
    assert_eq!(record.timestamp, None);
    assert_eq!(record.prefix, "");
    let OomMessage::Task(task) = record.message else {
        panic!()
    };
    assert_eq!(task.pid, 7);
    assert_eq!(task.name, "name with spaces");
    for stamp in ["1.1234567890", "1..2", "18446744073709551616.1"] {
        assert!(parse_line(format!("[{stamp}] Mem-Info:")).is_err());
    }
}

#[test]
fn numa_ranges_and_cgroup_context_do_not_split_lists_at_commas() {
    let context = "oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=0-2,4,cpuset=/jobs,mems_allowed=0,2-4,oom_memcg=/jobs/test,task_memcg=/jobs/test/worker,task=worker,pid=10,uid=1000";
    let OomMessage::OomContext(c) = message(context) else {
        panic!()
    };
    assert_eq!(c.constraint, Constraint::MemoryCgroup);
    let mask = c.nodemask.unwrap();
    assert_eq!(
        mask.iter().map(|n| (n.start, n.end)).collect::<Vec<_>>(),
        [(0, 2), (4, 4)]
    );
    assert_eq!(
        c.mems_allowed
            .iter()
            .map(|n| (n.start, n.end))
            .collect::<Vec<_>>(),
        [(0, 0), (2, 4)]
    );
    assert_eq!(c.scope, OomScope::MemoryCgroup("/jobs/test".into()));
    assert_eq!(c.task_memcg, "/jobs/test/worker");
    assert!(parse_line(context.replace("0-2", "2-0")).is_err());
    assert!(parse_line(context.replace("pid=10", "pid=4294967296")).is_err());
}

#[test]
fn allocation_decimals_and_modules_and_frame_modules() {
    let OomMessage::Allocation(a) = message("0.01 KiB 1 path/file.c:12 [mod] func:allocate") else {
        panic!()
    };
    assert_eq!((a.size.mantissa, a.size.decimal_places), (1, 2));
    assert_eq!(a.size.unit, SizeUnit::KiB);
    assert_eq!(a.module.as_deref(), Some("mod"));
    let OomMessage::StackFrame(f) = message("? work+0x0/0x20 [mod]") else {
        panic!()
    };
    assert!(f.uncertain);
    assert_eq!(
        (f.offset, f.size),
        (bytesize::ByteSize::b(0), bytesize::ByteSize::b(32))
    );
    assert_eq!(f.module.as_deref(), Some("mod"));
}

#[test]
fn rejects_malformed_diagnostics_instead_of_silently_skipping() {
    assert!(parse_task_line("[ 1] 0 1 10 10 10 0 0 4096 0", TaskLayout::RssBreakdown).is_err());
    for line in [
        "CPU: 0 PID: 1 Comm: worker Tainted: P",
        "Tainted: [P]=",
        "Hardware name: machine, BIOS 123",
        "Workqueue: events",
        "worker+0xNOTHEX/0x10",
        "active_anon:18446744073709551616",
        "active_anon:1 trailing:2",
        "Node 0 Normal free:1MB",
        "Node 0 Normal: 1*4kB (U) = ",
        "Node 0 hugepages_total=0 hugepages_free=0",
        "lowmem_reserve[]: -1",
        "Free swap = -1kB",
        "1.00 MiB 1 source.c:4294967296 func:allocate",
        "oom-kill:constraint=CONSTRAINT_NONE",
    ] {
        assert!(parse_line(line).is_err(), "should reject {line:?}");
    }
}

#[test]
fn every_fixture_line_parses_independently_and_crlf_is_equivalent() {
    let log = include_str!("../examples/nixos-linux-6.18.log");
    let all = parse(log).unwrap();
    let crlf = parse(log.replace('\n', "\r\n")).unwrap();
    assert_eq!(crlf.len(), all.len());
    for (a, b) in crlf.iter().zip(&all) {
        assert_eq!(a.message, b.message);
        assert_eq!(a.timestamp, b.timestamp);
        assert_eq!(a.wall_time, b.wall_time);
    }
    for (source, expected) in log.lines().zip(all) {
        let record = parse_line(source).unwrap().unwrap();
        assert_eq!(record.message, expected.message);
        assert_eq!(record.timestamp, expected.timestamp);
        assert_eq!(record.prefix, expected.prefix);
    }
}

#[test]
fn truncating_diagnostic_lines_does_not_panic() {
    for line in include_str!("../examples/nixos-linux-6.18.log").lines() {
        for (end, _) in line.char_indices() {
            let _ = parse_line(&line[..end]);
        }
    }
}

#[test]
fn unrelated_text_is_not_a_diagnostic_and_task_names_are_not_stack_frames() {
    for line in [
        "application reports pages in use",
        "application: work+0x10/0x20",
        "application: hello func:world",
    ] {
        assert_eq!(parse_line(line).unwrap(), None);
    }
    let OomMessage::Task(task) = message("[ 7] 0 7 100 80 60 20 0 4096 0 0 worker+0x10") else {
        panic!()
    };
    assert_eq!(task.name, "worker+0x10");
}

#[test]
fn older_counter_spacing_and_multiword_bios() {
    let record = parse_line("Node 0 active_anon:0kB shmem_thp: 0kB anon_thp: 1236992kB")
        .unwrap()
        .unwrap();
    let OomMessage::NodeMemory(node) = record.message else {
        panic!()
    };
    assert_eq!(node.counters.len(), 3);
    let record = parse_line("Hardware name: QEMU, BIOS ArchLinux 1.14.0-1 04/01/2014")
        .unwrap()
        .unwrap();
    let OomMessage::Hardware(hardware) = record.message else {
        panic!()
    };
    assert_eq!(hardware.bios_version, "ArchLinux 1.14.0-1");
    assert_eq!(hardware.bios_date, "04/01/2014");
}
