# linux-oom-parser

A self-contained Rust library for extracting typed Linux OOM killer messages
from text logs, using [winnow](https://docs.rs/winnow/) parsers. No runtime
services, Linux-only APIs, or external commands are required.

**AI disclosure:** This library was written with assistance from OpenAI Codex,
powered by GPT-6.

```toml
[dependencies]
linux-oom-parser = "0.1"
```

```rust
use linux_oom_parser::{parse, OomMessage};

let log = "Out of memory: Killed process 42 (worker) total-vm:1024kB, anon-rss:512kB, file-rss:0kB";
let records = parse(log).expect("valid OOM log");
for record in records {
    if let OomMessage::Killed(process) = record.message {
        println!("Killed {} ({})", process.pid, process.name);
    }
}
```

`parse`, `parse_events`, `parse_line`, and `parse_task_line` accept `impl AsRef<str>`: `&str`, `String`, `&String`,
`Box<str>`, `Cow<str>`, and `Arc<str>`, among others. Returned records own their
strings. Byte inputs must first be decoded to UTF-8 by the caller.

## Analyze why OOMs happened

```sh
cargo run --bin oom-analyze -- examples/prod-6.12.log
# After cargo install --path .:
oom-analyze examples/prod-multiple-ooms.log
oom-analyze --verbose examples/prod-multiple-ooms.log
dmesg | oom-analyze -
```

`oom-analyze` reports each event's trigger, source-line evidence, possible
contributors, and prevention/verification steps. It distinguishes manual SysRq,
cgroup limits, cpuset/NUMA policy restrictions, global allocation failures,
and unknown or incomplete events. It inspects allocation order, swap totals,
zone free/minimum counters, victim memory, and the three largest task-table RSS
values. The default report leads with the outcome, explains the request in plain
language, shows the largest processes in a table, and numbers the next steps.
Source references follow observations, and uncertainty is summarized in the
interpretation notes.

Every displayed memory quantity includes a human-readable IEC size. Add
`--verbose` for exact byte counts, original task page counts, OOM score
adjustments, allocation flags, and cpuset/node details. Both modes retain source
references. Flags use kernel names such as `GFP_HIGHUSER_MOVABLE | __GFP_COMP`,
not Rust enum/debug output. Options may appear before or after the input path;
use `--` before a filename beginning with a dash.
The default base page size is **4 KiB**, explicitly stated in each report; for
other source machines use `oom-analyze --page-size 65536 LOG` (64 KiB pages),
or another positive byte count. The source page size is not inferred from the
analysis host. Shared RSS is not summed across tasks. The tool reads logs only; it does not inspect or
change the running machine.

The NixOS 6.18 fixture is correctly classified as a **manual OOM request**,
not evidence that RAM was exhausted. The production captures produce individual
reports for every parsed OOM. Reports retain the parser's conservative event
boundaries; missing or interleaved lines can limit the analysis.

Possible causes are explicitly hypotheses. A snapshot cannot prove a leak,
attribute earlier growth, or establish that the killed process caused the OOM.
A positive allocation order alone does not prove fragmentation. Recommendations
are conditional on the captured scope and evidence; no blanket VM tuning or
`oom_score_adj` adjustment is proposed as a capacity fix.

The same analysis is available to library consumers:

```rust
use linux_oom_parser::{analyze_event, parse_events, format_event_analysis, AnalysisOptions};
let log = "[1.234] sysrq: Manual OOM execution\n";
for event in parse_events(log).unwrap() {
    let report = analyze_event(&event);
    // For a different page size, use analyze_event_with_options and AnalysisOptions.
    // Match the human-facing CLI report (true enables verbose output):
    println!("{}", format_event_analysis(&event, AnalysisOptions::default(), false));
    // report.reason, evidence, possible_causes, recommendations, limitations
}
```

`analyze_event` still returns the reusable findings, and its `Display` retains
the detailed evidence-oriented format. `format_event_analysis` provides the new
human-facing layout.

`--help` prints usage. Empty/unrelated input reports zero events and succeeds;
I/O and parsing errors return a nonzero exit status. The complete input is
parsed before reports are printed.

The interpretation rules follow the kernel documentation for
[SysRq](https://docs.kernel.org/admin-guide/sysrq.html),
[cgroup memory limits](https://www.kernel.org/doc/html/v6.7/admin-guide/cgroup-v2.html),
and [OOM allocation constraints](https://kernel.org/doc/html/v6.10/admin-guide/sysctl/vm.html).

## Split logs into individual files

Install the user-facing tool locally:

```sh
cargo install --path .
oom-split examples/prod-multiple-ooms.log ./oom-events
# Or read stdin:
dmesg | oom-split - ./dmesg-events
# Without installing:
cargo run --bin oom-split -- examples/prod-6.12.log ./production-events
```

The tool writes `oom-000001.log`, `oom-000002.log`, and so on. The output
folder must not already exist; files are never overwritten. Its parent must
exist. All input is parsed before output begins, so a parse error creates no
files. I/O failures during writing may leave partial output. Empty logs create
an empty directory. Input must be UTF-8. `oom-split --help` shows usage.

Each file contains an event's original OOM records, including any matched delayed
reaper. Unrelated lines are excluded, and incomplete events are retained using
the boundary rules below.

## Lossless output and timestamps

`Record` and `OomEvent` implement `Display` and therefore `to_string()`:

```rust
use linux_oom_parser::parse_events;
let source = "[1.234] sysrq: Manual OOM execution\r\n";
let events = parse_events(source).unwrap();
assert_eq!(events[0].to_string(), source);
```

Printing reproduces the **original source snapshot**, preserving spacing,
prefixes, decimal precision, LF/CRLF, and missing final newlines. Typed fields
remain available for analysis. Changing those public fields does not change
printed text; this is lossless extraction, not an editor or a formatter for
newly constructed messages. Record equality includes the source snapshot.
The 126-line `examples/nixos-linux-6.18.log` fixture is tested byte-for-byte
through parse → print → parse (this is the existing 6.18 fixture filename).

`Record::timestamp` is a Jiff `SignedDuration` for time since boot.
`Record::wall_time` is independent: a prefix may contain both. `WallTime` holds
an offset-aware Jiff `Timestamp`, a timezone-free Jiff civil `DateTime`, or a
traditional syslog month/day plus Jiff civil `Time`. A missing syslog year or
timezone is never inferred. ISO date/time prefixes, syslog prefixes containing
`kernel:`, and bracketed `dmesg -T` dates are supported. Unrecognized calendar
prefixes remain available as raw prefix text; continuation lines inherit no time.

## Supported formats

- Global and memory-cgroup `Killed process` messages, including older messages
  without shared-memory, UID, page-table, or OOM score fields.
- `invoked oom-killer` messages with hexadecimal GFP masks, optional symbolic
  flags, allocation order, and OOM score adjustment.
- Successful `oom_reaper: reaped process` messages.
- Manual SysRq OOM requests; CPU/task context, kernel release/build/preemption,
  taint flags and descriptions; hardware/BIOS identity and workqueue callbacks.
- Stack section boundaries and frames with symbol, offset, size, uncertainty,
  and optional module; x86-64 instruction pointers, opcode bytes, and registers.
- Global memory counters and their continuation lines; NUMA node/zone counters,
  low-memory reserves, buddy allocator buckets with migration types, hugepage
  pools, page totals and swap totals.
- Allocation profiling with source path/line, module, function, allocation count,
  and the printed decimal size.
- Linux 6.6 and 6.18 task table columns and rows, plus OOM constraint/victim summaries
  with typed NUMA node ranges and global or memory-cgroup scope.
- Bare messages, numeric dmesg timestamps, priority tags, and text syslog or
  journal prefixes containing `kernel:`. Prefix text is preserved verbatim, and
  numeric dmesg timestamps are decoded into `Option<jiff::SignedDuration>`.
  Calendar timestamps are decoded independently into `Record::wall_time`.
- LF and CRLF logs, multiple messages, and unrelated lines.

Each captured OOM source line produces one `Record`. Its `OomMessage` variant
holds a dedicated struct or enum, not a raw diagnostic string. The NixOS fixture
produces **126 typed records from 126 lines**, including all 56 task rows.
Untimestamped continuation lines have `timestamp: None`; records do not inherit
timestamps from adjacent lines.

Memory data retains its units: `MemoryValue::Pages`, `MemoryValue::Bytes`, or
`MemoryValue::State` for boolean fields. Task fields distinguish page counts
from `page_tables`. All memory sizes use `bytesize::ByteSize`, re-exported as
`linux_oom_parser::ByteSize`; kernel kB/KB values are multiplied by 1024 with
overflow checking. Kill/reaper fields now use names such as `anon_rss` and
`total_vm` instead of the former `_kib` names. Stack offsets and symbol lengths
also use `ByteSize`. Register values, addresses, and opcode bytes retain their
integer types because they are values rather than sizes. `Task::rss_anon_pages`,
`rss_file_pages`, and `rss_shmem_pages` are now `Option<u64>`: absent on Linux 6.6,
`Some` on Linux 6.18. Table headers choose the layout rather than kernel version
strings, so backported formats work as well. No machine page size is
assumed. Allocation sizes preserve the printed decimal exactly as a mantissa,
decimal-place count, and unit (e.g. 1.21 GiB is `121`, `2`, `GiB`); these kernel
measurements are rounded. `ReportedSize::bytes` provides the printed magnitude
converted to `ByteSize`, rounded down to a whole byte, without implying that
the original measurement was exact.

`Invocation::gfp_flags` is now `Option<Vec<GfpFlag>>`, replacing `Option<String>`.
It decodes allocation classes such as `GfpFlag::Kernel` and modifiers such as
`GfpFlag::FlagComp`. `gfp_mask` retains the original numeric mask. Symbolic flags
are authoritative: the library does not infer version/configuration-dependent
bit meanings when the kernel omits their names. Unknown symbolic flags or
hexadecimal remnants have explicit `Unknown`/`UnknownBits` variants.

`CpuContext::taints` decodes the kernel's taint letters, including `P` as
`ProprietaryModule` and `O` as `OutOfTreeModule`; `G` and spaces do not indicate
taint. Future letters are retained as `TaintFlag::Unknown`.

```rust
use linux_oom_parser::{parse_line, OomMessage, TaintFlag};

let log = "CPU: 13 UID: 0 PID: 194 Comm: kworker/13:1 Tainted: P           O        6.18.52 #1-NixOS PREEMPT(lazy)";
if let Some(record) = parse_line(log).expect("valid diagnostic") {
    if let OomMessage::CpuContext(cpu) = record.message {
        assert!(cpu.taints.contains(&TaintFlag::OutOfTreeModule));
        println!("Kernel {} on CPU {}", cpu.kernel_release, cpu.cpu);
    }
}
```

## Continuous logs and multiple OOMs

Use `parse_events` to group OOMs, or `parse` for the same records flattened into
original source order. Both exclude unrelated boot messages, networking chatter,
allocation-failure dumps and warning stacks outside OOM regions.

```rust
use linux_oom_parser::{parse_events, OomMessage};

let log = std::fs::read_to_string("examples/prod-multiple-ooms.log")
    .expect("read kernel log");
for event in parse_events(log).expect("valid OOM records") {
    for record in event.records {
        if let OomMessage::Killed(victim) = record.message {
            println!("line {}: killed {} ({})", record.line_number, victim.pid, victim.name);
        }
    }
}
```

An invocation or manual SysRq OOM request opens capture. A kill, new invocation,
reboot banner, or unrecognized line ends it. This conservative boundary rule
avoids collecting unrelated diagnostics after incomplete OOMs. It also means an
unrecognized or interleaved message can end diagnostic capture early. OOM-specific
constraint/kill/reaper lines are always retained, even in truncated logs.
Incomplete events are retained; an event does not necessarily contain a kill.

A delayed reaper attaches to the preceding matching victim by PID and name,
provided its timestamp is compatible and no reboot was observed. A boot banner
or backwards uptime jump greater than 60 seconds resets associations. Grouping
uses source order and is not proof of causality; interleaved events without
identifiers and reordered/multi-host logs may require application-level handling.

`parse_line` remains **context-free**: it can parse a CPU or memory diagnostic
without an invocation. Do not loop over it to filter continuous logs, as those
formats also occur outside OOMs. For standalone task rows it infers the layout
from numeric columns. For task names that begin with numeric words, use
`parse_task_line(line, TaskLayout::TotalRss)` or `TaskLayout::RssBreakdown`.
Whole-log parsing uses the actual table header, avoiding this ambiguity.

Malformed supported records inside OOM capture return a `ParseError` with the
original source line number. Unrelated lines outside capture cannot trigger
such errors. Parsing consumes the full message; numeric overflow, truncation,
and unknown trailing fields are rejected. Empty input returns an empty vector.

Coverage is verified against three real captures:

| Fixture | Verified result |
| --- | --- |
| `examples/nixos-linux-6.18.log` | All 126 lines typed, including 56 task rows |
| `examples/prod-multiple-ooms.log` | 22 OOM dumps and one delayed reaper from 30,541 lines; unrelated diagnostic regions excluded |
| `examples/prod-6.12.log` | 191 OOM events and 191 kills across multiple boots; extracted records round-trip |

Tests assert every OOM source line and event boundary in the original two captures, field
values, header-driven layout changes, incomplete events, reboot separation,
reaper matching, malformed data and truncation. This does not guarantee support
for every kernel release. Older `Kill process ... score ...` selection messages,
failed reaper messages, journal JSON and userspace OOM daemons are not supported.
Unrecognized task headers within an OOM region return errors.

Low-memory reserve vectors retain zone order without automatic node attachment.
Names, paths, kernel release/build identifiers and BIOS dates retain their text.
Task names containing a complete message delimiter are inherently ambiguous.

Format references:

- [Linux OOM messages](https://github.com/torvalds/linux/blob/v6.18/mm/oom_kill.c)
- [Linux GFP definitions](https://github.com/torvalds/linux/blob/v6.18/include/linux/gfp_types.h)
- [Kernel taint flags](https://docs.kernel.org/admin-guide/tainted-kernels.html)
- [Memory diagnostic output](https://github.com/torvalds/linux/blob/v6.18/mm/show_mem.c)

## Run and develop

Requires Rust 1.85 or later (edition 2024).

```sh
cargo run --example parse -- examples/nixos-linux-6.18.log
cargo run --example inspect -- examples/nixos-linux-6.18.log
cargo run --example events -- examples/prod-multiple-ooms.log
# Or: dmesg | cargo run --example parse
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo doc --no-deps
cargo package --list
```

Licensed under the MIT license; see [LICENSE](LICENSE).

Cgroup OOM dumps retain `memory`, `memory+swap`, `swap`, and `kmem` usage,
printed limits, and cumulative `failcnt` values. Explicit `Memory cgroup stats
for ...:` blocks keep byte quantities separate from cumulative event counters;
unknown fields retain integers without inferred units. Reports distinguish the
limiting OOM cgroup from the victim's membership path. Unlimited-limit sentinels
are preserved as printed, and failed charges are not interpreted as OOM counts.
