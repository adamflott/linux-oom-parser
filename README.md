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
The CLI and `analyze_event` infer base page size from consistent order-zero buddy
buckets and their doubling sequence, falling back to **4 KiB** when evidence is
missing or inconsistent. Use `oom-analyze --page-size 65536 LOG` to override with
64 KiB pages. `analyze_event_with_options` and `format_event_analysis` honor the
supplied size and report conflicts with buddy evidence. The source page size is
never taken from the analysis host.

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
  without shared-memory, UID, page-table, or OOM score fields, and the
  `Out of memory (oom_kill_allocating_task)` prefix.
- `invoked oom-killer` messages with hexadecimal GFP masks, optional symbolic
  flags, allocation order, and OOM score adjustment.
- Successful `oom_reaper: reaped process` messages.
- Manual SysRq OOM requests; CPU/task context, kernel release/build/preemption,
  taint flags and descriptions; hardware/BIOS identity and workqueue callbacks;
  the kernel's `COMPACTION is disabled!!!` notice.
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
are authoritative. Numeric-only masks are interpreted separately in analysis
using verified upstream layouts; configuration-dependent bits remain unresolved. Unknown symbolic flags or
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

An adjacent `Tasks in ... memory.oom.group set` announcement reopens capture
after the initially selected victim's kill; subsequent group victims stay in
one event. Matched reapers may appear between that kill and the announcement.
New invocations, constraint lines, reboots and unrelated lines end group capture.
Reports identify every captured victim and keep their RSS measurements separate
because shared memory can overlap. An OOM event count is distinct from a victim
count.

A delayed reaper attaches to the preceding matching victim by PID and name,
provided its timestamp is compatible and no reboot was observed. A boot banner
or backwards uptime jump greater than 60 seconds resets associations, including
uptime changes on unrelated lines outside OOM capture. Grouping
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
for every kernel release. Failed reaper messages, journal JSON and userspace
OOM daemons are not supported.
Unrecognized task headers within an OOM region return errors.

Low-memory reserve vectors retain zone order without automatic node attachment.
Names, paths, kernel release/build identifiers and BIOS dates retain their text.
Task names containing a complete message delimiter are inherently ambiguous.
Transport `kernel:` identifiers are recognized as leading fields, optionally
after a timestamp and hostname; occurrences inside names and paths are retained.

Configuration-dependent context is retained without inventing missing fields.
`OomContext::cpuset`, `mems_allowed`, and `task_memcg` are optional: kernels
without `CONFIG_CPUSETS` or `CONFIG_MEMCG` omit these fields. Missing scope
markers use `OomScope::Unknown`; the printed allocation constraint still guides
classification. Missing allowed nodes do not exclude every node from analysis.
`shadow_call_stack` counters and zero GFP masks printed as `gfp_mask=0()` are
also supported.

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

Older kernel compatibility includes invoking-task `cpuset`/`mems_allowed` lines,
invocation `nodemask`, raw stack words and addressed frames, `#012`-escaped
Mem-Info, swap-cache statistics, and `Kill process ... score ...` selection
records. Selection alone does not confirm a kill. Legacy task headers can print
`nr_ptes`, `nr_pmds`, and `nr_puds` in pages: `Task::page_tables` is now
`Option<ByteSize>` (`None` for these headers), and the corresponding
`page_table_pages`, `pmd_table_pages`, and `pud_table_pages` retain page counts.
Use `TaskLayout::Legacy` for standalone rows whose units cannot be inferred.

Four additional OOMAnalyser fixtures (Arch Linux 6.1.1, Proxmox cgroup OOM,
RHEL 7, Ubuntu 21.10 manual OOM) verify complete event capture, typed records,
classification, victim identification, and exact round trips. Their upstream
MIT license and attribution are retained under `tests/fixtures/oomanalyser`.

Numeric-only GFP masks can be decoded with `decode_gfp_mask(mask, release)`.
Verified upstream layouts are 3.10, 4.14, 5.4, 5.10, 5.13, 5.15, 6.1, 6.6,
6.12, and 6.18. Analysis uses the logged CPU header's kernel release and source
lines; parsed invocation flags remain exactly what was printed. Unverified
versions remain undecoded, and conditional extension bits stay `UnknownBits`.
Vendor kernels can backport different layouts, so inferred flags are labeled as
upstream assumptions. Assignments were checked against each release's
`include/linux/gfp.h` or `include/linux/gfp_types.h` in the upstream Linux tree.

Analysis now exposes categorized `Evidence` (`EvidenceKind`) for cgroup budgets,
buddy block availability, page-size checks, watermarks/reserves, memory
composition, and legacy diagnostics. `format_event_analysis` renders these
shared findings, recommendations, and limitations. It reports shortages only
within the printed node restrictions and candidate zones identifiable from
known GFP flags. Zone fallback, migration types, CMA and high-atomic reserves
still prevent a snapshot from proving exact allocation eligibility.

For automation, `OomAnalysis::structured_findings` exposes source lines and typed
`FindingData` for swap shortages, zone watermarks, validated buddy availability,
and cgroup budgets. `StructuredFinding::code()` returns a non-exhaustive
`FindingCode` independent of description wording. Byte measurements use
`ByteSize`; allocation requests and block counts use `u128` to preserve large
values. Other categories remain available as human-readable evidence.

```rust
use linux_oom_parser::{FindingCode, FindingData, analyze_event, parse_events};

let events = parse_events("worker invoked oom-killer: gfp_mask=0xcc0(GFP_KERNEL), order=0, oom_score_adj=0\nFree swap = 0kB\nTotal swap = 1024kB\n")?;
let analysis = analyze_event(&events[0]);
for finding in &analysis.structured_findings {
    if finding.code() == FindingCode::SwapExhausted {
        if let FindingData::Swap { total, .. } = &finding.data {
            println!("Swap exhausted: {} bytes, source lines {:?}", total.as_u64(), finding.lines);
        }
    }
}
# Ok::<(), linux_oom_parser::ParseError>(())
```

Consumers calling the analysis functions retain the existing evidence API.
Consumers constructing `OomAnalysis` with a struct literal must also initialize
the `structured_findings` and `page_size` fields.

`AnalysisOptions::page_size` and inferred page sizes now use validated `PageSize`
values rather than `NonZeroU64`. Construct a size with `PageSize::new(bytes)?`;
sizes must be powers of two of at least 1024 bytes. This validates geometry,
not whether the source machine supports that size. CLI overrides use the same
validation, including when the input contains no events.

`OomAnalysis::page_size` records the selected size, its `PageSizeSource`
(`Explicit`, `Buddy`, or `Fallback`), and `PageSizeEvidence` (`Missing`,
`Consistent`, `Inconsistent`, or `Conflicting`) with source lines. Explicit
options remain explicit even when their size equals 4096 bytes or matches the
buddy evidence. Conflicts retain both the selected and inferred sizes.
`format_event_analysis_auto` renders automatic analysis; `format_event_analysis`
renders explicitly supplied options. CLI override guidance lives in rendering,
while reusable analysis contains no CLI flags.

```rust
use linux_oom_parser::{AnalysisOptions, PageSize};

let options = AnalysisOptions { page_size: PageSize::new(65536)? };
# Ok::<(), linux_oom_parser::InvalidPageSize>(())
```

System Mem-Info categories and task RSS can overlap; reports do not sum them
into a system-used total. Occupied swap is total minus free, with swap cache
shown separately. Missing victim RSS components remain unknown. Reserved,
HighMem/MovableOnly and CMA page totals are labeled rather than added together.
