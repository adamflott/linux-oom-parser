//! Typed parsing of Linux OOM killer messages.
//!
//! [`parse`] extracts supported records from mixed, multiline logs. [`parse_line`]
//! distinguishes unrelated lines (`Ok(None)`) from malformed supported messages.
//! Inputs may be any [`AsRef<str>`], including `&str`, `String`, `Box<str>`, and
//! `Cow<str>`. Results own their strings and do not borrow the input.
//!
//! ```
//! use linux_oom_parser::{parse, OomMessage};
//! let log = "Out of memory: Killed process 42 (worker) total-vm:1024kB, anon-rss:512kB, file-rss:0kB";
//! let records = parse(log)?;
//! if let OomMessage::Killed(process) = &records[0].message {
//!     assert_eq!(process.pid, 42);
//!     assert_eq!(process.memory.anon_rss, Some(bytesize::ByteSize::kib(512)));
//! }
//! # Ok::<(), linux_oom_parser::ParseError>(())
//! ```
//!
//! Supports invocation/kill/reaper messages and the diagnostic formats in the
//! Linux 6.6 and 6.18 fixtures: CPU/taint context, hardware, workqueues, stacks, memory
//! counters, NUMA zones, buddy/hugepage statistics, allocation profiles, task
//! tables and OOM constraints. Each recognized line produces one typed record.
//! Bare messages, dmesg timestamps/priority tags and syslog/journal `kernel:`
//! prefixes are accepted. Numeric timestamps are decoded as [`jiff::SignedDuration`].
//! Untimestamped continuation lines retain `None` timestamps.
//!
//! [`parse_events`] groups OOM invocations, diagnostics and kills into events.
//! [`parse`] returns the same OOM-only records in source order. Generic CPU,
//! stack and memory diagnostics outside an OOM region are ignored. [`parse_line`]
//! is context-free and should be used for isolated diagnostic snippets.
//! Memory data retains explicit units without assuming the machine's page size.
//! Recognized messages must parse completely. See [`parse_events`] for grouping
//! limitations when logs are truncated or interleaved.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod gfp;
pub use gfp::decode_gfp_mask;
mod report;
pub use report::format_event_analysis;
mod analysis;
pub use analysis::{
    AnalysisOptions, Evidence, EvidenceKind, FindingCode, FindingData, OomAnalysis, OomReason,
    PageSizeInference, StructuredFinding, analyze_event, analyze_event_with_options,
    infer_page_size,
};
mod diagnostics;
mod events;
pub use events::parse_events;
mod types;
pub use types::*;

/// Byte counts used by memory measurements.
pub use bytesize::ByteSize;
use jiff::SignedDuration;
use std::{error::Error, fmt};
mod timestamps;
pub use timestamps::*;
use winnow::{
    Parser,
    ascii::{dec_int, dec_uint, hex_uint, space0, space1},
    combinator::{alt, delimited, opt},
    token::take_until,
};

/// Resident and virtual memory measurements as byte sizes. Kernel kB means 1024 bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemoryUsage {
    /// Total virtual memory; absent in reaper messages.
    pub total_vm: Option<ByteSize>,
    /// Anonymous resident memory.
    pub anon_rss: Option<ByteSize>,
    /// File-backed resident memory.
    pub file_rss: Option<ByteSize>,
    /// Shared resident memory; absent in older kernel messages.
    pub shmem_rss: Option<ByteSize>,
    /// Page table memory; absent in older kernel messages.
    pub page_tables: Option<ByteSize>,
}

/// A process selected and killed by the kernel OOM killer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KilledProcess {
    /// Process ID.
    pub pid: u32,
    /// Kernel task name (which may be truncated by the kernel).
    pub name: String,
    /// Memory measurements at the time of the kill.
    pub memory: MemoryUsage,
    /// User ID, when logged.
    pub uid: Option<u32>,
    /// OOM score adjustment, when logged.
    pub oom_score_adj: Option<i32>,
    /// Whether the message explicitly says `Memory cgroup out of memory`.
    pub memory_cgroup: bool,
}

/// The task that invoked the OOM killer; not necessarily the killed task.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Invocation {
    /// Invoking task name.
    pub name: String,
    /// GFP allocation mask.
    pub gfp_mask: u64,
    /// Decoded symbolic GFP classes and modifiers, if printed.
    pub gfp_flags: Option<Vec<GfpFlag>>,
    /// Optional invoking-task nodemask, absent or null when not specified.
    pub nodemask: Option<Vec<NodeRange>>,
    /// Allocation order; may be negative for a forced OOM.
    pub order: i32,
    /// Invoking task's OOM score adjustment.
    pub oom_score_adj: i32,
}

/// Memory remaining after the OOM reaper processed a task.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReapedProcess {
    /// Process ID.
    pub pid: u32,
    /// Kernel task name.
    pub name: String,
    /// Remaining resident memory as byte sizes.
    pub memory: MemoryUsage,
}

/// A supported kernel OOM message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OomMessage {
    /// Older invoking-task cpuset membership and memory-node eligibility.
    LegacyCpuset(LegacyCpuset),
    /// Older victim selection and badness score; not a kill confirmation.
    VictimSelection(VictimSelection),
    /// Unresolved raw stack words from older kernels.
    StackWords(Vec<u64>),
    /// Memory cgroup resource usage and limit.
    CgroupBudget(CgroupBudget),
    /// Path introducing a cgroup statistics block.
    CgroupStatsPath(String),
    /// One cgroup statistics field; event parsing only accepts these inside that block.
    CgroupStat(CgroupStat),
    /// A process was killed.
    Killed(KilledProcess),
    /// A task invoked the OOM killer.
    Invoked(Invocation),
    /// The reaper reclaimed a task's memory.
    Reaped(ReapedProcess),
    /// SysRq requested a manual OOM execution.
    ManualOom,
    /// CPU, command, kernel build and taint context.
    CpuContext(CpuContext),
    /// Expanded descriptions of active kernel taints.
    TaintDescriptions(Vec<TaintDescription>),
    /// Hardware and BIOS identity.
    Hardware(Hardware),
    /// Workqueue callback context.
    Workqueue(Workqueue),
    /// Diagnostic section header.
    Section(Section),
    /// Stack context boundary.
    StackBoundary(StackBoundary),
    /// A stack frame.
    StackFrame(StackFrame),
    /// Global memory counters, including untimestamped continuation lines.
    MemoryCounters(Vec<MemoryCounter>),
    /// NUMA node or zone memory counters.
    NodeMemory(NodeMemory),
    /// Low-memory reserves in pages, in kernel zone order. Node/zone association
    /// comes from the preceding node record; no adjacency is inferred here.
    LowmemReserves(Vec<u64>),
    /// Buddy allocator free block counts and migration types.
    BuddyInfo(BuddyInfo),
    /// Hugepage pool counters.
    HugePages(HugePages),
    /// System page or swap total.
    MemoryTotal(MemoryTotal),
    /// Cumulative swap-cache operation counts.
    SwapCacheStats(SwapCacheStats),
    /// Allocation profiling entry.
    Allocation(Allocation),
    /// Task table column identities.
    TaskColumns(Vec<TaskColumn>),
    /// Task memory snapshot.
    Task(Task),
    /// OOM constraint, scope and victim summary.
    OomContext(OomContext),
    /// Instruction pointer from an OOM stack dump.
    InstructionPointer(InstructionPointer),
    /// Machine code bytes or the address at which they were inaccessible.
    InstructionCode(InstructionCode),
    /// CPU register snapshot, preserving raw bit patterns and segment selectors.
    Registers(Vec<RegisterValue>),
}

/// A parsed message and its original location.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Record {
    /// One-based source line number (always 1 for [`parse_line`]).
    pub line_number: usize,
    /// Uninterpreted text before the message, including whitespace.
    pub prefix: String,
    /// Time since boot from a numeric dmesg timestamp; absent on continuation
    /// lines. No timestamp is inferred from neighboring records.
    pub timestamp: Option<jiff::SignedDuration>,
    /// Calendar timestamp, independent of the optional uptime.
    pub wall_time: Option<WallTime>,
    original: String,
    /// Parsed message.
    pub message: OomMessage,
}

/// A malformed supported message, or multiple lines passed to [`parse_line`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParseError {
    /// One-based source line number.
    pub line_number: usize,
    /// Original source line, without its line ending.
    pub input: String,
    /// Parser diagnostic.
    pub detail: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid OOM message on line {}: {}",
            self.line_number, self.detail
        )
    }
}
impl Error for ParseError {}

/// Extract OOM-related records from a continuous log in source order.
///
/// Uses the OOM boundaries documented by [`parse_events`]. Empty or unrelated
/// input returns an empty vector. LF and CRLF are accepted.
///
/// # Errors
/// Returns the first malformed supported message inside an OOM region (or a
/// malformed standalone OOM-specific message).
pub fn parse(input: impl AsRef<str>) -> Result<Vec<Record>, ParseError> {
    let mut records: Vec<_> = parse_events(input)?
        .into_iter()
        .flat_map(|event| event.records)
        .collect();
    records.sort_by_key(|record| record.line_number);
    Ok(records)
}

/// Parse one diagnostic line without OOM context.
///
/// Returns `None` for an unsupported format. CPU, stack and memory diagnostics
/// may also belong to non-OOM kernel activity; use [`parse`] or [`parse_events`]
/// to filter a continuous log. Task rows without headers infer their layout
/// from the numeric columns; use [`parse_task_line`] for numeric task names.
///
/// An optional final LF or CRLF is accepted.
///
/// # Errors
/// Returns an error for malformed supported messages or embedded line endings.
pub fn parse_line(input: impl AsRef<str>) -> Result<Option<Record>, ParseError> {
    let input = input.as_ref();
    let line = input
        .strip_suffix("\r\n")
        .or_else(|| input.strip_suffix('\n'))
        .unwrap_or(input);
    if line.contains(['\n', '\r']) {
        return Err(ParseError {
            line_number: 1,
            input: line.into(),
            detail: "expected a single line".into(),
        });
    }
    let mut record = parse_at(line, 1, None)?;
    if let Some(record) = &mut record {
        record.original = input.into();
    }
    Ok(record)
}

// Only remove recognizable transport prefixes; do not search arbitrary text for
// kill markers, which would turn user-space messages into kernel events.
fn message_start(line: &str) -> usize {
    let mut rest = line;
    if let Some((_, body)) = line.split_once("kernel:") {
        rest = body;
    }
    rest = rest.trim_start();
    if let Some(body) = rest.strip_prefix('<') {
        if let Some((priority, tail)) = body.split_once('>') {
            if !priority.is_empty() && priority.bytes().all(|b| b.is_ascii_digit()) {
                rest = tail.trim_start();
            }
        }
    }
    if !line.contains("kernel:") {
        // ISO date/time followed directly by a kernel message.
        if let Some((date, tail)) = rest.split_once(' ') {
            if timestamps::parse_wall_time(date).is_some() {
                rest = tail.trim_start();
            } else if let Some((time, body)) = tail.split_once(' ') {
                if timestamps::parse_wall_time(&format!("{date} {time}")).is_some() {
                    rest = body.trim_start();
                }
            }
        }
    }
    if let Some(body) = rest.strip_prefix('[') {
        if let Some((stamp, tail)) = body.split_once(']') {
            if (stamp.contains('.')
                && !stamp.trim().is_empty()
                && stamp
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '.' || c == ' '))
                || timestamps::parse_wall_time(stamp).is_some()
                || timestamps::is_dmesg_date(stamp)
            {
                rest = tail.trim_start();
            }
        }
    }
    line.len() - rest.len()
}

fn parse_at(
    line: &str,
    line_number: usize,
    layout: Option<TaskLayout>,
) -> Result<Option<Record>, ParseError> {
    let start = message_start(line);
    let body = line[start..].trim_end();
    // rsyslog can encode Mem-Info's embedded newlines as octal #012.
    // Normalize counters only; names and original source text remain untouched.
    let normalized = if body.contains("#012")
        && body
            .split_once(':')
            .is_some_and(|(key, _)| MemoryMetric::from_name(key).is_some())
    {
        std::borrow::Cow::Owned(body.replace("#012", " "))
    } else {
        std::borrow::Cow::Borrowed(body)
    };
    let body = normalized.as_ref();
    let result = if body.starts_with("Killed process")
        || body.starts_with("Out of memory: Killed process")
        || body.starts_with("Memory cgroup out of memory: Killed process")
    {
        killed
            .map(OomMessage::Killed)
            .parse(body)
            .map_err(|e| e.to_string())
    } else if body.starts_with("oom_reaper: reaped process") {
        reaped
            .map(OomMessage::Reaped)
            .parse(body)
            .map_err(|e| e.to_string())
    } else if body.contains(" invoked oom-killer:") {
        invoked
            .map(OomMessage::Invoked)
            .parse(body)
            .map_err(|e| e.to_string())
    } else if let Some(result) = diagnostics::parse_message(body, layout) {
        result
    } else {
        return Ok(None);
    };
    let timestamp = parse_timestamp(&line[..start]).map_err(|detail| ParseError {
        line_number,
        input: line.into(),
        detail,
    })?;
    result
        .map(|message| {
            Some(Record {
                line_number,
                prefix: line[..start].into(),
                timestamp,
                wall_time: timestamps::parse_wall_time(&line[..start]),
                original: line.into(),
                message,
            })
        })
        .map_err(|error| ParseError {
            line_number,
            input: line.into(),
            detail: error.to_string(),
        })
}

fn kib(input: &mut &str) -> winnow::Result<ByteSize> {
    let value: u64 = dec_uint.parse_next(input)?;
    "kB".parse_next(input)?;
    checked_kib(value)
}

fn resident(input: &mut &str) -> winnow::Result<MemoryUsage> {
    "anon-rss:".parse_next(input)?;
    let anon_rss = Some(kib.parse_next(input)?);
    (",", space0, "file-rss:").parse_next(input)?;
    let file_rss = Some(kib.parse_next(input)?);
    let shmem_rss =
        opt((",", space0, "shmem-rss:", kib).map(|(_, _, _, v)| v)).parse_next(input)?;
    Ok(MemoryUsage {
        anon_rss,
        file_rss,
        shmem_rss,
        ..Default::default()
    })
}

fn identity(input: &mut &str, mut terminator: &'static str) -> winnow::Result<(u32, String)> {
    let pid = dec_uint.parse_next(input)?;
    (space1, "(").parse_next(input)?;
    // Use the message-specific suffix, allowing ordinary parentheses in names.
    let name: &str = take_until(0.., terminator).parse_next(input)?;
    terminator.parse_next(input)?;
    Ok((pid, name.into()))
}

fn killed(input: &mut &str) -> winnow::Result<KilledProcess> {
    let reason =
        opt(alt(("Out of memory: ", "Memory cgroup out of memory: "))).parse_next(input)?;
    "Killed process ".parse_next(input)?;
    let (pid, name) = identity(input, ") total-vm:")?;
    let total_vm = Some(kib.parse_next(input)?);
    (",", space0).parse_next(input)?;
    let mut memory = resident(input)?;
    memory.total_vm = total_vm;
    let uid = opt((",", space0, "UID:", dec_uint::<_, u32, _>).map(|(_, _, _, v)| v))
        .parse_next(input)?;
    memory.page_tables = opt((space1, "pgtables:", kib).map(|(_, _, v)| v)).parse_next(input)?;
    let oom_score_adj = opt((space1, "oom_score_adj:", dec_int::<_, i32, _>).map(|(_, _, v)| v))
        .parse_next(input)?;
    Ok(KilledProcess {
        pid,
        name,
        memory,
        uid,
        oom_score_adj,
        memory_cgroup: reason == Some("Memory cgroup out of memory: "),
    })
}

fn reaped(input: &mut &str) -> winnow::Result<ReapedProcess> {
    "oom_reaper: reaped process ".parse_next(input)?;
    let (pid, name) = identity(input, "), now ")?;
    Ok(ReapedProcess {
        pid,
        name,
        memory: resident(input)?,
    })
}

fn invoked(input: &mut &str) -> winnow::Result<Invocation> {
    let name = take_until(1.., " invoked oom-killer:")
        .parse_next(input)?
        .to_owned();
    " invoked oom-killer: gfp_mask=".parse_next(input)?;
    // The kernel's %#x prints zero without a 0x prefix.
    opt("0x").parse_next(input)?;
    let gfp_mask = hex_uint.parse_next(input)?;
    let gfp_flags = opt(delimited("(", diagnostics::gfp_flags, ")")).parse_next(input)?;
    (",", space0).parse_next(input)?;
    let nodemask = if input.starts_with("nodemask=") {
        "nodemask=".parse_next(input)?;
        let before_order = take_until(1.., "order=").parse_next(input)?;
        let mask = before_order
            .trim_end()
            .strip_suffix(',')
            .map(str::trim)
            .ok_or_else(winnow::error::ContextError::new)?;
        if mask == "(null)" {
            None
        } else {
            Some(diagnostics::node_ranges(mask)?)
        }
    } else {
        None
    };
    "order=".parse_next(input)?;
    let order = dec_int.parse_next(input)?;
    (",", space0, "oom_score_adj=").parse_next(input)?;
    let oom_score_adj = dec_int.parse_next(input)?;
    Ok(Invocation {
        name,
        gfp_mask,
        gfp_flags,
        nodemask,
        order,
        oom_score_adj,
    })
}

fn parse_timestamp(prefix: &str) -> Result<Option<SignedDuration>, String> {
    let Some((_, bracket)) = prefix.rsplit_once('[') else {
        return Ok(None);
    };
    let Some((stamp, _)) = bracket.split_once(']') else {
        return Ok(None);
    };
    if !stamp.contains('.')
        || stamp
            .chars()
            .any(|c| !c.is_ascii_digit() && c != '.' && c != ' ')
    {
        return Ok(None);
    }
    fn timestamp(input: &mut &str) -> winnow::Result<SignedDuration> {
        let seconds: u64 = dec_uint
            .verify(|n: &u64| *n <= i64::MAX as u64)
            .parse_next(input)?;
        ".".parse_next(input)?;
        let fraction: &str =
            winnow::token::take_while(1..=9, |c: char| c.is_ascii_digit()).parse_next(input)?;
        let nanos = winnow::ascii::digit1::<_, winnow::error::ContextError>
            .try_map(str::parse::<u32>)
            .parse(fraction)
            .map_err(|_| winnow::error::ContextError::new())?
            * 10u32.pow(9 - fraction.len() as u32);
        Ok(SignedDuration::new(seconds as i64, nanos as i32))
    }
    timestamp
        .parse(stamp.trim())
        .map(Some)
        .map_err(|e| e.to_string())
}

/// Parse a standalone task row using an explicitly selected table layout.
/// Useful when the task name starts with numeric words and automatic layout
/// detection would be ambiguous. Whole-log parsing uses the printed header.
///
/// # Errors
/// Returns an error if the line is not a valid task row in the selected layout.
pub fn parse_task_line(input: impl AsRef<str>, layout: TaskLayout) -> Result<Record, ParseError> {
    let input = input.as_ref();
    let line = input
        .strip_suffix("\r\n")
        .or_else(|| input.strip_suffix('\n'))
        .unwrap_or(input);
    if !line.contains(['\r', '\n']) {
        if let Some(mut record) = parse_at(line, 1, Some(layout))? {
            if matches!(record.message, OomMessage::Task(_)) {
                record.original = input.into();
                return Ok(record);
            }
        }
    }
    Err(ParseError {
        line_number: 1,
        input: line.into(),
        detail: "expected a task table row".into(),
    })
}

pub(crate) fn checked_kib(value: u64) -> winnow::Result<ByteSize> {
    value
        .checked_mul(1024)
        .map(ByteSize::b)
        .ok_or_else(winnow::error::ContextError::new)
}

/// Prints the original parsed text, including its original line ending.
/// This lossless representation is a source snapshot: changing public semantic
/// fields does not rewrite the source text. Use it for extraction and archival.
impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.original)
    }
}
/// Prints the original text of the event's records in their stored order.
impl fmt::Display for OomEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for record in &self.records {
            write!(f, "{record}")?;
        }
        Ok(())
    }
}
