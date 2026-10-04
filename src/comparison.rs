//! Compare captured memory measurements without summing overlapping categories.
use crate::{
    AnalysisOptions, ByteSize, CgroupStatValue, MemoryValue, OomEvent, OomMessage, PageSize,
    PageSizeEvidence, PageSizeSelection, PageSizeSource, Task, TotalKind, analyze_event,
    analyze_event_with_options,
};
use std::{collections::BTreeMap, fmt::Write};

/// Page conversions for each side of a memory comparison.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ComparisonOptions {
    /// Override the first event's base page size; `None` infers it independently.
    pub before_page_size: Option<PageSize>,
    /// Override the second event's base page size; `None` infers it independently.
    pub after_page_size: Option<PageSize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Bytes(u128),
    Count(u128),
    Unknown(u64),
    State(bool),
}
impl Value {
    fn memory(value: &MemoryValue, page_size: PageSize) -> Self {
        match value {
            MemoryValue::Bytes(value) => Self::Bytes(value.as_u64().into()),
            MemoryValue::Pages(value) => Self::Bytes(pages(*value, page_size)),
            MemoryValue::Count(value) => Self::Count((*value).into()),
            MemoryValue::State(value) => Self::State(*value),
        }
    }

    fn render(&self) -> String {
        match self {
            Self::Bytes(value) => size(*value),
            Self::Count(value) => format!("{value} count"),
            Self::Unknown(value) => format!("{value} (unit unknown)"),
            Self::State(value) => value.to_string(),
        }
    }
}

#[derive(Debug)]
struct Measurement {
    value: Value,
    lines: Vec<usize>,
}

// Separate scopes so node, zone, task and global measurements never overwrite
// each other or turn into a misleading combined system memory total.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Group {
    System,
    Totals,
    Node(u32, Option<String>),
    Buddy(u32, String),
    HugePages(u32, u64),
    CgroupBudget,
    CgroupStats(Option<String>),
    Process(u32, String),
    Victim(String),
    Allocations,
}
impl Group {
    fn title(&self) -> String {
        match self {
            Self::System => "System memory categories".into(),
            Self::Totals => "RAM, page cache and swap totals".into(),
            Self::Node(node, None) => format!("Node {node}"),
            Self::Node(node, Some(zone)) => format!("Node {node}, {zone} zone"),
            Self::Buddy(node, zone) => format!("Node {node}, {zone} buddy allocator"),
            Self::HugePages(node, bytes) => {
                format!("Node {node}, {} hugepage pool", size((*bytes).into()))
            }
            Self::CgroupBudget => "Cgroup budgets".into(),
            Self::CgroupStats(path) => format!(
                "Cgroup memory.stat ({})",
                path.as_deref().unwrap_or("path not reported")
            ),
            Self::Process(uid, name) => format!("Process {name} (UID {uid}; grouped by command)"),
            Self::Victim(name) => format!("Killed process {name} (grouped by command)"),
            Self::Allocations => "Allocation profiling (rounded measurements)".into(),
        }
    }
}

#[derive(Default)]
struct Snapshot {
    measurements: BTreeMap<(Group, String), Measurement>,
    duplicate_counters: bool,
    overflowed_totals: bool,
}
impl Snapshot {
    fn insert(&mut self, group: Group, name: impl Into<String>, value: Value, lines: Vec<usize>) {
        if self
            .measurements
            .insert((group, name.into()), Measurement { value, lines })
            .is_some()
        {
            self.duplicate_counters = true;
        }
    }

    fn capture(event: &OomEvent, page_size: PageSize) -> Self {
        let mut snapshot = Self::default();
        let mut tasks: BTreeMap<(u32, String), Vec<(usize, &Task)>> = BTreeMap::new();
        let mut victims: BTreeMap<String, Vec<(usize, &crate::KilledProcess)>> = BTreeMap::new();
        let mut cgroup_path = None;
        for record in &event.records {
            let line = vec![record.line_number];
            match &record.message {
                OomMessage::MemoryCounters(counters) => {
                    for counter in counters {
                        snapshot.insert(
                            Group::System,
                            counter.metric.to_string(),
                            Value::memory(&counter.value, page_size),
                            line.clone(),
                        );
                    }
                }
                OomMessage::MemoryTotal(total) => {
                    let name = match total.kind {
                        TotalKind::Ram => "RAM",
                        TotalKind::PageCache => "Page cache",
                        TotalKind::SwapCache => "Swap cache",
                        TotalKind::TotalSwap => "Total swap",
                        TotalKind::FreeSwap => "Free swap",
                        TotalKind::HighMemMovable => "HighMem/MovableOnly",
                        TotalKind::Reserved => "Reserved",
                        TotalKind::CmaReserved => "CMA reserved",
                        TotalKind::PageTableCache => "Page table cache",
                        TotalKind::HardwarePoisoned => "Hardware poisoned",
                    };
                    snapshot.insert(
                        Group::Totals,
                        name,
                        Value::memory(&total.value, page_size),
                        line,
                    );
                }
                OomMessage::NodeMemory(node) => {
                    let group = Group::Node(node.node, node.zone.as_ref().map(ToString::to_string));
                    for counter in &node.counters {
                        snapshot.insert(
                            group.clone(),
                            counter.metric.to_string(),
                            Value::memory(&counter.value, page_size),
                            line.clone(),
                        );
                    }
                }
                OomMessage::BuddyInfo(buddy) => {
                    let group = Group::Buddy(buddy.node, buddy.zone.to_string());
                    snapshot.insert(
                        group.clone(),
                        "Free memory",
                        Value::Bytes(buddy.total.as_u64().into()),
                        line.clone(),
                    );
                    let largest = buddy
                        .blocks
                        .iter()
                        .filter(|block| block.count > 0)
                        .map(|block| block.size.as_u64())
                        .max()
                        .unwrap_or(0);
                    snapshot.insert(
                        group,
                        "Largest available block",
                        Value::Bytes(largest.into()),
                        line,
                    );
                }
                OomMessage::HugePages(pool) => {
                    let group = Group::HugePages(pool.node, pool.size.as_u64());
                    for (name, count) in [
                        ("Total pool", pool.total),
                        ("Free pool", pool.free),
                        ("Surplus pool", pool.surplus),
                    ] {
                        snapshot.insert(
                            group.clone(),
                            name,
                            Value::Bytes(u128::from(count) * u128::from(pool.size.as_u64())),
                            line.clone(),
                        );
                    }
                }
                OomMessage::CgroupBudget(budget) => {
                    for (name, value) in [
                        ("usage", Value::Bytes(budget.usage.as_u64().into())),
                        ("limit", Value::Bytes(budget.limit.as_u64().into())),
                        (
                            "failcnt (cumulative failed charges)",
                            Value::Count(budget.fail_count.into()),
                        ),
                    ] {
                        snapshot.insert(
                            Group::CgroupBudget,
                            format!("{} {name}", budget.resource),
                            value,
                            line.clone(),
                        );
                    }
                }
                OomMessage::CgroupStatsPath(path) => cgroup_path = Some(path.clone()),
                OomMessage::CgroupStat(stat) => {
                    let value = match stat.value {
                        CgroupStatValue::Bytes(value) => Value::Bytes(value.as_u64().into()),
                        CgroupStatValue::Count(value) => Value::Count(value.into()),
                        CgroupStatValue::Unknown(value) => Value::Unknown(value),
                    };
                    snapshot.insert(
                        Group::CgroupStats(cgroup_path.clone()),
                        &stat.name,
                        value,
                        line,
                    );
                }
                OomMessage::Task(task) => tasks
                    .entry((task.uid, task.name.clone()))
                    .or_default()
                    .push((record.line_number, task)),
                OomMessage::Killed(victim) => victims
                    .entry(victim.name.clone())
                    .or_default()
                    .push((record.line_number, victim)),
                OomMessage::Allocation(allocation) => {
                    let name = format!(
                        "{}:{} {}{}",
                        allocation.file,
                        allocation.line,
                        allocation.function,
                        allocation
                            .module
                            .as_ref()
                            .map(|m| format!(" [{m}]"))
                            .unwrap_or_default()
                    );
                    snapshot.insert(
                        Group::Allocations,
                        format!("{name}: size"),
                        Value::Bytes(allocation.size.bytes.as_u64().into()),
                        line.clone(),
                    );
                    snapshot.insert(
                        Group::Allocations,
                        format!("{name}: allocations"),
                        Value::Count(allocation.count.into()),
                        line,
                    );
                }
                _ => {}
            }
        }
        for ((uid, name), rows) in tasks {
            let group = Group::Process(uid, name);
            let lines: Vec<_> = rows.iter().map(|(line, _)| *line).collect();
            snapshot.insert(
                group.clone(),
                "Captured tasks",
                Value::Count(rows.len() as u128),
                lines.clone(),
            );
            let mut fields: BTreeMap<&str, Option<u128>> = BTreeMap::new();
            for (_, task) in &rows {
                for (name, value) in [
                    (
                        "Resident memory (RSS)",
                        Some(pages(task.rss_pages, page_size)),
                    ),
                    (
                        "Anonymous RSS",
                        task.rss_anon_pages.map(|n| pages(n, page_size)),
                    ),
                    ("File RSS", task.rss_file_pages.map(|n| pages(n, page_size))),
                    (
                        "Shared RSS",
                        task.rss_shmem_pages.map(|n| pages(n, page_size)),
                    ),
                    (
                        "Virtual memory",
                        Some(pages(task.total_vm_pages, page_size)),
                    ),
                    ("Swap", Some(pages(task.swap_entries, page_size))),
                    (
                        "Page tables",
                        task.page_tables.map(|v| u128::from(v.as_u64())),
                    ),
                    (
                        "Page tables (legacy nr_ptes)",
                        task.page_table_pages.map(|n| pages(n, page_size)),
                    ),
                    (
                        "Page tables (legacy nr_pmds)",
                        task.pmd_table_pages.map(|n| pages(n, page_size)),
                    ),
                    (
                        "Page tables (legacy nr_puds)",
                        task.pud_table_pages.map(|n| pages(n, page_size)),
                    ),
                ] {
                    let total = fields.entry(name).or_insert(Some(0));
                    *total = total.zip(value).and_then(|(sum, value)| {
                        let combined = sum.checked_add(value);
                        snapshot.overflowed_totals |= combined.is_none();
                        combined
                    });
                }
            }
            for (name, value) in fields {
                if let Some(value) = value {
                    snapshot.insert(group.clone(), name, Value::Bytes(value), lines.clone());
                }
            }
        }
        for (name, rows) in victims {
            let group = Group::Victim(name);
            let lines: Vec<_> = rows.iter().map(|(line, _)| *line).collect();
            snapshot.insert(
                group.clone(),
                "Killed tasks",
                Value::Count(rows.len() as u128),
                lines.clone(),
            );
            for (name, field) in [
                (
                    "Anonymous RSS",
                    (|m: &crate::MemoryUsage| m.anon_rss)
                        as fn(&crate::MemoryUsage) -> Option<ByteSize>,
                ),
                ("File RSS", |m: &crate::MemoryUsage| m.file_rss),
                ("Shared RSS", |m: &crate::MemoryUsage| m.shmem_rss),
                ("Virtual memory", |m: &crate::MemoryUsage| m.total_vm),
                ("Page tables", |m: &crate::MemoryUsage| m.page_tables),
            ] {
                let total: Option<u128> = rows
                    .iter()
                    .map(|(_, victim)| field(&victim.memory).map(|v| u128::from(v.as_u64())))
                    .sum();
                if let Some(total) = total {
                    snapshot.insert(group.clone(), name, Value::Bytes(total), lines.clone());
                }
            }
        }
        snapshot
    }
}

fn pages(count: u64, page_size: PageSize) -> u128 {
    u128::from(count) * u128::from(page_size.get())
}

fn size(value: u128) -> String {
    if let Ok(bytes) = u64::try_from(value) {
        ByteSize::b(bytes).display().iec().to_string()
    } else {
        format!("{:.2} EiB", value as f64 / (1u64 << 60) as f64)
    }
}

fn safe(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

fn delta(before: Option<&Value>, after: Option<&Value>) -> String {
    match (before, after) {
        (Some(Value::Bytes(before)), Some(Value::Bytes(after))) => {
            numeric_delta(*before, *after, true)
        }
        (Some(Value::Count(before)), Some(Value::Count(after))) => {
            numeric_delta(*before, *after, false)
        }
        (None, _) | (_, None) => "not comparable (missing measurement)".into(),
        (Some(Value::Unknown(_)), _) | (_, Some(Value::Unknown(_))) => {
            "not comparable (unit unknown)".into()
        }
        (Some(Value::State(before)), Some(Value::State(after))) => format!("{before} -> {after}"),
        _ => "not comparable (different units)".into(),
    }
}

fn numeric_delta(before: u128, after: u128, memory: bool) -> String {
    let difference = before.abs_diff(after);
    let sign = if after >= before { '+' } else { '-' };
    let amount = if memory {
        format!("{sign}{} ({sign}{difference} bytes)", size(difference))
    } else {
        format!("{sign}{difference} count")
    };
    let percent = if before == 0 {
        "baseline zero".into()
    } else {
        format!("{sign}{:.1}%", difference as f64 / before as f64 * 100.0)
    };
    format!("{amount}; {percent}")
}

fn page_selection(event: &OomEvent, override_size: Option<PageSize>) -> PageSizeSelection {
    if let Some(page_size) = override_size {
        analyze_event_with_options(event, AnalysisOptions { page_size }).page_size
    } else {
        analyze_event(event).page_size
    }
}

fn page_description(selection: &PageSizeSelection) -> String {
    let source = match selection.source {
        PageSizeSource::Buddy => "inferred from buddy buckets",
        PageSizeSource::Fallback => "fallback assumption",
        PageSizeSource::Explicit => "explicit override",
    };
    let evidence = match &selection.evidence {
        PageSizeEvidence::Conflicting { inferred, .. } => {
            format!("; conflicts with inferred {} bytes", inferred.get())
        }
        PageSizeEvidence::Inconsistent { .. } => "; buddy geometry is inconsistent".into(),
        _ => String::new(),
    };
    format!("{} bytes ({source}{evidence})", selection.page_size.get())
}

fn scope(event: &OomEvent) -> String {
    let context = event.records.iter().find_map(|record| {
        if let OomMessage::OomContext(context) = &record.message {
            Some(context)
        } else {
            None
        }
    });
    match context.map(|context| &context.scope) {
        Some(crate::OomScope::Global) => "global".into(),
        Some(crate::OomScope::MemoryCgroup(path)) => format!("cgroup {}", safe(path)),
        _ => event
            .records
            .iter()
            .find_map(|record| {
                if let OomMessage::CgroupStatsPath(path) = &record.message {
                    Some(format!("cgroup {}", safe(path)))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "not reported".into()),
    }
}

fn reference(measurement: Option<&Measurement>) -> String {
    match measurement {
        Some(measurement) => {
            let mut ranges = Vec::new();
            let mut lines = measurement.lines.iter().copied();
            if let Some(mut start) = lines.next() {
                let mut end = start;
                for line in lines {
                    if end.checked_add(1) == Some(line) {
                        end = line;
                    } else {
                        ranges.push(if start == end {
                            start.to_string()
                        } else {
                            format!("{start}-{end}")
                        });
                        start = line;
                        end = line;
                    }
                }
                ranges.push(if start == end {
                    start.to_string()
                } else {
                    format!("{start}-{end}")
                });
            }
            ranges.join(",")
        }
        None => "-".into(),
    }
}

/// Render changed measurements from two OOM snapshots, with signed byte deltas.
///
/// Each side selects its own page size unless overridden. Tasks are grouped
/// by command and UID, not matched by potentially reused PIDs. Missing counters
/// remain unknown. Only changed or one-sided measurements appear, with source
/// line references. Memory categories and task RSS can overlap and are not
/// summed into system usage. Control characters in log text are escaped.
pub fn format_event_comparison(
    before: &OomEvent,
    after: &OomEvent,
    options: ComparisonOptions,
) -> String {
    let scopes = format!(
        "OOM scope: before {}; after {}.\n",
        scope(before),
        scope(after)
    );
    let before_page = page_selection(before, options.before_page_size);
    let after_page = page_selection(after, options.after_page_size);
    let before = Snapshot::capture(before, before_page.page_size);
    let after = Snapshot::capture(after, after_page.page_size);
    scopes + &render_comparison(&before, &after, &before_page, &after_page)
}

fn render_comparison(
    before: &Snapshot,
    after: &Snapshot,
    before_page: &PageSizeSelection,
    after_page: &PageSizeSelection,
) -> String {
    let mut out = String::new();
    // String's fmt::Write cannot fail.
    let _ = writeln!(
        out,
        "Page size: before {}; after {}.",
        page_description(before_page),
        page_description(after_page)
    );
    let keys: std::collections::BTreeSet<_> = before
        .measurements
        .keys()
        .chain(after.measurements.keys())
        .collect();
    let changes: Vec<_> = keys
        .into_iter()
        .filter_map(|key| {
            let left = before.measurements.get(key);
            let right = after.measurements.get(key);
            (left.map(|m| &m.value) != right.map(|m| &m.value)).then_some((key, left, right))
        })
        .collect();
    if changes.is_empty() {
        if before.measurements.is_empty() && after.measurements.is_empty() {
            out.push_str("No memory measurements were captured in either event.\n");
        } else {
            out.push_str("No differences in captured memory measurements.\n");
        }
    } else {
        let mut ranked: Vec<_> = changes
            .iter()
            .filter_map(|(key, left, right)| {
                match (left.map(|m| &m.value), right.map(|m| &m.value)) {
                    (Some(Value::Bytes(a)), Some(Value::Bytes(b))) if key.1 != "Virtual memory" => {
                        Some((a.abs_diff(*b), key, a, b))
                    }
                    _ => None,
                }
            })
            .collect();
        ranked.sort_by_key(|(difference, key, _, _)| (std::cmp::Reverse(*difference), *key));
        if !ranked.is_empty() {
            out.push_str("\nLargest measured memory changes (categories may overlap):\n");
            for (_, (group, name), left, right) in ranked.iter().take(5) {
                let _ = writeln!(
                    out,
                    "  {} / {}: {}",
                    safe(&group.title()),
                    safe(name),
                    numeric_delta(**left, **right, true)
                );
            }
        }
        for (side, captured, other) in [("before", before, after), ("after", after, before)] {
            let mut one_sided: Vec<_> = captured
                .measurements
                .iter()
                .filter_map(|((group, name), measurement)| {
                    if matches!(group, Group::Process(_, _))
                        && name == "Resident memory (RSS)"
                        && !other
                            .measurements
                            .contains_key(&(group.clone(), "Captured tasks".into()))
                    {
                        if let Value::Bytes(value) = measurement.value {
                            return Some((value, group, measurement));
                        }
                    }
                    None
                })
                .collect();
            one_sided.sort_by_key(|(value, group, _)| (std::cmp::Reverse(*value), *group));
            if !one_sided.is_empty() {
                let _ = writeln!(
                    out,
                    "\nProcess groups captured only {side} (largest RSS first; up to 5 shown):"
                );
                for (value, group, measurement) in one_sided.iter().take(5) {
                    let _ = writeln!(
                        out,
                        "  {}: RSS {} ({value} bytes); {side} lines {}.",
                        safe(&group.title()),
                        size(*value),
                        reference(Some(measurement))
                    );
                }
            }
        }
        let _ = writeln!(
            out,
            "\n{} changed or one-sided measurement(s). Deltas are after - before.",
            changes.len()
        );
        let mut previous = None;
        let mut width = 30;
        for ((group, name), left, right) in &changes {
            if previous != Some(group) {
                width = changes
                    .iter()
                    .filter(|((candidate, _), _, _)| candidate == group)
                    .map(|((_, name), _, _)| safe(name).chars().count())
                    .max()
                    .unwrap_or(30)
                    .max(30);
                let _ = writeln!(out, "\n{}", safe(&group.title()));
                let _ = writeln!(
                    out,
                    "  {:<width$} {:>16}  {:>16}  Change",
                    "Measurement", "Before", "After"
                );
                previous = Some(group);
            }
            let value = |measurement: Option<&Measurement>| {
                measurement
                    .map(|m| m.value.render())
                    .unwrap_or_else(|| "not reported".into())
            };
            let _ = writeln!(
                out,
                "  {:<width$} {:>16}  {:>16}  {}",
                safe(name),
                value(*left),
                value(*right),
                delta(left.map(|m| &m.value), right.map(|m| &m.value))
            );
            let _ = writeln!(
                out,
                "    Source lines: before {}; after {}.",
                reference(*left),
                reference(*right)
            );
        }
    }
    if before.duplicate_counters || after.duplicate_counters {
        out.push_str("\nRepeated counters in a scope use the last captured value.\n");
    }
    if before.overflowed_totals || after.overflowed_totals {
        out.push_str("\nProcess totals exceeding the supported byte range were omitted.\n");
    }
    out.push_str("\nMissing measurements mean not reported, not zero. Process groups present in only\none snapshot may reflect a changed workload or incomplete capture. Shared RSS and\nmemory categories can overlap; virtual memory is not resident memory. Cumulative\ncounts are snapshot differences, not rates. Snapshots alone do not establish a leak.\n");
    out
}
