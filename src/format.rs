//! Rewrite memory quantities while retaining the surrounding source log.
use std::{collections::BTreeMap, ops::Range};

use crate::{
    ByteSize, CgroupStatValue, MemoryCounter, MemoryUsage, MemoryValue, OomMessage, PageSize,
    PageSizeInference, ParseError, Record, Section, Task, TaskColumn, TotalKind, infer_page_size,
    parse_events,
};

/// Overrides for formatting memory quantities in an OOM log.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct FormatOptions {
    /// Base page size. `None` infers from buddy buckets, falling back to 4096 bytes.
    pub page_size: Option<PageSize>,
    /// Total physical RAM in bytes, overriding each event's RAM total.
    /// `None` uses the event's `pages RAM` line. Zero is treated as unknown.
    pub total_memory: Option<ByteSize>,
}

struct Context {
    page_size: u64,
    total: Option<u128>,
}

impl Context {
    fn bytes(&self, bytes: u128) -> String {
        let size = if let Ok(bytes) = u64::try_from(bytes) {
            ByteSize::b(bytes).display().iec().to_string()
        } else {
            format!("{:.2} EiB", bytes as f64 / (1u64 << 60) as f64)
        };
        let percent = match self.total {
            Some(total) => {
                let percent = bytes as f64 / total as f64 * 100.0;
                if bytes != 0 && percent < 0.01 {
                    "<0.01%".into()
                } else {
                    format!("{percent:.2}%")
                }
            }
            None => "RAM unknown".into(),
        };
        format!("{size} ({percent})")
    }

    fn pages(&self, pages: u64) -> String {
        self.bytes(u128::from(pages) * u128::from(self.page_size))
    }

    fn value(&self, value: &MemoryValue) -> Option<String> {
        match value {
            MemoryValue::Pages(pages) => Some(self.pages(*pages)),
            MemoryValue::Bytes(bytes) => Some(self.bytes(bytes.as_u64().into())),
            MemoryValue::Count(_) | MemoryValue::State(_) => None,
        }
    }
}

/// Print the original log with memory quantities replaced by IEC sizes and RAM percentages.
///
/// Uses [`parse_events`] to identify OOM records and their event-local RAM totals.
/// Percentages use physical RAM, excluding swap and without substituting cgroup
/// limits. Totals and inferred page sizes are never carried across events. Missing
/// or zero RAM totals display `RAM unknown`. Overrides apply to every event.
/// Percentages may exceed 100%, for example for virtual memory or swap capacity.
///
/// Other source lines, prefixes, names, non-memory counters, and line endings are
/// preserved. Task memory columns are widened and aligned, with unit-bearing
/// headers updated. Buddy block counts remain counts; their sizes are per block.
/// Hugepage pool counts are converted using their printed hugepage size.
/// Addresses, instruction bytes, and stack offsets are retained as code context.
/// The resulting text is for reading, not parsing back as a kernel OOM log.
///
/// # Errors
/// Returns the first malformed supported OOM record, before producing output.
pub fn format_log(input: impl AsRef<str>, options: FormatOptions) -> Result<String, ParseError> {
    let input = input.as_ref();
    let events = parse_events(input)?;
    let mut lines = BTreeMap::new();
    for event in &events {
        let page_size =
            options
                .page_size
                .map(PageSize::get)
                .unwrap_or_else(|| match infer_page_size(event) {
                    Some(PageSizeInference::Consistent { page_size, .. }) => page_size.get(),
                    _ => 4096,
                });
        let total = options
            .total_memory
            .map(|bytes| u128::from(bytes.as_u64()))
            .or_else(|| {
                event
                    .records
                    .iter()
                    .find_map(|record| match &record.message {
                        OomMessage::MemoryTotal(total) if total.kind == TotalKind::Ram => {
                            match total.value {
                                MemoryValue::Pages(pages) => {
                                    Some(u128::from(pages) * u128::from(page_size))
                                }
                                MemoryValue::Bytes(bytes) => Some(bytes.as_u64().into()),
                                _ => None,
                            }
                        }
                        _ => None,
                    })
            })
            .filter(|total| *total != 0);
        let context = Context { page_size, total };
        let mut index = 0;
        while index < event.records.len() {
            let record = &event.records[index];
            if let OomMessage::TaskColumns(columns) = &record.message {
                let end = index
                    + 1
                    + event.records[index + 1..]
                        .iter()
                        .take_while(|record| matches!(record.message, OomMessage::Task(_)))
                        .count();
                format_table(&event.records[index..end], columns, &context, &mut lines);
                index = end;
            } else {
                lines.insert(record.line_number, format_record(record, &context));
                index += 1;
            }
        }
    }
    let mut output = String::with_capacity(input.len());
    for (index, line) in input.split_inclusive('\n').enumerate() {
        output.push_str(lines.get(&(index + 1)).map(String::as_str).unwrap_or(line));
    }
    Ok(output)
}

// All replacement positions refer to the original body, excluding its prefix.
// Apply them in reverse so an expanded size never changes a later position.
fn replace(record: &Record, mut replacements: Vec<(Range<usize>, String)>) -> String {
    let mut line = record.original.clone();
    replacements.sort_by_key(|(range, _)| range.start);
    for (range, value) in replacements.into_iter().rev() {
        let offset = record.prefix.len();
        line.replace_range(range.start + offset..range.end + offset, &value);
    }
    line
}

fn body(record: &Record) -> &str {
    record.original[record.prefix.len()..].trim_end()
}

fn number(text: &str, start: usize) -> Range<usize> {
    let start = start + text[start..].len() - text[start..].trim_start().len();
    let digits = text[start..].bytes().take_while(u8::is_ascii_digit).count();
    let mut end = start + digits;
    if text[end..].starts_with("kB") || text[end..].starts_with("KB") {
        end += 2;
    }
    start..end
}

fn after(text: &str, marker: &str) -> Option<Range<usize>> {
    text.find(marker)
        .map(|start| number(text, start + marker.len()))
}

fn counters(
    text: &str,
    values: &[MemoryCounter],
    context: &Context,
) -> Vec<(Range<usize>, String)> {
    let mut positions = text
        .match_indices(':')
        .map(|(index, _)| number(text, index + 1));
    let mut replacements = Vec::new();
    for counter in values {
        if matches!(counter.value, MemoryValue::State(_)) {
            continue;
        }
        if let Some(range) = positions.next() {
            if let Some(value) = context.value(&counter.value) {
                replacements.push((range, value));
            }
        }
    }
    replacements
}

fn process_memory(
    text: &str,
    memory: &MemoryUsage,
    context: &Context,
) -> Vec<(Range<usize>, String)> {
    // Begin after the task name so names containing memory-like text stay intact.
    let (marker, offset) = if memory.total_vm.is_some() {
        (") total-vm:", 2)
    } else {
        ("), now ", 7)
    };
    let start = text.find(marker).map(|start| start + offset);
    let Some(start) = start else {
        return Vec::new();
    };
    [
        ("total-vm:", memory.total_vm),
        ("anon-rss:", memory.anon_rss),
        ("file-rss:", memory.file_rss),
        ("shmem-rss:", memory.shmem_rss),
        ("pgtables:", memory.page_tables),
    ]
    .into_iter()
    .filter_map(|(key, bytes)| {
        let bytes = bytes?;
        let range = after(&text[start..], key)?;
        Some((
            range.start + start..range.end + start,
            context.bytes(bytes.as_u64().into()),
        ))
    })
    .collect()
}

fn format_record(record: &Record, context: &Context) -> String {
    let text = body(record);
    let replacements = match &record.message {
        OomMessage::MemoryCounters(values) => counters(text, values, context),
        OomMessage::NodeMemory(node) => counters(text, &node.counters, context),
        OomMessage::Killed(process) => process_memory(text, &process.memory, context),
        OomMessage::Reaped(process) => process_memory(text, &process.memory, context),
        OomMessage::LowmemReserves(values) => text
            .find(':')
            .map(|colon| {
                tokens(&text[colon + 1..])
                    .into_iter()
                    .zip(values)
                    .map(|(range, pages)| {
                        (
                            range.start + colon + 1..range.end + colon + 1,
                            context.pages(*pages),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
        OomMessage::HugePages(pool) => [
            (
                "hugepages_total=",
                u128::from(pool.total) * u128::from(pool.size.as_u64()),
            ),
            (
                "hugepages_free=",
                u128::from(pool.free) * u128::from(pool.size.as_u64()),
            ),
            (
                "hugepages_surp=",
                u128::from(pool.surplus) * u128::from(pool.size.as_u64()),
            ),
            ("hugepages_size=", pool.size.as_u64().into()),
        ]
        .into_iter()
        .filter_map(|(key, bytes)| after(text, key).map(|range| (range, context.bytes(bytes))))
        .collect(),
        OomMessage::BuddyInfo(buddy) => {
            let mut replacements: Vec<_> = text
                .match_indices('*')
                .zip(&buddy.blocks)
                .map(|((index, _), block)| {
                    (
                        number(text, index + 1),
                        context.bytes(block.size.as_u64().into()),
                    )
                })
                .collect();
            if let Some(range) = after(text, "= ") {
                replacements.push((range, context.bytes(buddy.total.as_u64().into())));
            }
            replacements
        }
        OomMessage::MemoryTotal(total) => {
            let range = if matches!(total.kind, TotalKind::FreeSwap | TotalKind::TotalSwap) {
                after(text, "=")
            } else {
                Some(number(text, 0))
            };
            let mut replacements: Vec<_> =
                range.zip(context.value(&total.value)).into_iter().collect();
            // The replacement is a size, so remove the old page-count unit.
            if let Some((index, _)) = text.match_indices(" pages").next() {
                replacements.push((index..index + " pages".len(), String::new()));
            }
            replacements
        }
        OomMessage::CgroupBudget(budget) => [("usage ", budget.usage), ("limit ", budget.limit)]
            .into_iter()
            .filter_map(|(key, bytes)| {
                after(text, key).map(|range| (range, context.bytes(bytes.as_u64().into())))
            })
            .collect(),
        OomMessage::CgroupStat(stat) => match stat.value {
            CgroupStatValue::Bytes(bytes) => after(text, &stat.name)
                .map(|range| vec![(range, context.bytes(bytes.as_u64().into()))])
                .unwrap_or_default(),
            _ => Vec::new(),
        },
        OomMessage::Allocation(allocation) => {
            let ranges = tokens(text);
            ranges
                .get(1)
                .map(|unit| {
                    vec![(
                        0..unit.end,
                        context.bytes(allocation.size.bytes.as_u64().into()),
                    )]
                })
                .unwrap_or_default()
        }
        OomMessage::Section(Section::Tasks) => vec![(
            0..text.len(),
            "Tasks state (memory values: size and % of RAM):".into(),
        )],
        OomMessage::Task(task) => {
            let columns = inferred_columns(task);
            return table_line(record, &table_cells(record, &columns, context), &[]);
        }
        _ => Vec::new(),
    };
    replace(record, replacements)
}

fn tokens(text: &str) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut start = None;
    for (index, ch) in text.char_indices() {
        if ch.is_whitespace() {
            if let Some(start) = start.take() {
                ranges.push(start..index);
            }
        } else if start.is_none() {
            start = Some(index);
        }
    }
    if let Some(start) = start {
        ranges.push(start..text.len());
    }
    ranges
}

fn inferred_columns(task: &Task) -> Vec<TaskColumn> {
    let mut columns = vec![
        TaskColumn::Pid,
        TaskColumn::Uid,
        TaskColumn::Tgid,
        TaskColumn::TotalVm,
        TaskColumn::Rss,
    ];
    if task.rss_anon_pages.is_some() {
        columns.extend([
            TaskColumn::RssAnon,
            TaskColumn::RssFile,
            TaskColumn::RssShmem,
        ]);
    }
    if task.page_tables.is_some() {
        columns.push(TaskColumn::PageTablesBytes);
    }
    if task.page_table_pages.is_some() {
        columns.push(TaskColumn::NrPtes);
    }
    if task.pmd_table_pages.is_some() {
        columns.push(TaskColumn::NrPmds);
    }
    if task.pud_table_pages.is_some() {
        columns.push(TaskColumn::NrPuds);
    }
    columns.extend([
        TaskColumn::SwapEntries,
        TaskColumn::OomScoreAdj,
        TaskColumn::Name,
    ]);
    columns
}

fn table_cells(record: &Record, columns: &[TaskColumn], context: &Context) -> Vec<String> {
    let text = body(record);
    let Some(close) = text.find(']') else {
        return vec![text.into()];
    };
    let mut cells = vec![text[..close + 1].into()];
    let remaining = &text[close + 1..];
    let ranges = tokens(remaining);
    for (column, range) in columns.iter().skip(1).zip(&ranges) {
        if *column == TaskColumn::Name {
            cells.push(remaining[range.start..].into());
            break;
        }
        let raw = &remaining[range.clone()];
        let value = match &record.message {
            OomMessage::Task(_) => match column {
                TaskColumn::TotalVm
                | TaskColumn::Rss
                | TaskColumn::RssAnon
                | TaskColumn::RssFile
                | TaskColumn::RssShmem
                | TaskColumn::NrPtes
                | TaskColumn::NrPmds
                | TaskColumn::NrPuds
                | TaskColumn::SwapEntries => raw.parse().ok().map(|pages| context.pages(pages)),
                TaskColumn::PageTablesBytes => raw
                    .parse::<u64>()
                    .ok()
                    .map(|bytes| context.bytes(bytes.into())),
                _ => None,
            },
            _ => match column {
                TaskColumn::PageTablesBytes => Some("pgtables".into()),
                TaskColumn::NrPtes => Some("ptes".into()),
                TaskColumn::NrPmds => Some("pmds".into()),
                TaskColumn::NrPuds => Some("puds".into()),
                TaskColumn::SwapEntries => Some("swap".into()),
                _ => None,
            },
        };
        cells.push(value.unwrap_or_else(|| raw.into()));
    }
    cells
}

fn table_line(record: &Record, cells: &[String], widths: &[usize]) -> String {
    let mut line = record.prefix.clone();
    for (index, cell) in cells.iter().enumerate() {
        if index > 0 {
            line.push_str("  ");
        }
        let width = widths.get(index).copied().unwrap_or(0);
        if index == 0 {
            line.push_str(&format!("{cell:<width$}"));
        } else {
            line.push_str(&format!("{cell:>width$}"));
        }
    }
    line.push_str(&record.original[record.prefix.len() + body(record).len()..]);
    line
}

fn format_table(
    records: &[Record],
    columns: &[TaskColumn],
    context: &Context,
    lines: &mut BTreeMap<usize, String>,
) {
    let rows: Vec<_> = records
        .iter()
        .map(|record| table_cells(record, columns, context))
        .collect();
    let mut widths = vec![0; columns.len()];
    for row in &rows {
        for (index, cell) in row.iter().enumerate().take(columns.len().saturating_sub(1)) {
            widths[index] = widths[index].max(cell.chars().count());
        }
    }
    for (record, cells) in records.iter().zip(rows) {
        lines.insert(record.line_number, table_line(record, &cells, &widths));
    }
}
