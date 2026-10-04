//! OOM-scoped selection for continuous kernel logs.
use crate::{
    OomEvent, OomMessage, ParseError, Record, TaskColumn, TaskLayout, message_start, parse_at,
    parse_timestamp,
};

/// Extract distinct OOM events from a continuous kernel log.
///
/// An invocation (or manual SysRq OOM request) opens diagnostic capture. A kill,
/// new invocation, reboot banner, or unrecognized line closes it. Unrelated
/// diagnostics outside that region are ignored, even if `parse_line` can parse
/// them. Standalone OOM constraint, kill and reaper messages are retained as
/// partial events, as are explicitly printed cgroup budgets/statistics. Delayed reapers are attached to a preceding matching victim
/// (PID and name) within the same observed boot and with a compatible timestamp.
/// Boot banners and backwards uptime jumps greater than 60 seconds reset matching,
/// including uptime changes on unrelated lines outside diagnostic capture.
/// Task table headers select the column layout until the current capture ends.
/// A `memory.oom.group` announcement immediately following a kill (or matched
/// reapers) joins that event and keeps subsequent kills together. A new OOM
/// context, invocation, reboot or unrelated line ends group capture.
///
/// ```
/// use linux_oom_parser::{parse_events, OomMessage};
/// let log = "worker invoked oom-killer: gfp_mask=0xcc0(GFP_KERNEL), order=0, oom_score_adj=0\nOut of memory: Killed process 7 (worker) total-vm:100kB, anon-rss:50kB, file-rss:0kB";
/// let events = parse_events(log)?;
/// assert_eq!(events.len(), 1);
/// assert!(matches!(events[0].records[0].message, OomMessage::Invoked(_)));
/// # Ok::<(), linux_oom_parser::ParseError>(())
/// ```
///
/// Grouping follows log order, not proof of causality. Interleaved diagnostics
/// without identifiers cannot always be attributed; unknown lines conservatively
/// end capture. Incomplete events remain available rather than being dropped.
///
/// # Errors
/// Returns the first malformed supported message in an OOM event. Malformed
/// unrelated messages outside an event do not cause errors.
pub fn parse_events(input: impl AsRef<str>) -> Result<Vec<OomEvent>, ParseError> {
    let mut events: Vec<OomEvent> = Vec::new();
    let mut active: Option<usize> = None;
    let mut pending_kill = None;
    let mut group_event = None;
    let mut layout = None;
    let mut cgroup_stats = false;
    let mut boot_start = 0;
    let mut last_timestamp = None;
    for (index, line) in input.as_ref().split_inclusive('\n').enumerate() {
        let original = line;
        let line = line
            .strip_suffix("\r\n")
            .or_else(|| line.strip_suffix('\n'))
            .unwrap_or(line);
        let start = message_start(line);
        let body = line[start..].trim_end();
        // Numeric timestamps may jump backwards slightly with concurrent printk.
        // A reboot banner is definitive; reaper matching also checks timestamps.
        if body.starts_with("Linux version ") {
            active = None;
            pending_kill = None;
            group_event = None;
            layout = None;
            cgroup_stats = false;
            boot_start = events.len();
            last_timestamp = None;
            continue;
        }
        // Observe uptime on every line, including traffic outside OOM capture.
        // Do not use wall-clock syslog dates to infer reboot boundaries.
        if let Ok(Some(stamp)) = parse_timestamp(&line[..start]) {
            if last_timestamp.is_some_and(|last: jiff::SignedDuration| {
                last - stamp > jiff::SignedDuration::new(60, 0)
            }) {
                active = None;
                pending_kill = None;
                group_event = None;
                layout = None;
                cgroup_stats = false;
                boot_start = events.len();
            }
            last_timestamp = Some(stamp);
        }
        let invocation = body.contains(" invoked oom-killer:");
        let manual = body.starts_with("sysrq: Manual OOM");
        let kill = crate::is_kill_message(body);
        let selection = (body.starts_with("Out of memory")
            || body.starts_with("Memory cgroup out of memory"))
            && body.contains(": Kill process ");
        let cgroup = body.starts_with("Memory cgroup stats for ")
            || body.starts_with("memory: usage ")
            || body.starts_with("memory+swap: usage ")
            || body.starts_with("swap: usage ")
            || body.starts_with("kmem: usage ");
        let context = body.starts_with("oom-kill:");
        let reaper = body.starts_with("oom_reaper: reaped process");
        let group = body.starts_with("Tasks in ") && body.contains("memory.oom.group");
        let specific =
            invocation || manual || kill || selection || cgroup || context || reaper || group;
        if group_event.is_some() && !kill && !reaper && !group {
            active = None;
            pending_kill = None;
            group_event = None;
            layout = None;
            cgroup_stats = false;
        }
        if !specific && active.is_none() {
            pending_kill = None;
            continue;
        }
        if invocation || manual {
            pending_kill = None;
            group_event = None;
            let follows_manual = invocation
                && active.is_some_and(|i| {
                    events[i].records.len() == 1
                        && matches!(events[i].records[0].message, OomMessage::ManualOom)
                });
            if !follows_manual {
                active = Some(events.len());
                events.push(OomEvent {
                    records: Vec::new(),
                });
            }
            layout = None;
            cgroup_stats = false;
        }
        let parsed = if cgroup_stats && !specific {
            if let Some(result) = crate::diagnostics::cgroup_stat(body) {
                Some(crate::Record {
                    line_number: index + 1,
                    prefix: line[..start].into(),
                    timestamp: parse_timestamp(&line[..start]).map_err(|detail| ParseError {
                        line_number: index + 1,
                        input: line.into(),
                        detail,
                    })?,
                    wall_time: crate::timestamps::parse_wall_time(&line[..start]),
                    original: original.into(),
                    message: result.map_err(|detail| ParseError {
                        line_number: index + 1,
                        input: line.into(),
                        detail,
                    })?,
                })
            } else {
                parse_at(line, index + 1, layout)?
            }
        } else {
            parse_at(line, index + 1, layout)?
        };
        let Some(mut record) = parsed else {
            active = None;
            pending_kill = None;
            group_event = None;
            layout = None;
            cgroup_stats = false;
            continue;
        };
        cgroup_stats = matches!(
            record.message,
            OomMessage::CgroupStatsPath(_) | OomMessage::CgroupStat(_)
        );
        record.original = original.into();
        if reaper {
            let target = (boot_start..events.len()).rev().find(|&i| {
                events[i]
                    .records
                    .iter()
                    .any(|prior| reaper_matches(prior, &record))
            });
            if let Some(i) = target {
                events[i].records.push(record);
                if pending_kill != Some(i) {
                    pending_kill = None;
                }
            } else {
                pending_kill = None;
                events.push(OomEvent {
                    records: vec![record],
                });
            }
            continue;
        }
        if let OomMessage::TaskColumns(columns) = &record.message {
            layout = Some(if columns.contains(&TaskColumn::RssAnon) {
                TaskLayout::RssBreakdown
            } else if columns.contains(&TaskColumn::NrPtes) {
                TaskLayout::Legacy {
                    pmds: columns.contains(&TaskColumn::NrPmds),
                    puds: columns.contains(&TaskColumn::NrPuds),
                }
            } else {
                TaskLayout::TotalRss
            });
        }
        // The announcement follows the initially selected victim's kill, which
        // already closed ordinary capture. Reopen only that adjacent event.
        if group && active.is_none() {
            active = pending_kill.take();
        }
        let event = match active {
            Some(i) => i,
            None => {
                events.push(OomEvent {
                    records: Vec::new(),
                });
                events.len() - 1
            }
        };
        events[event].records.push(record);
        if group {
            group_event = Some(event);
        }
        if kill {
            if group_event == Some(event) {
                active = Some(event);
                pending_kill = None;
            } else {
                active = None;
                pending_kill = Some(event);
            }
            layout = None;
            cgroup_stats = false;
        } else {
            pending_kill = None;
            active = Some(event);
        }
    }
    Ok(events)
}

fn reaper_matches(prior: &Record, current: &Record) -> bool {
    let (OomMessage::Killed(kill), OomMessage::Reaped(reaper)) = (&prior.message, &current.message)
    else {
        return false;
    };
    kill.pid == reaper.pid
        && kill.name == reaper.name
        && match (prior.timestamp, current.timestamp) {
            (Some(before), Some(after)) => before <= after,
            _ => true,
        }
}
