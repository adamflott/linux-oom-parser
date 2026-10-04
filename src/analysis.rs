//! Evidence-based interpretation of parsed OOM events. No live system inspection.
use crate::{Constraint, MemoryValue, OomEvent, OomMessage, OomScope, TotalKind};
use std::fmt;

/// How the available records explain entry into the OOM killer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OomReason {
    /// Explicit manual SysRq request (including the kernel's order=-1 marker).
    Manual,
    /// Memory cgroup limit could not be satisfied.
    MemoryCgroup,
    /// Memory available within a cpuset was insufficient.
    Cpuset,
    /// Memory available under a NUMA policy was insufficient.
    MemoryPolicy,
    /// Global allocation failure, subject to allocation eligibility constraints.
    Global,
    /// Allocation failure without sufficient scope information.
    AllocationFailure,
    /// Too little information to determine the trigger.
    Unknown,
}

/// Category of a diagnostic observation, shared by API consumers and rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvidenceKind {
    /// Invocation, scope, victim, swap, zone minimum or largest-task observation.
    Observation,
    /// Cgroup budget or composition.
    Cgroup,
    /// Contiguous blocks, watermarks or allocation rules.
    Allocation,
    /// Page-size validation.
    PageSize,
    /// System memory composition.
    Memory,
    /// Legacy kernel diagnostic details.
    Legacy,
}

/// A statement tied to original source lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// Diagnostic category.
    pub kind: EvidenceKind,
    /// One-based original source line numbers.
    pub lines: Vec<usize>,
    /// Human-readable observation.
    pub description: String,
}

/// Analysis of one event. Possible causes are hypotheses, never diagnoses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OomAnalysis {
    /// Classified trigger.
    pub reason: OomReason,
    /// Explanation of the trigger and scope.
    pub explanation: String,
    /// Observations drawn from parsed fields.
    pub evidence: Vec<Evidence>,
    /// Plausible contributors and investigation leads.
    pub possible_causes: Vec<String>,
    /// Prevention and verification steps; no changes are executed.
    pub recommendations: Vec<String>,
    /// Missing information and limits on conclusions.
    pub limitations: Vec<String>,
}

/// Options for converting logged page counts into byte sizes.
#[derive(Debug, Clone, Copy)]
pub struct AnalysisOptions {
    /// Base page size of the machine that produced the log (not the analysis host).
    pub page_size: std::num::NonZeroU64,
}
impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            page_size: const {
                match std::num::NonZeroU64::new(4096) {
                    Some(size) => size,
                    None => panic!("the default page size must be nonzero"),
                }
            },
        }
    }
}

fn bytes(value: u128) -> String {
    if let Ok(value) = u64::try_from(value) {
        format!(
            "{} ({value} bytes)",
            crate::ByteSize::b(value).display().iec()
        )
    } else {
        // Multiplication of two u64 values fits u128. Preserve the exact count
        // even when it exceeds ByteSize's range.
        format!(
            "{:.2} EiB ({value} bytes)",
            value as f64 / (1u64 << 60) as f64
        )
    }
}
fn optional_bytes(value: Option<crate::ByteSize>) -> String {
    value.map_or_else(|| "not reported".into(), |v| bytes(v.as_u64().into()))
}
fn pages(count: u64, options: AnalysisOptions) -> String {
    format!(
        "{count} pages ({})",
        bytes(u128::from(count) * u128::from(options.page_size.get()))
    )
}

/// Page-size evidence from order-zero buddy buckets and their doubling sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PageSizeInference {
    /// Every captured buddy row has consistent bucket sizes and the same base size.
    Consistent {
        /// Inferred base page size, independent of the analysis host.
        page_size: std::num::NonZeroU64,
        /// Source lines establishing the size.
        lines: Vec<usize>,
    },
    /// Buddy rows disagree or have invalid bucket geometry; automatic inference is refused.
    Inconsistent {
        /// Source lines with buddy information.
        lines: Vec<usize>,
    },
}

/// Infer base page size from buddy rows, returning `None` when none were captured.
/// A truncated or inconsistent bucket sequence is not accepted as evidence.
pub fn infer_page_size(event: &OomEvent) -> Option<PageSizeInference> {
    let rows: Vec<_> = event
        .records
        .iter()
        .filter_map(|r| match &r.message {
            OomMessage::BuddyInfo(b) => Some((r.line_number, b)),
            _ => None,
        })
        .collect();
    if rows.is_empty() {
        return None;
    }
    let lines = rows.iter().map(|(line, _)| *line).collect();
    let base = rows
        .first()?
        .1
        .blocks
        .first()
        .map(|b| b.size.as_u64())
        .unwrap_or(0);
    let consistent = base >= 1024
        && base.is_power_of_two()
        && rows.iter().all(|(_, row)| {
            !row.blocks.is_empty()
                && row.blocks.iter().enumerate().all(|(order, block)| {
                    u32::try_from(order)
                        .ok()
                        .and_then(|n| 1u64.checked_shl(n))
                        .and_then(|n| base.checked_mul(n))
                        == Some(block.size.as_u64())
                })
        });
    if consistent {
        std::num::NonZeroU64::new(base)
            .map(|page_size| PageSizeInference::Consistent { page_size, lines })
    } else {
        Some(PageSizeInference::Inconsistent { lines })
    }
}

/// Interpret an event using inferred buddy page size, falling back to 4 KiB.
///
/// Use [`analyze_event_with_options`] to supply an explicit page size.
///
/// Manual requests take precedence over memory-pressure explanations. Victims
/// and invoking tasks are observations, not proof of which task caused pressure.
/// No leak, fragmentation, or trend is diagnosed from a single snapshot.
pub fn analyze_event(event: &OomEvent) -> OomAnalysis {
    let mut options = AnalysisOptions::default();
    if let Some(PageSizeInference::Consistent { page_size, .. }) = infer_page_size(event) {
        options.page_size = page_size;
    }
    analyze_event_with_options(event, options)
}

/// Interpret an event using the supplied base page size for all page conversions.
/// The report states the conversion size; the log does not necessarily confirm it.
pub fn analyze_event_with_options(event: &OomEvent, options: AnalysisOptions) -> OomAnalysis {
    let invocation = event.records.iter().find_map(|r| match &r.message {
        OomMessage::Invoked(i) => Some((r.line_number, i)),
        _ => None,
    });
    let context = event.records.iter().find_map(|r| match &r.message {
        OomMessage::OomContext(c) => Some((r.line_number, c)),
        _ => None,
    });
    let killed = event.records.iter().find_map(|r| match &r.message {
        OomMessage::Killed(k) => Some((r.line_number, k)),
        _ => None,
    });
    let manual = event
        .records
        .iter()
        .find(|r| matches!(r.message, OomMessage::ManualOom));
    let reason = if manual.is_some() || invocation.is_some_and(|(_, i)| i.order == -1) {
        OomReason::Manual
    } else if context.is_some_and(|(_, c)| {
        matches!(c.scope, OomScope::MemoryCgroup(_)) || c.constraint == Constraint::MemoryCgroup
    }) || killed.is_some_and(|(_, k)| k.memory_cgroup)
        || event.records.iter().any(|r| {
            matches!(
                r.message,
                OomMessage::CgroupBudget(_) | OomMessage::CgroupStatsPath(_)
            )
        })
    {
        OomReason::MemoryCgroup
    } else if let Some((_, c)) = context {
        match c.constraint {
            Constraint::Cpuset => OomReason::Cpuset,
            Constraint::MemoryPolicy => OomReason::MemoryPolicy,
            Constraint::None => OomReason::Global,
            _ => OomReason::Unknown,
        }
    } else if invocation.is_some() {
        OomReason::AllocationFailure
    } else {
        OomReason::Unknown
    };
    let (explanation, causes, steps): (&str, &[&str], &[&str]) = match reason {
        OomReason::Manual => (
            "The OOM killer was explicitly requested through the manual SysRq path. This does not establish memory exhaustion.",
            &["An operator, test, or privileged automation may have requested a manual OOM."],
            &[
                "Check operator activity, test jobs, and automation that writes to /proc/sysrq-trigger; remove unintended manual OOM triggers.",
            ],
        ),
        OomReason::MemoryCgroup => (
            "The memory cgroup could not satisfy a memory charge within its effective limit after reclaim. The host may still have free memory.",
            &[
                "The workload may have exceeded its container/service memory budget, or an ancestor cgroup limit may be tighter than expected.",
            ],
            &[
                "Inspect the affected cgroup and its ancestors: on cgroup v2, compare memory.current, memory.max, memory.high, memory.events, memory.stat, and memory.swap.max; use equivalent controls on v1.",
                "Bound workload concurrency, caches, and heap size to fit the effective limit. Increase limits only after checking host and ancestor capacity.",
            ],
        ),
        OomReason::Cpuset | OomReason::MemoryPolicy => (
            "The allocation could not be satisfied within the allowed NUMA nodes or cpuset. Free memory elsewhere may be ineligible.",
            &[
                "NUMA placement or cpuset restrictions may concentrate demand on a subset of memory nodes.",
            ],
            &[
                "Compare the logged allowed nodes with per-node memory usage and the workload's cpuset/NUMA policy. Rebalance placement or broaden allowed nodes when appropriate.",
            ],
        ),
        OomReason::Global => (
            "The kernel entered the global OOM path because an allocation could not be satisfied after reclaim. This does not mean every byte of host RAM was used.",
            &[
                "Combined workload demand, a transient allocation burst, or retained application/kernel memory may have exceeded reclaimable capacity.",
            ],
            &[
                "Measure peak resident memory and workload concurrency; bound caches, heaps, and parallel jobs, or add capacity based on measured peaks.",
            ],
        ),
        OomReason::AllocationFailure => (
            "A task invoked the OOM killer after an allocation could not be satisfied, but the available records do not establish its memory scope.",
            &["Memory pressure or allocation restrictions are possible; the scope is missing."],
            &[
                "Capture the complete OOM dump, especially the oom-kill constraint line, before choosing between host-capacity, cgroup-limit, and NUMA-policy changes.",
            ],
        ),
        OomReason::Unknown => (
            "The available records do not establish why the OOM killer was invoked.",
            &[
                "An isolated kill or reaper message cannot identify the original allocation failure or manual trigger.",
            ],
            &[
                "Collect the preceding invocation, constraint, memory counters, and task table from the same boot.",
            ],
        ),
    };
    let mut report = OomAnalysis {
        reason, explanation: explanation.into(), evidence: Vec::new(),
        possible_causes: causes.iter().map(|s| (*s).into()).collect(),
        recommendations: steps.iter().map(|s| (*s).into()).collect(),
        limitations: vec!["This log is a snapshot: it cannot prove a memory leak, reconstruct earlier growth, or show current system configuration. The invoking task and killed victim need not be the cause.".into()],
    };
    report.limitations.push(format!("Page conversions use a base page size of {}. Verify this against the source machine; use --page-size BYTES to override automatic inference or the 4096-byte fallback.", bytes(options.page_size.get().into())));
    if let Some(r) = manual {
        report.observe(r.line_number, "Manual SysRq OOM request recorded.".into());
    }
    if let Some((line, i)) = invocation {
        report.observe(
            line,
            format!(
                "Invoking task {:?}; allocation order {}; GFP mask {:#x}; symbolic flags {:?}.",
                i.name, i.order, i.gfp_mask, i.gfp_flags
            ),
        );
        if i.order > 0 && reason != OomReason::Manual {
            report.possible_causes.push(format!("Order {} requests physically contiguous pages; fragmentation or a shortage of eligible blocks may contribute, but order alone does not prove fragmentation.", i.order));
            report.recommendations.push("Inspect the allocation call trace and buddy allocator distribution for eligible zones; investigate large contiguous allocations before changing VM tuning.".into());
        }
    }
    if let Some((line, c)) = context {
        report.observe(
            line,
            format!(
                "Constraint {:?}; scope {:?}; cpuset {:?}; allowed nodes {:?}; victim cgroup {:?}.",
                c.constraint, c.scope, c.cpuset, c.mems_allowed, c.task_memcg
            ),
        );
    }
    if let Some((line, k)) = killed {
        report.observe(line, format!("Killed PID {} ({:?}); anonymous RSS {}, file RSS {}, shared RSS {}; oom_score_adj {:?}. Virtual address space is not resident memory.", k.pid, k.name, optional_bytes(k.memory.anon_rss), optional_bytes(k.memory.file_rss), optional_bytes(k.memory.shmem_rss), k.oom_score_adj));
    } else {
        report.limitations.push("No kill record was captured; this may be an incomplete event. A successful kill is not confirmed.".into());
    }
    let mut swap_total = None;
    let mut swap_free = None;
    for r in &event.records {
        if let OomMessage::MemoryTotal(t) = &r.message {
            if let MemoryValue::Bytes(size) = t.value {
                match t.kind {
                    TotalKind::TotalSwap => swap_total = Some((r.line_number, size.as_u64())),
                    TotalKind::FreeSwap => swap_free = Some((r.line_number, size.as_u64())),
                    _ => {}
                }
            }
        }
    }
    if reason != OomReason::Manual {
        if let Some((line, 0)) = swap_total {
            report.observe(
                line,
                format!("The dump reports zero total swap: {}.", bytes(0)),
            );
            report.possible_causes.push("No swap capacity was available as a buffer for swappable memory; this alone does not explain the OOM.".into());
            report.recommendations.push("Evaluate swap or zram for transient pressure if latency requirements permit; check cgroup swap limits. Swap does not replace sufficient RAM for the active working set.".into());
        } else if let (Some((total_line, total)), Some((free_line, 0))) = (swap_total, swap_free) {
            if total > 0 {
                report.evidence.push(Evidence {
                    kind: EvidenceKind::Observation,
                    lines: vec![total_line, free_line],
                    description: format!(
                        "Configured swap had no free space in the dump: total {}, free {}.",
                        bytes(total.into()),
                        bytes(0)
                    ),
                });
                report
                    .possible_causes
                    .push("Exhausted swap may have limited reclaim of anonymous memory.".into());
                report.recommendations.push("Measure swap usage and paging latency over time; reduce memory demand and evaluate swap capacity and cgroup swap limits.".into());
            }
        }
        report.recommendations.push("Collect time-series process/cgroup memory, memory pressure (PSI), and workload metrics around future events. Use growth profiles to distinguish leaks from bursts; do not use oom_score_adj changes as a capacity fix.".into());
    }
    // Compare only counters in the same zone and with the same unit.
    let mut constrained_zones = 0;
    for r in &event.records {
        if let OomMessage::NodeMemory(node) = &r.message {
            let Some(zone) = &node.zone else {
                continue;
            };
            let value = |metric| {
                node.counters
                    .iter()
                    .find(|c| c.metric == metric)
                    .map(|c| &c.value)
            };
            if let (Some(MemoryValue::Bytes(free)), Some(MemoryValue::Bytes(min))) = (
                value(crate::MemoryMetric::Free),
                value(crate::MemoryMetric::Min),
            ) {
                if free < min {
                    constrained_zones += 1;
                    if constrained_zones <= 3 {
                        report.observe(r.line_number, format!("Node {} zone {}: free {} is below the printed minimum {}. Allocation eligibility and reserves still matter.", node.node, zone, bytes(free.as_u64().into()), bytes(min.as_u64().into())));
                    }
                }
            }
        }
    }
    if constrained_zones > 0 && reason != OomReason::Manual {
        report.possible_causes.push(format!("{constrained_zones} zone(s) show free memory below their printed minimum. Local zone pressure may contribute, but the dump does not establish that each zone was eligible for this allocation."));
        report.recommendations.push("Track per-node/zone pressure and allocation eligibility alongside host memory; host-wide free memory can hide a shortage in an eligible zone.".into());
    }
    let mut tasks: Vec<_> = event
        .records
        .iter()
        .filter_map(|r| match &r.message {
            OomMessage::Task(t) => Some((r.line_number, t)),
            _ => None,
        })
        .collect();
    tasks.sort_by_key(|a| std::cmp::Reverse(a.1.rss_pages));
    for (line, t) in tasks.into_iter().take(3) {
        report.observe(line, format!("Large task in this snapshot: PID {} ({:?}), RSS {}, oom_score_adj {}. Shared pages may overlap other tasks.", t.pid, t.name, pages(t.rss_pages, options), t.oom_score_adj));
    }
    match infer_page_size(event) {
        Some(PageSizeInference::Consistent { page_size, lines }) => {
            let conflict = if page_size == options.page_size {
                "matches the conversion size"
            } else {
                "CONFLICTS with the supplied conversion size; conversions retain the supplied size"
            };
            report.finding(
                EvidenceKind::PageSize,
                lines,
                format!(
                    "Buddy buckets indicate {} base pages; this {conflict} ({}).",
                    bytes(page_size.get().into()),
                    bytes(options.page_size.get().into())
                ),
            );
            if page_size != options.page_size {
                report.limitations.push("Buddy page-size evidence conflicts with the supplied page size. Verify the source machine before interpreting converted quantities.".into());
            }
        }
        Some(PageSizeInference::Inconsistent { lines }) => {
            report.finding(
                EvidenceKind::PageSize,
                lines,
                "Buddy bucket sizes are inconsistent; no base page size was inferred.".into(),
            );
            report.limitations.push("Inconsistent buddy sizes prevent automatic page-size inference; conversions use the supplied size.".into());
        }
        None => {}
    }
    analyze_cgroup(event, &mut report);
    analyze_buddy(event, options, &mut report);
    analyze_watermarks(event, options, &mut report);
    report
}

fn analyze_watermarks(event: &OomEvent, options: AnalysisOptions, report: &mut OomAnalysis) {
    use crate::{GfpFlag, MemoryMetric};
    if matches!(report.reason, OomReason::Manual | OomReason::MemoryCgroup) {
        return;
    }
    let invocation = event.records.iter().find_map(|r| match &r.message {
        OomMessage::Invoked(i) => Some((r.line_number, i)),
        _ => None,
    });
    let context = event.records.iter().find_map(|r| match &r.message {
        OomMessage::OomContext(c) => Some(c),
        _ => None,
    });
    if let Some((line, invocation)) = invocation {
        if let Some(flags) = &invocation.gfp_flags {
            let zone = if flags
                .iter()
                .any(|f| matches!(f, GfpFlag::Dma | GfpFlag::FlagDma))
            {
                "DMA"
            } else if flags
                .iter()
                .any(|f| matches!(f, GfpFlag::Dma32 | GfpFlag::FlagDma32))
            {
                "DMA32"
            } else if flags.iter().any(|f| {
                matches!(
                    f,
                    GfpFlag::HighuserMovable | GfpFlag::Transhuge | GfpFlag::TranshugeLight
                )
            }) {
                "high/movable memory"
            } else if flags
                .iter()
                .any(|f| matches!(f, GfpFlag::Highuser | GfpFlag::FlagHighmem))
            {
                "high memory"
            } else {
                "no explicit DMA/high-memory restriction"
            };
            let modifiers = flags
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" | ");
            report.finding(EvidenceKind::Allocation, vec![line], format!(
                "Printed allocation flags {modifiers}: {zone}. Fallback zones and reserves depend on kernel configuration. __GFP_HIGH may relax watermarks; __GFP_MEMALLOC may access reserves; __GFP_THISNODE restricts fallback."));
        } else {
            report.limitations.push("Symbolic allocation flags were not printed; numeric GFP masks require version-aware decoding before zone or reserve rules can be interpreted.".into());
        }
    }
    let mut pressure = false;
    for (index, record) in event.records.iter().enumerate() {
        let OomMessage::NodeMemory(node) = &record.message else {
            continue;
        };
        let Some(zone) = &node.zone else {
            continue;
        };
        if !node_permitted(node.node, context) {
            continue;
        }
        let value = |metric| {
            node.counters.iter().find_map(|c| {
                if c.metric == metric {
                    if let MemoryValue::Bytes(v) = c.value {
                        Some(v.as_u64())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
        };
        let (Some(free), Some(low)) = (value(MemoryMetric::Free), value(MemoryMetric::Low)) else {
            continue;
        };
        let mut lines = vec![record.line_number];
        let mut detail = format!(
            "Node {} zone {}: free {}, low watermark {}",
            node.node,
            zone,
            bytes(free.into()),
            bytes(low.into())
        );
        for (metric, label) in [
            (MemoryMetric::Min, "minimum"),
            (MemoryMetric::High, "high watermark"),
            (MemoryMetric::Boost, "watermark boost"),
            (MemoryMetric::ReservedHighatomic, "high-atomic reserve"),
            (MemoryMetric::FreeHighatomic, "free high-atomic reserve"),
            (MemoryMetric::FreeCma, "free CMA"),
        ] {
            if let Some(value) = value(metric) {
                detail.push_str(&format!("; {label} {}", bytes(value.into())));
            }
        }
        // Reserve vectors have no intrinsic node identity. Attach only a directly
        // following vector and retain its original zone-index order.
        if let Some(next) = event.records.get(index + 1) {
            if next.line_number == record.line_number + 1 {
                if let OomMessage::LowmemReserves(reserves) = &next.message {
                    lines.push(next.line_number);
                    detail.push_str(&format!("; lowmem_reserve[] {reserves:?} pages in printed zone-index order ({} per page)", bytes(options.page_size.get().into())));
                }
            }
        }
        if free < low {
            pressure = true;
            detail.push_str(". Free memory is below the printed low watermark");
        }
        detail.push_str(". This comparison does not include the kernel's allocation-specific watermark adjustments, unusable free pages or reserve-index selection; it cannot prove the exact failure reason.");
        report.finding(EvidenceKind::Allocation, lines, detail);
    }
    if pressure {
        report.possible_causes.push("Free memory below a printed low watermark may restrict allocations even when some pages remain free; allocation flags and reserves determine eligibility.".into());
        report.recommendations.push("Compare the request's GFP flags, allowed NUMA nodes, zone watermarks, low-memory reserve vectors and buddy migration types before changing VM tuning.".into());
    }
}

fn node_permitted(node: u32, context: Option<&crate::OomContext>) -> bool {
    let Some(context) = context else {
        return true;
    };
    let contains =
        |ranges: &[crate::NodeRange]| ranges.iter().any(|r| r.start <= node && node <= r.end);
    contains(&context.mems_allowed)
        && context
            .nodemask
            .as_ref()
            .is_none_or(|ranges| contains(ranges))
}

fn analyze_buddy(event: &OomEvent, options: AnalysisOptions, report: &mut OomAnalysis) {
    if matches!(report.reason, OomReason::Manual | OomReason::MemoryCgroup) {
        return;
    }
    let invocation = event.records.iter().find_map(|r| match &r.message {
        OomMessage::Invoked(i) => Some((r.line_number, i)),
        _ => None,
    });
    let Some((invoke_line, invocation)) = invocation else {
        return;
    };
    let Some(request) = u32::try_from(invocation.order)
        .ok()
        .and_then(|order| 1u128.checked_shl(order))
        .and_then(|pages| pages.checked_mul(u128::from(options.page_size.get())))
    else {
        report.limitations.push("Allocation order cannot be converted safely into a request size; buddy availability was not evaluated.".into());
        return;
    };
    let context = event.records.iter().find_map(|r| match &r.message {
        OomMessage::OomContext(c) => Some(c),
        _ => None,
    });
    let mut found = false;
    for record in &event.records {
        let OomMessage::BuddyInfo(buddy) = &record.message else {
            continue;
        };
        if !node_permitted(buddy.node, context) {
            continue;
        }
        found = true;
        let fitting: u128 = buddy
            .blocks
            .iter()
            .filter(|b| u128::from(b.size.as_u64()) >= request)
            .map(|b| u128::from(b.count))
            .sum();
        let largest = buddy
            .blocks
            .iter()
            .filter(|b| b.count > 0)
            .map(|b| b.size.as_u64())
            .max();
        let status = if fitting == 0 {
            "no printed free block is large enough"
        } else {
            "printed free blocks are large enough, but this does not guarantee allocation success"
        };
        let largest = largest.map_or_else(|| "none".into(), |size| bytes(size.into()));
        report.finding(EvidenceKind::Allocation, vec![invoke_line, record.line_number], format!(
            "Node {} zone {} buddy snapshot: request {}; {status} ({fitting} blocks at this size or larger). Largest printed free block: {largest}. Zone eligibility, migration types, CMA and high-atomic reserves can restrict use.",
            buddy.node, buddy.zone, bytes(request)));
        let threshold = u128::from(options.page_size.get()) * 8;
        if !buddy
            .blocks
            .iter()
            .any(|b| b.count > 0 && u128::from(b.size.as_u64()) >= threshold)
        {
            report.finding(EvidenceKind::Allocation, vec![record.line_number], format!(
                "Node {} zone {} has no printed free blocks of {} or larger (order 3+). This is consistent with fragmentation or depletion; this snapshot cannot distinguish them.", buddy.node, buddy.zone, bytes(threshold)));
        }
    }
    if !found {
        report.limitations.push("No buddy distribution was captured for a permitted node; contiguous-block availability is unknown.".into());
    }
}

fn analyze_cgroup(event: &OomEvent, report: &mut OomAnalysis) {
    use crate::{CgroupResource, CgroupStatValue};
    if let Some(record) = event
        .records
        .iter()
        .find(|r| matches!(r.message, OomMessage::CgroupStatsPath(_)))
    {
        if let OomMessage::CgroupStatsPath(path) = &record.message {
            report.finding(
                EvidenceKind::Cgroup,
                vec![record.line_number],
                format!("Cgroup statistics describe {path:?}."),
            );
        }
    }
    for record in &event.records {
        match &record.message {
            OomMessage::CgroupBudget(budget) => {
                let usage = budget.usage.as_u64();
                let limit = budget.limit.as_u64();
                let status = if limit == 0 {
                    if budget.resource == CgroupResource::Swap {
                        "swap allowance is zero"
                    } else {
                        "printed limit is zero"
                    }
                } else if usage >= limit {
                    "at or above the printed limit"
                } else {
                    "below the printed limit"
                };
                report.finding(EvidenceKind::Cgroup, vec![record.line_number], format!(
                    "Cgroup {}: usage {}, printed limit {} ({status}); cumulative failcnt {}. Failed charges are not a count of OOM kills; very large limits may be unlimited sentinels.",
                    budget.resource, bytes(usage.into()), bytes(limit.into()), budget.fail_count));
            }
            OomMessage::CgroupStat(stat) => {
                let value = match stat.value {
                    CgroupStatValue::Bytes(v) => bytes(v.as_u64().into()),
                    CgroupStatValue::Count(n) => format!("{n} cumulative events (not a rate)"),
                    CgroupStatValue::Unknown(n) => format!("{n} (unit unknown)"),
                };
                report.finding(
                    EvidenceKind::Cgroup,
                    vec![record.line_number],
                    format!("Cgroup {}: {value}.", stat.name),
                );
            }
            OomMessage::OomContext(context) => {
                if let OomScope::MemoryCgroup(path) = &context.scope {
                    report.finding(EvidenceKind::Cgroup, vec![record.line_number], format!(
                        "Limiting OOM cgroup {path:?}; victim membership {:?}. The limiting cgroup can be an ancestor of the victim's cgroup.", context.task_memcg));
                }
            }
            _ => {}
        }
    }
}

impl OomAnalysis {
    fn finding(&mut self, kind: EvidenceKind, lines: Vec<usize>, description: String) {
        self.evidence.push(Evidence {
            kind,
            lines,
            description,
        });
    }
    fn observe(&mut self, line: usize, description: String) {
        self.evidence.push(Evidence {
            kind: EvidenceKind::Observation,
            lines: vec![line],
            description,
        });
    }
}

impl fmt::Display for OomAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Why the OOM killer was invoked:\n  {}", self.explanation)?;
        writeln!(f, "Evidence:")?;
        if self.evidence.is_empty() {
            writeln!(f, "  No diagnostic evidence captured.")?;
        }
        for e in &self.evidence {
            writeln!(f, "  - Lines {:?}: {}", e.lines, e.description)?;
        }
        for (heading, items) in [
            ("Possible causes (not confirmed)", &self.possible_causes),
            ("Prevention and next checks", &self.recommendations),
            ("Limits of this analysis", &self.limitations),
        ] {
            writeln!(f, "{heading}:")?;
            for item in items {
                writeln!(f, "  - {item}")?;
            }
        }
        Ok(())
    }
}
