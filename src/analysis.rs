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

/// A statement tied to original source lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
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

/// Interpret an event using an explicitly reported 4 KiB base-page assumption.
/// Use [`analyze_event_with_options`] for logs from machines with other page sizes.
///
/// Manual requests take precedence over memory-pressure explanations. Victims
/// and invoking tasks are observations, not proof of which task caused pressure.
/// No leak, fragmentation, or trend is diagnosed from a single snapshot.
pub fn analyze_event(event: &OomEvent) -> OomAnalysis {
    analyze_event_with_options(event, AnalysisOptions::default())
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
    report.limitations.push(format!("Page conversions use a base page size of {}. Verify this against the source machine; use --page-size BYTES to override the CLI default of 4096.", bytes(options.page_size.get().into())));
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
    report
}

impl OomAnalysis {
    fn observe(&mut self, line: usize, description: String) {
        self.evidence.push(Evidence {
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
