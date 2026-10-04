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

/// Stable identity of a machine-readable observation, independent of prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FindingCode {
    /// The dump reports no configured swap.
    SwapUnavailable,
    /// Configured swap has no free space.
    SwapExhausted,
    /// Swap capacity without an exhaustion observation.
    SwapCapacity,
    /// A candidate zone is below its printed minimum.
    ZoneBelowMinimum,
    /// A candidate zone is below its printed low watermark.
    ZoneBelowLow,
    /// A candidate zone is at or above its printed low watermark.
    ZoneWatermark,
    /// Validated buddy buckets have no block large enough for the request.
    BuddyShortage,
    /// Validated buddy buckets have blocks large enough for the request.
    BuddyAvailability,
    /// Printed cgroup usage and budget, without interpreting unlimited sentinels.
    CgroupBudget,
}

/// Typed measurements supporting a finding. Byte quantities retain exact units.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FindingData {
    /// Swap totals; `None` means free swap was not reported.
    Swap {
        /// Printed total swap bytes.
        total: crate::ByteSize,
        /// Printed free swap bytes.
        free: Option<crate::ByteSize>,
    },
    /// Free memory compared with a printed zone watermark.
    ZoneWatermark {
        /// NUMA node identifier.
        node: u32,
        /// Printed memory zone.
        zone: crate::MemoryZone,
        /// Printed free bytes.
        free: crate::ByteSize,
        /// Printed threshold bytes.
        threshold: crate::ByteSize,
        /// Watermark used for comparison (`Min` or `Low`).
        metric: crate::MemoryMetric,
    },
    /// Buddy availability under consistent geometry and the selected page size.
    Buddy {
        /// NUMA node identifier.
        node: u32,
        /// Candidate memory zone.
        zone: crate::MemoryZone,
        /// Allocation request in bytes, widened to preserve large orders.
        request_bytes: u128,
        /// Number of printed blocks at least as large as the request.
        fitting_blocks: u128,
        /// Largest nonempty printed bucket; absent when all counts are zero.
        largest_block: Option<crate::ByteSize>,
    },
    /// Printed cgroup budget; usage below a limit does not exclude failed charges.
    CgroupBudget {
        /// Resource constrained by this budget.
        resource: crate::CgroupResource,
        /// Printed usage bytes.
        usage: crate::ByteSize,
        /// Printed limit bytes; may be an unlimited sentinel.
        limit: crate::ByteSize,
        /// Cumulative failed charges, not OOM kills.
        fail_count: u64,
    },
}

/// A typed observation with the same original source references as its evidence.
/// These observations describe snapshots and do not prove allocation eligibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredFinding {
    /// One-based original source line numbers.
    pub lines: Vec<usize>,
    /// Exact measurements supporting the observation.
    pub data: FindingData,
}

impl StructuredFinding {
    /// Classify the measurements without parsing human-readable descriptions.
    pub fn code(&self) -> FindingCode {
        match &self.data {
            FindingData::Swap { total, .. } if total.as_u64() == 0 => FindingCode::SwapUnavailable,
            FindingData::Swap {
                free: Some(free), ..
            } if free.as_u64() == 0 => FindingCode::SwapExhausted,
            FindingData::Swap { .. } => FindingCode::SwapCapacity,
            FindingData::ZoneWatermark {
                free,
                threshold,
                metric,
                ..
            } => {
                if free >= threshold {
                    FindingCode::ZoneWatermark
                } else if *metric == crate::MemoryMetric::Min {
                    FindingCode::ZoneBelowMinimum
                } else {
                    FindingCode::ZoneBelowLow
                }
            }
            FindingData::Buddy {
                fitting_blocks: 0, ..
            } => FindingCode::BuddyShortage,
            FindingData::Buddy { .. } => FindingCode::BuddyAvailability,
            FindingData::CgroupBudget { .. } => FindingCode::CgroupBudget,
        }
    }
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
    /// Typed swap, watermark, buddy and cgroup observations. Other evidence remains
    /// available in `evidence`; this collection does not yet cover every category.
    pub structured_findings: Vec<StructuredFinding>,
    /// Selected conversion size, its origin, and supporting or conflicting evidence.
    pub page_size: PageSizeSelection,
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
    pub page_size: PageSize,
}

/// A power-of-two base page size of at least 1024 bytes.
/// Validation checks geometry, not whether a particular machine supports the size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageSize(std::num::NonZeroU64);

/// An invalid base page size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPageSize;
impl fmt::Display for InvalidPageSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("page size must be a power of two of at least 1024 bytes")
    }
}
impl std::error::Error for InvalidPageSize {}
impl PageSize {
    /// Validate a byte count as a base page size.
    pub fn new(bytes: u64) -> Result<Self, InvalidPageSize> {
        if bytes < 1024 || !bytes.is_power_of_two() {
            return Err(InvalidPageSize);
        }
        std::num::NonZeroU64::new(bytes)
            .map(Self)
            .ok_or(InvalidPageSize)
    }
    /// Return the exact byte count.
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}
impl TryFrom<u64> for PageSize {
    type Error = InvalidPageSize;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl std::str::FromStr for PageSize {
    type Err = InvalidPageSize;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value.parse().map_err(|_| InvalidPageSize)?)
    }
}

/// Origin of the selected page conversion size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PageSizeSource {
    /// Supplied through explicit analysis options, even when equal to the default.
    Explicit,
    /// Inferred from consistent printed buddy buckets.
    Buddy,
    /// Assumed 4096 bytes because usable buddy evidence was absent.
    Fallback,
}

/// Relationship between printed buddy evidence and the selected size.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PageSizeEvidence {
    /// No buddy rows were captured.
    Missing,
    /// Buddy geometry confirms the selected conversion size.
    Consistent {
        /// Original source lines.
        lines: Vec<usize>,
    },
    /// Consistent buddy geometry disagrees with an explicit size.
    Conflicting {
        /// Size inferred from the log.
        inferred: PageSize,
        /// Original source lines.
        lines: Vec<usize>,
    },
    /// Buddy rows disagree or have invalid geometry.
    Inconsistent {
        /// Original source lines.
        lines: Vec<usize>,
    },
}

/// Structured provenance for every page-to-byte conversion in an analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageSizeSelection {
    /// Validated size used for conversions.
    pub page_size: PageSize,
    /// How the conversion size was selected.
    pub source: PageSizeSource,
    /// Supporting, missing, inconsistent or conflicting log evidence.
    pub evidence: PageSizeEvidence,
}
impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            page_size: PageSize(
                const {
                    match std::num::NonZeroU64::new(4096) {
                        Some(size) => size,
                        None => panic!("the default page size must be nonzero"),
                    }
                },
            ),
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
        page_size: PageSize,
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
/// Inconsistent order-zero sizes or non-doubling bucket sequences are rejected.
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
        PageSize::new(base)
            .ok()
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
    let facts = AllocationFacts::new(event);
    let mut options = AnalysisOptions::default();
    let source = if let Some(PageSizeInference::Consistent { page_size, .. }) = &facts.page_size {
        options.page_size = *page_size;
        PageSizeSource::Buddy
    } else {
        PageSizeSource::Fallback
    };
    analyze_with_facts(event, options, facts, source)
}

/// Interpret an event using an explicitly supplied, validated base page size.
/// The result records supporting or conflicting buddy evidence.
pub fn analyze_event_with_options(event: &OomEvent, options: AnalysisOptions) -> OomAnalysis {
    analyze_with_facts(
        event,
        options,
        AllocationFacts::new(event),
        PageSizeSource::Explicit,
    )
}

fn analyze_with_facts(
    event: &OomEvent,
    options: AnalysisOptions,
    facts: AllocationFacts<'_>,
    source: PageSizeSource,
) -> OomAnalysis {
    let evidence = match &facts.page_size {
        None => PageSizeEvidence::Missing,
        Some(PageSizeInference::Inconsistent { lines }) => PageSizeEvidence::Inconsistent {
            lines: lines.clone(),
        },
        Some(PageSizeInference::Consistent { page_size, lines })
            if *page_size == options.page_size =>
        {
            PageSizeEvidence::Consistent {
                lines: lines.clone(),
            }
        }
        Some(PageSizeInference::Consistent { page_size, lines }) => PageSizeEvidence::Conflicting {
            inferred: *page_size,
            lines: lines.clone(),
        },
    };
    let selection = PageSizeSelection {
        page_size: options.page_size,
        source,
        evidence,
    };
    let invocation = facts.invocation;
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
                OomMessage::CgroupBudget(_)
                    | OomMessage::CgroupStatsPath(_)
                    | OomMessage::VictimSelection(crate::VictimSelection {
                        memory_cgroup: true,
                        ..
                    })
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
        reason, explanation: explanation.into(), evidence: Vec::new(), structured_findings: Vec::new(), page_size: selection,
        possible_causes: causes.iter().map(|s| (*s).into()).collect(),
        recommendations: steps.iter().map(|s| (*s).into()).collect(),
        limitations: vec!["This log is a snapshot: it cannot prove a memory leak, reconstruct earlier growth, or show current system configuration. The invoking task and killed victim need not be the cause.".into()],
    };
    report.limitations.push(format!(
        "Page conversions use a base page size of {}. Verify this against the source machine.",
        bytes(options.page_size.get().into())
    ));
    let source = match report.page_size.source {
        PageSizeSource::Explicit => "explicit analysis options",
        PageSizeSource::Buddy => "consistent printed buddy buckets",
        PageSizeSource::Fallback => "the 4096-byte fallback assumption",
    };
    report
        .limitations
        .push(format!("Conversion page size was selected from {source}."));
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
            report.structured(
                vec![line],
                FindingData::Swap {
                    total: crate::ByteSize::b(0),
                    free: swap_free.map(|(_, free)| crate::ByteSize::b(free)),
                },
            );
            report.observe(
                line,
                format!("The dump reports zero total swap: {}.", bytes(0)),
            );
            report.possible_causes.push("No swap capacity was available as a buffer for swappable memory; this alone does not explain the OOM.".into());
            report.recommendations.push("Evaluate swap or zram for transient pressure if latency requirements permit; check cgroup swap limits. Swap does not replace sufficient RAM for the active working set.".into());
        } else if let (Some((total_line, total)), Some((free_line, 0))) = (swap_total, swap_free) {
            if total > 0 {
                report.structured(
                    vec![total_line, free_line],
                    FindingData::Swap {
                        total: crate::ByteSize::b(total),
                        free: Some(crate::ByteSize::b(0)),
                    },
                );
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
            if !facts.node_permitted(node.node) || !candidate_zone(&facts, zone) {
                continue;
            }
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
                    report.structured(
                        vec![r.line_number],
                        FindingData::ZoneWatermark {
                            node: node.node,
                            zone: zone.clone(),
                            free: *free,
                            threshold: *min,
                            metric: crate::MemoryMetric::Min,
                        },
                    );
                    if constrained_zones <= 3 {
                        report.observe(r.line_number, format!("Node {} zone {}: free {} is below the printed minimum {}. Allocation eligibility and reserves still matter.", node.node, zone, bytes(free.as_u64().into()), bytes(min.as_u64().into())));
                    }
                }
            }
        }
    }
    if constrained_zones > 0 && !matches!(reason, OomReason::Manual | OomReason::MemoryCgroup) {
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
    match &facts.page_size {
        Some(PageSizeInference::Consistent { page_size, lines }) => {
            let conflict = if *page_size == options.page_size {
                "matches the conversion size"
            } else {
                "CONFLICTS with the supplied conversion size; conversions retain the supplied size"
            };
            report.finding(
                EvidenceKind::PageSize,
                lines.clone(),
                format!(
                    "Buddy buckets indicate {} base pages; this {conflict} ({}).",
                    bytes(page_size.get().into()),
                    bytes(options.page_size.get().into())
                ),
            );
            if *page_size != options.page_size {
                report.limitations.push("Buddy page-size evidence conflicts with the supplied page size. Verify the source machine before interpreting converted quantities.".into());
            }
        }
        Some(PageSizeInference::Inconsistent { lines }) => {
            report.finding(
                EvidenceKind::PageSize,
                lines.clone(),
                "Buddy bucket sizes are inconsistent; no base page size was inferred.".into(),
            );
            report.limitations.push("Inconsistent buddy sizes prevent automatic page-size inference; conversions use the selected size.".into());
        }
        None => {}
    }
    analyze_gfp(event, &facts, &mut report);
    analyze_cgroup(event, &mut report);
    analyze_buddy(event, &facts, options, &mut report);
    analyze_watermarks(event, &facts, options, &mut report);
    analyze_memory(event, options, &mut report);
    analyze_legacy(event, options, &mut report);
    report
}

/// Cached allocation inputs shared by node and zone eligibility checks.
struct AllocationFacts<'a> {
    flags: Option<(std::borrow::Cow<'a, [crate::GfpFlag]>, Vec<usize>, bool)>,
    invocation: Option<(usize, &'a crate::Invocation)>,
    page_size: Option<PageSizeInference>,
    node_restrictions: Vec<&'a [crate::NodeRange]>,
}

impl<'a> AllocationFacts<'a> {
    fn new(event: &'a OomEvent) -> Self {
        let mut node_restrictions = Vec::new();
        let mut invocation = None;
        for record in &event.records {
            match &record.message {
                OomMessage::OomContext(c) => {
                    if let Some(ranges) = &c.mems_allowed {
                        node_restrictions.push(ranges.as_slice());
                    }
                    if let Some(ranges) = &c.nodemask {
                        node_restrictions.push(ranges.as_slice());
                    }
                }
                OomMessage::LegacyCpuset(c) => node_restrictions.push(c.mems_allowed.as_slice()),
                OomMessage::Invoked(i) => {
                    invocation.get_or_insert((record.line_number, i));
                    if let Some(ranges) = &i.nodemask {
                        node_restrictions.push(ranges.as_slice());
                    }
                }
                _ => {}
            }
        }
        Self {
            flags: event_gfp_flags(event),
            invocation,
            page_size: infer_page_size(event),
            node_restrictions,
        }
    }

    fn node_permitted(&self, node: u32) -> bool {
        self.node_restrictions
            .iter()
            .all(|ranges| ranges.iter().any(|r| r.start <= node && node <= r.end))
    }
}

fn event_gfp_flags(
    event: &OomEvent,
) -> Option<(std::borrow::Cow<'_, [crate::GfpFlag]>, Vec<usize>, bool)> {
    let (line, invocation) = event.records.iter().find_map(|r| match &r.message {
        OomMessage::Invoked(i) => Some((r.line_number, i)),
        _ => None,
    })?;
    if let Some(flags) = &invocation.gfp_flags {
        return Some((
            std::borrow::Cow::Borrowed(flags.as_slice()),
            vec![line],
            true,
        ));
    }
    let (cpu_line, cpu) = event.records.iter().find_map(|r| match &r.message {
        OomMessage::CpuContext(c) => Some((r.line_number, c)),
        _ => None,
    })?;
    crate::decode_gfp_mask(invocation.gfp_mask, &cpu.kernel_release)
        .map(|flags| (std::borrow::Cow::Owned(flags), vec![line, cpu_line], false))
}

fn analyze_gfp(event: &OomEvent, facts: &AllocationFacts<'_>, report: &mut OomAnalysis) {
    if !event
        .records
        .iter()
        .any(|r| matches!(&r.message, OomMessage::Invoked(i) if i.gfp_flags.is_none()))
    {
        return;
    }
    if let Some((flags, lines, _)) = &facts.flags {
        let names = if flags.is_empty() {
            "none (zero mask)".into()
        } else {
            flags
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" | ")
        };
        report.finding(EvidenceKind::Legacy, lines.clone(), format!(
            "Numeric GFP mask decoded using the logged release's verified upstream layout: {names}. Vendor backports may differ; printed symbolic flags take precedence. Unknown bits include configuration-dependent extensions."));
    } else {
        report.limitations.push("Numeric GFP mask was not decoded: the kernel release is missing or its layout is unverified. Zone and reserve rules cannot be inferred from that mask.".into());
    }
}

fn memory_bytes(value: &MemoryValue, options: AnalysisOptions) -> Option<u128> {
    match value {
        MemoryValue::Bytes(v) => Some(v.as_u64().into()),
        MemoryValue::Pages(n) => Some(u128::from(*n) * u128::from(options.page_size.get())),
        MemoryValue::State(_) | MemoryValue::Count(_) => None,
    }
}

fn analyze_memory(event: &OomEvent, options: AnalysisOptions, report: &mut OomAnalysis) {
    let mut ram = None;
    let mut swap_total = None;
    let mut swap_free = None;
    let global_counters = event
        .records
        .iter()
        .any(|r| matches!(r.message, OomMessage::MemoryCounters(_)));
    for record in &event.records {
        match &record.message {
            OomMessage::MemoryTotal(total) => {
                let Some(value) = memory_bytes(&total.value, options) else {
                    continue;
                };
                let label = match total.kind {
                    TotalKind::Ram => {
                        ram = Some((record.line_number, value));
                        "printed RAM capacity"
                    }
                    TotalKind::HighMemMovable => "HighMem/MovableOnly pages (included in RAM)",
                    TotalKind::Reserved => "reserved pages",
                    TotalKind::CmaReserved => "CMA reserved pages",
                    TotalKind::HardwarePoisoned => "hardware-poisoned pages",
                    TotalKind::PageCache => "total pagecache pages",
                    TotalKind::SwapCache => "swap-cache pages (RAM that also has swap backing)",
                    TotalKind::PageTableCache => "page-table cache",
                    TotalKind::TotalSwap => {
                        swap_total = Some((record.line_number, value));
                        continue;
                    }
                    TotalKind::FreeSwap => {
                        swap_free = Some((record.line_number, value));
                        continue;
                    }
                };
                report.finding(
                    EvidenceKind::Memory,
                    vec![record.line_number],
                    format!("System {label}: {}.", bytes(value)),
                );
            }
            OomMessage::MemoryCounters(counters) => {
                describe_counters(
                    "System Mem-Info",
                    counters,
                    record.line_number,
                    options,
                    report,
                );
            }
            OomMessage::NodeMemory(node) if !global_counters && node.zone.is_none() => {
                describe_counters(
                    &format!("Node {} memory", node.node),
                    &node.counters,
                    record.line_number,
                    options,
                    report,
                );
            }
            _ => {}
        }
    }
    if let (Some((total_line, total)), Some((free_line, free))) = (swap_total, swap_free) {
        if let Some(used) = total.checked_sub(free) {
            report.finding(EvidenceKind::Memory, vec![total_line, free_line], format!(
                "Occupied swap: {} (total minus free, including swap backing for swap-cache pages). Swap cache is shown separately and is not subtracted from occupied swap.", bytes(used)));
        } else {
            report.limitations.push(
                "Printed free swap exceeds total swap; occupied swap was not calculated.".into(),
            );
        }
    }
    if let Some(record) = event
        .records
        .iter()
        .find(|r| matches!(r.message, OomMessage::Killed(_)))
    {
        if let OomMessage::Killed(killed) = &record.message {
            let components = [
                killed.memory.anon_rss,
                killed.memory.file_rss,
                killed.memory.shmem_rss,
            ];
            if components.iter().any(Option::is_some) {
                let rss: u128 = components
                    .iter()
                    .flatten()
                    .map(|v| u128::from(v.as_u64()))
                    .sum();
                let complete = components.iter().all(Option::is_some);
                let label = if complete {
                    "Total victim RSS"
                } else {
                    "Sum of reported victim RSS components (partial; missing components are unknown)"
                };
                let mut lines = vec![record.line_number];
                let mut detail = format!("{label}: {}", bytes(rss));
                if let Some((ram_line, capacity)) = ram {
                    if capacity > 0 {
                        lines.push(ram_line);
                        detail.push_str(&format!(
                            " ({:.1}% of printed RAM capacity)",
                            rss as f64 * 100.0 / capacity as f64
                        ));
                    }
                }
                detail.push_str(". Shared pages may remain mapped by other processes; this is not the amount guaranteed to be reclaimed.");
                report.finding(EvidenceKind::Memory, lines, detail);
            }
        }
    }
    if global_counters {
        report.limitations.push("Mem-Info categories can overlap (for example shmem and file/LRU counters); they are not summed into a system-used total. Task RSS also overlaps shared mappings.".into());
    }
}

fn describe_counters(
    label: &str,
    counters: &[crate::MemoryCounter],
    line: usize,
    options: AnalysisOptions,
    report: &mut OomAnalysis,
) {
    let measurements = counters
        .iter()
        .map(|counter| {
            let value = match &counter.value {
                MemoryValue::Pages(count) => pages(*count, options),
                MemoryValue::Bytes(v) => bytes(v.as_u64().into()),
                MemoryValue::State(state) => state.to_string(),
                MemoryValue::Count(count) => {
                    format!("{count} scanned pages (not a memory quantity)")
                }
            };
            format!("{} {value}", counter.metric)
        })
        .collect::<Vec<_>>()
        .join("; ");
    report.finding(
        EvidenceKind::Memory,
        vec![line],
        format!(
            "{label}: {measurements}. Categories may overlap; no used-memory total is inferred."
        ),
    );
}

fn analyze_watermarks(
    event: &OomEvent,
    facts: &AllocationFacts<'_>,
    options: AnalysisOptions,
    report: &mut OomAnalysis,
) {
    use crate::{GfpFlag, MemoryMetric};
    if matches!(report.reason, OomReason::Manual | OomReason::MemoryCgroup) {
        return;
    }
    if let Some((flags, flag_lines, printed)) = &facts.flags {
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
        }) || (flags.contains(&GfpFlag::FlagHighmem)
            && flags.contains(&GfpFlag::FlagMovable))
        {
            "high/movable memory"
        } else if flags
            .iter()
            .any(|f| matches!(f, GfpFlag::Highuser | GfpFlag::FlagHighmem))
        {
            "high memory"
        } else if flags
            .iter()
            .any(|f| matches!(f, GfpFlag::Unknown(_) | GfpFlag::UnknownBits(_)))
        {
            "zone restriction is not fully known"
        } else {
            "no explicit DMA/high-memory restriction"
        };
        let modifiers = flags
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" | ");
        let source = if *printed {
            "Printed"
        } else {
            "Inferred upstream"
        };
        report.finding(EvidenceKind::Allocation, flag_lines.clone(), format!(
                "{source} allocation flags {modifiers}: {zone}. Fallback zones and reserves depend on kernel configuration. __GFP_HIGH may relax watermarks; __GFP_MEMALLOC may access reserves; __GFP_THISNODE restricts fallback."));
    }
    let mut pressure = false;
    for (index, record) in event.records.iter().enumerate() {
        let OomMessage::NodeMemory(node) = &record.message else {
            continue;
        };
        let Some(zone) = &node.zone else {
            continue;
        };
        if !facts.node_permitted(node.node) || !candidate_zone(facts, zone) {
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
        report.structured(
            lines.clone(),
            FindingData::ZoneWatermark {
                node: node.node,
                zone: zone.clone(),
                free: crate::ByteSize::b(free),
                threshold: crate::ByteSize::b(low),
                metric: MemoryMetric::Low,
            },
        );
        report.finding(EvidenceKind::Allocation, lines, detail);
    }
    if pressure {
        report.possible_causes.push("Free memory below a printed low watermark may restrict allocations even when some pages remain free; allocation flags and reserves determine eligibility.".into());
        report.recommendations.push("Compare the request's GFP flags, allowed NUMA nodes, zone watermarks, low-memory reserve vectors and buddy migration types before changing VM tuning.".into());
    }
}

// An upper bound on candidate zones, not a reconstruction of fallback order,
// migration eligibility or configured zone availability. Unknown flags/zones
// keep the observation available with its existing eligibility caveat.
fn candidate_zone(facts: &AllocationFacts<'_>, zone: &crate::MemoryZone) -> bool {
    use crate::{GfpFlag, MemoryZone};
    let Some((flags, _, _)) = &facts.flags else {
        return true;
    };
    if flags
        .iter()
        .any(|f| matches!(f, GfpFlag::Unknown(_) | GfpFlag::UnknownBits(_)))
    {
        return true;
    }
    let dma = flags
        .iter()
        .any(|f| matches!(f, GfpFlag::Dma | GfpFlag::FlagDma));
    let dma32 = flags
        .iter()
        .any(|f| matches!(f, GfpFlag::Dma32 | GfpFlag::FlagDma32));
    let high = flags.iter().any(|f| {
        matches!(
            f,
            GfpFlag::Highuser
                | GfpFlag::HighuserMovable
                | GfpFlag::Transhuge
                | GfpFlag::TranshugeLight
                | GfpFlag::FlagHighmem
        )
    });
    let movable = flags.iter().any(|f| {
        matches!(
            f,
            GfpFlag::HighuserMovable
                | GfpFlag::Transhuge
                | GfpFlag::TranshugeLight
                | GfpFlag::FlagMovable
        )
    });
    if u8::from(dma) + u8::from(dma32) + u8::from(high) > 1 {
        return true;
    }
    let highest = if dma {
        0
    } else if dma32 {
        1
    } else if high && movable {
        4
    } else if high {
        3
    } else {
        2
    };
    let rank = match zone {
        MemoryZone::Dma => 0,
        MemoryZone::Dma32 => 1,
        MemoryZone::Normal => 2,
        MemoryZone::HighMem => 3,
        MemoryZone::Movable => 4,
        MemoryZone::Device | MemoryZone::Unknown(_) => return true,
    };
    rank <= highest
}

fn analyze_legacy(event: &OomEvent, options: AnalysisOptions, report: &mut OomAnalysis) {
    for record in &event.records {
        match &record.message {
            OomMessage::LegacyCpuset(c) => {
                report.finding(EvidenceKind::Legacy, vec![record.line_number], format!(
                    "Legacy task {:?}: cpuset {:?}, allowed memory nodes {:?}. Membership alone does not establish CONSTRAINT_CPUSET or prove that other nodes were usable.", c.task, c.cpuset, c.mems_allowed));
            }
            OomMessage::VictimSelection(s) => {
                report.finding(EvidenceKind::Legacy, vec![record.line_number], format!(
                    "Legacy victim selection: PID {} ({:?}), printed badness score {}. This is distinct from oom_score_adj and does not confirm a completed kill; a child may have been selected instead.", s.pid, s.name, s.score));
            }
            OomMessage::Task(task) => {
                if let Some(ptes) = task.page_table_pages {
                    let mut detail = format!(
                        "Legacy task PID {} page-table memory: nr_ptes {}",
                        task.pid,
                        pages(ptes, options)
                    );
                    if let Some(n) = task.pmd_table_pages {
                        detail.push_str(&format!("; nr_pmds {}", pages(n, options)));
                    }
                    if let Some(n) = task.pud_table_pages {
                        detail.push_str(&format!("; nr_puds {}", pages(n, options)));
                    }
                    report.finding(EvidenceKind::Legacy, vec![record.line_number], detail);
                }
            }
            _ => {}
        }
    }
}
fn analyze_buddy(
    event: &OomEvent,
    facts: &AllocationFacts<'_>,
    options: AnalysisOptions,
    report: &mut OomAnalysis,
) {
    if matches!(report.reason, OomReason::Manual | OomReason::MemoryCgroup) {
        return;
    }
    let invocation = facts.invocation;
    let Some((invoke_line, invocation)) = invocation else {
        return;
    };
    let inference = &facts.page_size;
    let geometry_matches = matches!(
        inference,
        Some(PageSizeInference::Consistent { page_size, .. }) if *page_size == options.page_size
    );
    if !geometry_matches && inference.is_some() {
        report.limitations.push("Buddy availability and order-based block shortages were not evaluated because bucket geometry is inconsistent or conflicts with the conversion page size.".into());
        for record in &event.records {
            if let OomMessage::BuddyInfo(buddy) = &record.message {
                if facts.node_permitted(buddy.node) && candidate_zone(facts, &buddy.zone) {
                    let buckets = buddy
                        .blocks
                        .iter()
                        .map(|block| {
                            format!(
                                "{} blocks of {}",
                                block.count,
                                bytes(block.size.as_u64().into())
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("; ");
                    report.finding(EvidenceKind::Allocation, vec![record.line_number], format!(
                        "Node {} zone {} printed buddy buckets: {buckets}. Allocation availability was not evaluated.", buddy.node, buddy.zone));
                }
            }
        }
        return;
    }
    let Some(request) = u32::try_from(invocation.order)
        .ok()
        .and_then(|order| 1u128.checked_shl(order))
        .and_then(|pages| pages.checked_mul(u128::from(options.page_size.get())))
    else {
        report.limitations.push("Allocation order cannot be converted safely into a request size; buddy availability was not evaluated.".into());
        return;
    };
    let mut found = false;
    for record in &event.records {
        let OomMessage::BuddyInfo(buddy) = &record.message else {
            continue;
        };
        if !facts.node_permitted(buddy.node) || !candidate_zone(facts, &buddy.zone) {
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
        report.structured(
            vec![invoke_line, record.line_number],
            FindingData::Buddy {
                node: buddy.node,
                zone: buddy.zone.clone(),
                request_bytes: request,
                fitting_blocks: fitting,
                largest_block: largest.map(crate::ByteSize::b),
            },
        );
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
        report.limitations.push("No buddy distribution was captured for a permitted node and candidate zone; contiguous-block availability is unknown.".into());
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
                report.structured(
                    vec![record.line_number],
                    FindingData::CgroupBudget {
                        resource: budget.resource,
                        usage: budget.usage,
                        limit: budget.limit,
                        fail_count: budget.fail_count,
                    },
                );
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
    fn structured(&mut self, lines: Vec<usize>, data: FindingData) {
        self.structured_findings
            .push(StructuredFinding { lines, data });
    }

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
