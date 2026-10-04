//! Human-facing rendering, separate from the reusable analysis findings.
use crate::{
    AnalysisOptions, Constraint, MemoryMetric, MemoryValue, NodeRange, OomEvent, OomMessage,
    OomReason, TotalKind, analyze_event_with_options,
};

fn size(value: u128, verbose: bool) -> String {
    let human = if let Ok(value) = u64::try_from(value) {
        crate::ByteSize::b(value).display().iec().to_string()
    } else {
        format!("{:.2} EiB", value as f64 / (1u64 << 60) as f64)
    };
    if verbose {
        format!("{human} ({value} bytes)")
    } else {
        human
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
fn nodes(ranges: &[NodeRange]) -> String {
    ranges
        .iter()
        .map(|r| {
            if r.start == r.end {
                r.start.to_string()
            } else {
                format!("{}–{}", r.start, r.end)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}
fn reference(lines: &[usize]) -> String {
    let mut lines = lines.to_vec();
    lines.sort_unstable();
    lines.dedup();
    if lines.len() == 1 {
        return format!("[line {}]", lines[0]);
    }
    if lines
        .windows(2)
        .all(|pair| pair[0].checked_add(1) == Some(pair[1]))
    {
        return format!("[lines {}–{}]", lines[0], lines[lines.len() - 1]);
    }
    format!(
        "[lines {}]",
        lines
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    )
}
fn paragraph(out: &mut String, text: &str, prefix: &str) {
    out.push_str(prefix);
    let mut column = prefix.chars().count();
    let indent = " ".repeat(column);
    let mut first = true;
    for word in text.split_whitespace() {
        let width = word.chars().count();
        if !first && column + 1 + width > 88 {
            out.push('\n');
            out.push_str(&indent);
            column = indent.len();
        } else if !first {
            out.push(' ');
            column += 1;
        }
        out.push_str(word);
        column += width;
        first = false;
    }
    out.push('\n');
}

/// Render a readable event report, beginning with its descriptive title.
///
/// Default output uses human-readable IEC sizes; verbose output adds exact
/// bytes, task page counts, allocation flags and scope details. Source references
/// appear after observations in both modes. No terminal control codes from task
/// names or paths are emitted. The supplied page size is stated in either mode.
pub fn format_event_analysis(event: &OomEvent, options: AnalysisOptions, verbose: bool) -> String {
    let analysis = analyze_event_with_options(event, options);
    let mut out = String::new();
    let title = match analysis.reason {
        OomReason::Manual => "Manual OOM request",
        OomReason::Global => "System-wide memory pressure",
        OomReason::MemoryCgroup => "Memory cgroup limit reached",
        OomReason::Cpuset => "Memory shortage within the allowed cpuset",
        OomReason::MemoryPolicy => "Memory shortage under the NUMA policy",
        OomReason::AllocationFailure => "Memory allocation failure (scope unknown)",
        OomReason::Unknown => "OOM trigger unknown (incomplete or unsupported context)",
    };
    out.push_str(title);
    out.push('\n');
    let invocation = event.records.iter().find_map(|r| {
        if let OomMessage::Invoked(i) = &r.message {
            Some((r.line_number, i))
        } else {
            None
        }
    });
    let victim = event.records.iter().find_map(|r| {
        if let OomMessage::Killed(k) = &r.message {
            Some((r.line_number, k))
        } else {
            None
        }
    });
    let context = event.records.iter().find_map(|r| {
        if let OomMessage::OomContext(c) = &r.message {
            Some((r.line_number, c))
        } else {
            None
        }
    });
    if let Some((line, k)) = victim {
        paragraph(
            &mut out,
            &format!(
                "The kernel killed {} (PID {}) to recover memory. {}",
                safe(&k.name),
                k.pid,
                reference(&[line])
            ),
            "",
        );
    } else {
        paragraph(
            &mut out,
            "No kill record was captured; a successful kill is not confirmed.",
            "",
        );
    }
    out.push_str("\nWhat happened\n");
    if analysis.reason == OomReason::Manual {
        paragraph(
            &mut out,
            "The kernel received an explicit manual SysRq OOM request. This does not establish that memory was exhausted.",
            "  ",
        );
    } else if let Some((line, i)) = invocation {
        let amount = u32::try_from(i.order)
            .ok()
            .and_then(|order| 1u64.checked_shl(order));
        let request = amount
            .map(|count| {
                let bytes = size(
                    u128::from(count) * u128::from(options.page_size.get()),
                    verbose,
                );
                if count == 1 {
                    format!("one memory page ({bytes})")
                } else {
                    format!("{count} contiguous memory pages ({bytes})")
                }
            })
            .unwrap_or_else(|| "memory (request size unavailable)".into());
        paragraph(
            &mut out,
            &format!(
                "{} requested {request}. The kernel could not satisfy the request after trying to reclaim memory. {}",
                safe(&i.name),
                reference(&[line])
            ),
            "  ",
        );
    } else {
        paragraph(
            &mut out,
            "The invocation was not captured, so the original allocation request is unknown.",
            "  ",
        );
    }
    let scope = match analysis.reason {
        OomReason::Global => "This was a global OOM, rather than a reported cgroup-limit OOM.",
        OomReason::MemoryCgroup => {
            "The affected cgroup could not stay within its effective memory limit after reclaim. The host may still have available memory."
        }
        OomReason::Cpuset | OomReason::MemoryPolicy => {
            "Memory outside the permitted nodes may have been available but unusable for this allocation."
        }
        OomReason::AllocationFailure | OomReason::Unknown => {
            "The available records do not establish the allocation scope."
        }
        OomReason::Manual => {
            "Check operator activity, tests, or automation that can trigger a manual OOM."
        }
    };
    paragraph(&mut out, scope, "  ");
    if let Some((line, c)) = context {
        paragraph(
            &mut out,
            &format!(
                "The victim belonged to {}. {}",
                safe(&c.task_memcg),
                reference(&[line])
            ),
            "  ",
        );
    }
    out.push_str("\nWhat the log shows\n");
    let mut observations = 0;
    let mut total_swap = None;
    let mut free_swap = None;
    let mut low_zones = 0;
    for r in &event.records {
        if let OomMessage::MemoryTotal(t) = &r.message {
            if let MemoryValue::Bytes(value) = t.value {
                match t.kind {
                    TotalKind::TotalSwap => total_swap = Some((r.line_number, value.as_u64())),
                    TotalKind::FreeSwap => free_swap = Some((r.line_number, value.as_u64())),
                    _ => {}
                }
            }
        }
    }
    if let Some((line, total)) = total_swap {
        let text = match free_swap {
            Some((free_line, free)) => format!(
                "{}: {} total, {} available. {}",
                if total == 0 {
                    "No swap was configured"
                } else if free == 0 {
                    "Swap was full"
                } else {
                    "Swap"
                },
                size(total.into(), verbose),
                size(free.into(), verbose),
                reference(&[line, free_line])
            ),
            None => format!(
                "Swap capacity was {}; free swap was not reported. {}",
                size(total.into(), verbose),
                reference(&[line])
            ),
        };
        paragraph(&mut out, &text, "  • ");
        observations += 1;
    } else if let Some((line, free)) = free_swap {
        paragraph(
            &mut out,
            &format!(
                "Free swap was {}; total capacity was not reported. {}",
                size(free.into(), verbose),
                reference(&[line])
            ),
            "  • ",
        );
        observations += 1;
    }
    for r in &event.records {
        if let OomMessage::NodeMemory(n) = &r.message {
            let Some(zone) = &n.zone else {
                continue;
            };
            let value = |metric| {
                n.counters.iter().find_map(|c| {
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
            if let (Some(free), Some(min)) = (value(MemoryMetric::Free), value(MemoryMetric::Min)) {
                if free < min {
                    low_zones += 1;
                    if low_zones <= 3 {
                        paragraph(
                            &mut out,
                            &format!(
                                "Node {}'s {} memory zone had {} free, {} below its minimum threshold of {}. {}",
                                n.node,
                                safe(&zone.to_string()),
                                size(free.into(), verbose),
                                size((min - free).into(), verbose),
                                size(min.into(), verbose),
                                reference(&[r.line_number])
                            ),
                            "  • ",
                        );
                        observations += 1;
                    }
                }
            }
        }
    }
    if low_zones > 0 {
        paragraph(
            &mut out,
            "Some free memory must remain reserved for essential operations. Allocation rules determine which zones and reserves a request can use.",
            "    ",
        );
    }
    if low_zones > 3 {
        paragraph(
            &mut out,
            &format!(
                "{} additional zones were below their minimum thresholds.",
                low_zones - 3
            ),
            "  • ",
        );
    }
    let mut tasks: Vec<_> = event
        .records
        .iter()
        .filter_map(|r| {
            if let OomMessage::Task(t) = &r.message {
                Some((r.line_number, t))
            } else {
                None
            }
        })
        .collect();
    tasks.sort_by_key(|(_, t)| std::cmp::Reverse(t.rss_pages));
    if let Some((line, t)) = tasks.first() {
        let ranking = if tasks
            .get(1)
            .is_some_and(|(_, other)| other.rss_pages == t.rss_pages)
        {
            "was tied for the largest"
        } else {
            "was the largest"
        };
        paragraph(
            &mut out,
            &format!(
                "{} {ranking} resident-memory user in the captured task table ({}). {}",
                safe(&t.name),
                size(
                    u128::from(t.rss_pages) * u128::from(options.page_size.get()),
                    verbose
                ),
                reference(&[*line])
            ),
            "  • ",
        );
        observations += 1;
    }
    for finding in analysis
        .evidence
        .iter()
        .filter(|e| e.kind != crate::EvidenceKind::Observation)
    {
        paragraph(
            &mut out,
            &format!(
                "{} {}",
                safe(&finding.description),
                reference(&finding.lines)
            ),
            "  • ",
        );
        observations += 1;
    }
    if observations == 0 {
        paragraph(
            &mut out,
            "No swap, zone-pressure, or task-table measurements were captured.",
            "  ",
        );
    }
    if !tasks.is_empty() {
        out.push_str("\nLargest processes in the snapshot\n");
        let names: Vec<_> = tasks.iter().take(3).map(|(_, t)| safe(&t.name)).collect();
        let width = names
            .iter()
            .map(|s| s.chars().count())
            .max()
            .unwrap_or(7)
            .max(7);
        out.push_str(&format!(
            "  {:width$}  {:>10}  Resident memory\n",
            "Process", "PID"
        ));
        for ((line, t), name) in tasks.iter().take(3).zip(names) {
            let memory = size(
                u128::from(t.rss_pages) * u128::from(options.page_size.get()),
                verbose,
            );
            out.push_str(&format!(
                "  {name:width$}  {:>10}  {memory}{} {}\n",
                t.pid,
                if verbose {
                    format!(
                        "; {} pages; OOM score adjustment {}",
                        t.rss_pages, t.oom_score_adj
                    )
                } else {
                    String::new()
                },
                reference(&[*line])
            ));
        }
        paragraph(
            &mut out,
            "Shared memory can appear in more than one process's totals.",
            "  ",
        );
    }
    out.push_str("\nLikely contributors (not confirmed)\n");
    for cause in &analysis.possible_causes {
        paragraph(&mut out, &safe(cause), "  ");
    }
    out.push_str("\nWhat to do next\n");
    let mut steps = Vec::new();
    if matches!(analysis.reason, OomReason::Global | OomReason::MemoryCgroup) {
        if let Some((_, t)) = tasks.first() {
            steps.push(format!("Investigate {}'s memory use around the event. Compare heap, cache, and concurrency metrics over time to distinguish sustained growth from a temporary burst.",safe(&t.name)));
        }
    }
    steps.extend(analysis.recommendations.iter().cloned());
    for (i, step) in steps.iter().enumerate() {
        paragraph(&mut out, &safe(step), &format!("  {}. ", i + 1));
    }
    if verbose {
        out.push_str("\nTechnical details\n");
        if let Some((line, i)) = invocation {
            let flags = i
                .gfp_flags
                .as_ref()
                .map(|v| {
                    v.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" | ")
                })
                .unwrap_or_else(|| "not reported".into());
            paragraph(
                &mut out,
                &format!(
                    "Allocation order {}; GFP mask {:#x}; flags {}. {}",
                    i.order,
                    i.gfp_mask,
                    safe(&flags),
                    reference(&[line])
                ),
                "  ",
            );
        }
        if let Some((line, c)) = context {
            let constraint = match &c.constraint {
                Constraint::None => "none",
                Constraint::Cpuset => "cpuset",
                Constraint::MemoryPolicy => "NUMA memory policy",
                Constraint::MemoryCgroup => "memory cgroup",
                Constraint::Unknown(s) => s.as_str(),
            };
            paragraph(
                &mut out,
                &format!(
                    "Constraint: {}; cpuset: {}; allowed nodes: {}. {}",
                    safe(constraint),
                    safe(&c.cpuset),
                    nodes(&c.mems_allowed),
                    reference(&[line])
                ),
                "  ",
            );
        }
        if let Some((line, k)) = victim {
            let measurement = |v: Option<crate::ByteSize>| {
                v.map(|v| size(v.as_u64().into(), true))
                    .unwrap_or_else(|| "not reported".into())
            };
            paragraph(
                &mut out,
                &format!(
                    "Victim memory: anonymous RSS {}, file RSS {}, shared RSS {}; OOM score adjustment {}. {}",
                    measurement(k.memory.anon_rss),
                    measurement(k.memory.file_rss),
                    measurement(k.memory.shmem_rss),
                    k.oom_score_adj
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "not reported".into()),
                    reference(&[line])
                ),
                "  ",
            );
        }
    }
    out.push_str("\nInterpretation notes\n");
    paragraph(
        &mut out,
        "The invoking task and killed process are not necessarily responsible for the pressure. This snapshot cannot prove a leak or reconstruct earlier growth.",
        "  ",
    );
    paragraph(
        &mut out,
        &format!(
            "Page conversions use {} base pages; verify the source machine's page size and override with --page-size BYTES.",
            size(options.page_size.get().into(), verbose)
        ),
        "  ",
    );
    if !verbose {
        paragraph(
            &mut out,
            "Use --verbose for allocation flags, exact byte counts, and page counts.",
            "  ",
        );
    }
    out
}
