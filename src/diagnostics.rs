//! Parsers for diagnostic lines accompanying an OOM event.
use crate::{ByteSize, OomMessage, checked_kib, types::*};
use winnow::{
    Parser, Result,
    ascii::{dec_int, dec_uint, hex_uint, space0, space1},
    combinator::{alt, opt},
    error::ContextError,
    token::{rest, take_until, take_while},
};

fn invalid<T>() -> Result<T> {
    Err(ContextError::new())
}
fn word<'a>(input: &mut &'a str) -> Result<&'a str> {
    take_while(1.., |c: char| !c.is_ascii_whitespace()).parse_next(input)
}
fn tail(input: &mut &str) -> Result<String> {
    rest.verify(|s: &str| !s.is_empty())
        .map(str::to_owned)
        .parse_next(input)
}
fn number(input: &mut &str) -> Result<u64> {
    (space1, dec_uint).map(|(_, n)| n).parse_next(input)
}
fn kb(input: &mut &str) -> Result<ByteSize> {
    let n = dec_uint.parse_next(input)?;
    alt(("kB", "KB")).parse_next(input)?;
    checked_kib(n)
}

pub(crate) fn gfp_flags(input: &mut &str) -> Result<Vec<GfpFlag>> {
    let mut flags = Vec::new();
    loop {
        let token: &str =
            take_while(1.., |c: char| c.is_ascii_alphanumeric() || c == '_').parse_next(input)?;
        let flag = if token.starts_with("0x") {
            GfpFlag::UnknownBits(
                ("0x", hex_uint::<_, u64, ContextError>)
                    .map(|(_, n)| n)
                    .parse(token)
                    .map_err(|_| ContextError::new())?,
            )
        } else {
            GfpFlag::from_name(token)
        };
        flags.push(flag);
        if !input.starts_with('|') {
            break;
        }
        "|".parse_next(input)?;
    }
    Ok(flags)
}

pub(crate) fn parse_message(
    body: &str,
    layout: Option<TaskLayout>,
) -> Option<std::result::Result<OomMessage, String>> {
    if body.starts_with("memory: usage ")
        || body.starts_with("memory+swap: usage ")
        || body.starts_with("swap: usage ")
        || body.starts_with("kmem: usage ")
    {
        return Some(cgroup_budget.parse(body).map_err(|e| e.to_string()));
    }
    if body.starts_with("Memory cgroup stats for ") {
        return Some(cgroup_path.parse(body).map_err(|e| e.to_string()));
    }
    // Table headers take precedence over heuristics, including numeric task names.
    if body.starts_with('[')
        && body.split_once(']').is_some_and(|(s, _)| {
            !s[1..].trim().is_empty() && s[1..].trim().bytes().all(|b| b.is_ascii_digit())
        })
    {
        let mut parser = |input: &mut &str| task(input, layout);
        return Some(parser.parse(body).map_err(|e| e.to_string()));
    }
    let mut parser: fn(&mut &str) -> Result<OomMessage> = if body.starts_with("sysrq: Manual OOM") {
        manual
    } else if body.starts_with("RIP:") {
        instruction_pointer
    } else if body.starts_with("Code:") {
        instruction_code
    } else if body
        .split_once(':')
        .is_some_and(|(key, _)| Register::from_name(key).is_some())
    {
        registers
    } else if body.starts_with("CPU:") {
        cpu
    } else if body.starts_with("Tainted:") {
        taints
    } else if body.starts_with("Hardware name:") {
        hardware
    } else if body.starts_with("Workqueue:") {
        workqueue
    } else if body.starts_with("Call Trace:")
        || body.starts_with("Mem-Info:")
        || body.starts_with("Tasks state")
        || body.starts_with("Memory allocations (")
    {
        section
    } else if matches!(
        body,
        "<TASK>" | "</TASK>" | "<IRQ>" | "</IRQ>" | "<NMI>" | "</NMI>"
    ) {
        boundary
    } else if body
        .strip_prefix("? ")
        .unwrap_or(body)
        .split_once("+0x")
        .is_some_and(|(symbol, _)| {
            !symbol.is_empty()
                && symbol
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
        })
    {
        frame
    } else if body.starts_with("Node ") {
        node
    } else if body.starts_with("lowmem_reserve[]:") {
        reserves
    } else if body.starts_with("oom-kill:") {
        context
    } else if body.starts_with('[')
        && body
            .split_once(']')
            .is_some_and(|(s, _)| s[1..].trim() == "pid")
    {
        task_header
    } else if body.starts_with("Free swap")
        || body.starts_with("Total swap")
        || (body.as_bytes().first().is_some_and(u8::is_ascii_digit)
            && (body.contains(" pages ") || body.ends_with(" total pagecache pages")))
    {
        total
    } else if body.as_bytes().first().is_some_and(u8::is_ascii_digit) && body.contains(" func:") {
        allocation
    } else if body
        .split_once(':')
        .is_some_and(|(key, _)| MemoryMetric::from_name(key).is_some())
    {
        memory
    } else {
        return None;
    };
    Some(parser.parse(body).map_err(|error| error.to_string()))
}

fn manual(input: &mut &str) -> Result<OomMessage> {
    "sysrq: Manual OOM execution".parse_next(input)?;
    Ok(OomMessage::ManualOom)
}
fn section(input: &mut &str) -> Result<OomMessage> {
    let s = alt((
        "Call Trace:".value(Section::CallTrace),
        "Mem-Info:".value(Section::MemoryInfo),
        "Tasks state (memory values in pages):".value(Section::Tasks),
        "Memory allocations (profiling is currently turned on):"
            .value(Section::Allocations { enabled: true }),
        "Memory allocations (profiling is currently turned off):"
            .value(Section::Allocations { enabled: false }),
    ))
    .parse_next(input)?;
    Ok(OomMessage::Section(s))
}
fn boundary(input: &mut &str) -> Result<OomMessage> {
    let b = alt((
        "<TASK>".value(StackBoundary::TaskStart),
        "</TASK>".value(StackBoundary::TaskEnd),
        "<IRQ>".value(StackBoundary::IrqStart),
        "</IRQ>".value(StackBoundary::IrqEnd),
        "<NMI>".value(StackBoundary::NmiStart),
        "</NMI>".value(StackBoundary::NmiEnd),
    ))
    .parse_next(input)?;
    Ok(OomMessage::StackBoundary(b))
}
fn cpu(input: &mut &str) -> Result<OomMessage> {
    "CPU: ".parse_next(input)?;
    let cpu = dec_uint.parse_next(input)?;
    let uid = opt((" UID: ", dec_uint::<_, u32, _>).map(|(_, v)| v)).parse_next(input)?;
    " PID: ".parse_next(input)?;
    let pid = dec_uint.parse_next(input)?;
    " Comm: ".parse_next(input)?;
    let (command, taint_text) = if let Some((command, rest)) = input.split_once(" Tainted: ") {
        *input = rest;
        let flags = take_while(0.., |c: char| !c.is_ascii_digit()).parse_next(input)?;
        (command.to_owned(), flags)
    } else {
        let command = take_until(1.., " Not tainted ")
            .parse_next(input)?
            .to_owned();
        " Not tainted ".parse_next(input)?;
        (command, "")
    };
    if command.is_empty() {
        return invalid();
    }
    let taints = taint_text
        .chars()
        .filter_map(TaintFlag::from_code)
        .collect();
    let kernel_release = word(input)?.to_owned();
    space1.parse_next(input)?;
    let kernel_build = word(input)?.to_owned();
    let mut preemption = None;
    let mut build_flags = Vec::new();
    while !input.is_empty() {
        space1.parse_next(input)?;
        let flag = word(input)?;
        let mode = match flag {
            "PREEMPT" => Some(Preemption::Full),
            "PREEMPT(lazy)" => Some(Preemption::Lazy),
            "PREEMPT_DYNAMIC" => Some(Preemption::Dynamic),
            "PREEMPT_NONE" => Some(Preemption::None),
            "PREEMPT_VOLUNTARY" => Some(Preemption::Voluntary),
            s if s.starts_with("PREEMPT") => Some(Preemption::Unknown(s.into())),
            _ => None,
        };
        if let Some(mode) = mode {
            preemption = Some(mode);
        } else {
            build_flags.push(flag.into());
        }
    }
    Ok(OomMessage::CpuContext(CpuContext {
        cpu,
        uid,
        pid,
        command,
        taints,
        kernel_release,
        kernel_build,
        preemption,
        build_flags,
    }))
}
fn taints(input: &mut &str) -> Result<OomMessage> {
    "Tainted: ".parse_next(input)?;
    let mut descriptions = Vec::new();
    loop {
        "[".parse_next(input)?;
        let code: char = winnow::token::any.parse_next(input)?;
        let flag = TaintFlag::from_code(code).ok_or_else(ContextError::new)?;
        "]=".parse_next(input)?;
        let identifier = take_while(1.., |c: char| c.is_ascii_alphanumeric() || c == '_')
            .parse_next(input)?
            .to_owned();
        descriptions.push(TaintDescription { flag, identifier });
        if input.is_empty() {
            break;
        }
        (",", space0).parse_next(input)?;
    }
    Ok(OomMessage::TaintDescriptions(descriptions))
}
fn hardware(input: &mut &str) -> Result<OomMessage> {
    "Hardware name: ".parse_next(input)?;
    let name = take_until(1.., ", BIOS ").parse_next(input)?.to_owned();
    ", BIOS ".parse_next(input)?;
    let Some((version, date)) = input.rsplit_once(' ') else {
        return invalid();
    };
    if version.trim().is_empty() || date.is_empty() {
        return invalid();
    }
    let bios_version = version.trim_end().to_owned();
    let bios_date = date.to_owned();
    *input = "";
    Ok(OomMessage::Hardware(Hardware {
        name,
        bios_version,
        bios_date,
    }))
}
fn workqueue(input: &mut &str) -> Result<OomMessage> {
    "Workqueue: ".parse_next(input)?;
    let name = word(input)?.into();
    space1.parse_next(input)?;
    let function = word(input)?.into();
    Ok(OomMessage::Workqueue(Workqueue { name, function }))
}
fn frame(input: &mut &str) -> Result<OomMessage> {
    let uncertain = opt(("?", space1)).parse_next(input)?.is_some();
    let symbol = take_until(1.., "+0x").parse_next(input)?.to_owned();
    "+0x".parse_next(input)?;
    let offset = hex_uint.map(ByteSize::b).parse_next(input)?;
    "/0x".parse_next(input)?;
    let size = hex_uint.map(ByteSize::b).parse_next(input)?;
    let module = module(input)?;
    Ok(OomMessage::StackFrame(StackFrame {
        symbol,
        offset,
        size,
        uncertain,
        module,
    }))
}
fn module(input: &mut &str) -> Result<Option<String>> {
    opt((space1, "[", take_until(1.., "]"), "]")
        .map(|(_, _, name, _): (_, _, &str, _)| name.to_owned()))
    .parse_next(input)
}
fn counters(input: &mut &str) -> Result<Vec<MemoryCounter>> {
    let mut counters = Vec::new();
    loop {
        let key = take_while(1.., |c: char| {
            c.is_ascii_alphabetic() || matches!(c, '_' | '(' | ')')
        })
        .parse_next(input)?;
        let metric = MemoryMetric::from_name(key).ok_or_else(ContextError::new)?;
        let value = if metric == MemoryMetric::AllUnreclaimable {
            "? ".parse_next(input)?;
            MemoryValue::State(alt(("yes".value(true), "no".value(false))).parse_next(input)?)
        } else {
            (":", space0).parse_next(input)?;
            let n = dec_uint.parse_next(input)?;
            if opt(alt(("kB", "KB"))).parse_next(input)?.is_some() {
                MemoryValue::Bytes(checked_kib(n)?)
            } else {
                MemoryValue::Pages(n)
            }
        };
        counters.push(MemoryCounter { metric, value });
        if input.is_empty() {
            break;
        }
        space1.parse_next(input)?;
    }
    Ok(counters)
}
fn memory(input: &mut &str) -> Result<OomMessage> {
    Ok(OomMessage::MemoryCounters(counters(input)?))
}
fn zone(name: &str) -> MemoryZone {
    match name {
        "DMA" => MemoryZone::Dma,
        "DMA32" => MemoryZone::Dma32,
        "Normal" => MemoryZone::Normal,
        "HighMem" => MemoryZone::HighMem,
        "Movable" => MemoryZone::Movable,
        "Device" => MemoryZone::Device,
        other => MemoryZone::Unknown(other.into()),
    }
}
fn node(input: &mut &str) -> Result<OomMessage> {
    "Node ".parse_next(input)?;
    let node = dec_uint.parse_next(input)?;
    space1.parse_next(input)?;
    if input.starts_with("hugepages_total=") {
        "hugepages_total=".parse_next(input)?;
        let total = dec_uint.parse_next(input)?;
        " hugepages_free=".parse_next(input)?;
        let free = dec_uint.parse_next(input)?;
        " hugepages_surp=".parse_next(input)?;
        let surplus = dec_uint.parse_next(input)?;
        " hugepages_size=".parse_next(input)?;
        let size = kb(input)?;
        return Ok(OomMessage::HugePages(HugePages {
            node,
            total,
            free,
            surplus,
            size,
        }));
    }
    if input.starts_with("active_") {
        return Ok(OomMessage::NodeMemory(NodeMemory {
            node,
            zone: None,
            counters: counters(input)?,
        }));
    }
    let name =
        take_while(1.., |c: char| c.is_ascii_alphanumeric() || c == '_').parse_next(input)?;
    let zone = zone(name);
    if input.starts_with(':') {
        (":", space1).parse_next(input)?;
        let mut blocks = Vec::new();
        while !input.starts_with('=') {
            let count = dec_uint.parse_next(input)?;
            "*".parse_next(input)?;
            let size = kb(input)?;
            let codes =
                opt((" (", take_until(1.., ")"), ")").map(|(_, s, _)| s)).parse_next(input)?;
            let migration_types = codes
                .unwrap_or("")
                .chars()
                .map(|c| match c {
                    'U' => MigrationType::Unmovable,
                    'M' => MigrationType::Movable,
                    'E' => MigrationType::Reclaimable,
                    'H' => MigrationType::HighAtomic,
                    'C' => MigrationType::Cma,
                    'I' => MigrationType::Isolate,
                    c => MigrationType::Unknown(c),
                })
                .collect();
            blocks.push(FreeBlock {
                count,
                size,
                migration_types,
            });
            space1.parse_next(input)?;
        }
        "= ".parse_next(input)?;
        let total = kb(input)?;
        return Ok(OomMessage::BuddyInfo(BuddyInfo {
            node,
            zone,
            blocks,
            total,
        }));
    }
    space1.parse_next(input)?;
    Ok(OomMessage::NodeMemory(NodeMemory {
        node,
        zone: Some(zone),
        counters: counters(input)?,
    }))
}
fn reserves(input: &mut &str) -> Result<OomMessage> {
    "lowmem_reserve[]:".parse_next(input)?;
    let mut values = vec![number(input)?];
    while !input.is_empty() {
        values.push(number(input)?);
    }
    Ok(OomMessage::LowmemReserves(values))
}
fn total(input: &mut &str) -> Result<OomMessage> {
    if input.starts_with("Free swap") || input.starts_with("Total swap") {
        let kind = alt((
            "Free swap".value(TotalKind::FreeSwap),
            "Total swap".value(TotalKind::TotalSwap),
        ))
        .parse_next(input)?;
        (space0, "=", space0).parse_next(input)?;
        return Ok(OomMessage::MemoryTotal(MemoryTotal {
            kind,
            value: MemoryValue::Bytes(kb(input)?),
        }));
    }
    let value = MemoryValue::Pages(dec_uint.parse_next(input)?);
    let kind = alt((
        " total pagecache pages".value(TotalKind::PageCache),
        " pages in swap cache".value(TotalKind::SwapCache),
        " pages RAM".value(TotalKind::Ram),
        " pages HighMem/MovableOnly".value(TotalKind::HighMemMovable),
        " pages reserved".value(TotalKind::Reserved),
        " pages cma reserved".value(TotalKind::CmaReserved),
        " pages hwpoisoned".value(TotalKind::HardwarePoisoned),
    ))
    .parse_next(input)?;
    Ok(OomMessage::MemoryTotal(MemoryTotal { kind, value }))
}
fn allocation(input: &mut &str) -> Result<OomMessage> {
    let whole: &str = winnow::ascii::digit1.parse_next(input)?;
    let fractional: Option<&str> =
        opt((".", winnow::ascii::digit1).map(|(_, n)| n)).parse_next(input)?;
    let digits = format!("{}{}", whole, fractional.unwrap_or(""));
    let mantissa = winnow::ascii::digit1::<_, ContextError>
        .try_map(str::parse::<u64>)
        .parse(digits.as_str())
        .map_err(|_| ContextError::new())?;
    let decimal_places = fractional
        .unwrap_or("")
        .len()
        .try_into()
        .map_err(|_| ContextError::new())?;
    space1.parse_next(input)?;
    let unit = alt((
        "KiB".value(SizeUnit::KiB),
        "MiB".value(SizeUnit::MiB),
        "GiB".value(SizeUnit::GiB),
        "TiB".value(SizeUnit::TiB),
        "B".value(SizeUnit::Bytes),
    ))
    .parse_next(input)?;
    let exponent = match unit {
        SizeUnit::Bytes => 0,
        SizeUnit::KiB => 10,
        SizeUnit::MiB => 20,
        SizeUnit::GiB => 30,
        SizeUnit::TiB => 40,
    };
    let divisor = 10u128
        .checked_pow(decimal_places)
        .ok_or_else(ContextError::new)?;
    let bytes = ((u128::from(mantissa) << exponent) / divisor)
        .try_into()
        .map_err(|_| ContextError::new())?;
    let size = ReportedSize {
        bytes: ByteSize::b(bytes),
        mantissa,
        decimal_places,
        unit,
    };
    let count = number(input)?;
    space1.parse_next(input)?;
    let file = take_until(1.., ":").parse_next(input)?.to_owned();
    ":".parse_next(input)?;
    let line = dec_uint.parse_next(input)?;
    let module = module(input)?;
    (space1, "func:").parse_next(input)?;
    let function = word(input)?.to_owned();
    Ok(OomMessage::Allocation(Allocation {
        size,
        count,
        file,
        line,
        module,
        function,
    }))
}
fn task_header(input: &mut &str) -> Result<OomMessage> {
    ("[", space0, "pid", space0, "]").parse_next(input)?;
    let mut columns = vec![TaskColumn::Pid];
    for (name, col) in [
        ("uid", TaskColumn::Uid),
        ("tgid", TaskColumn::Tgid),
        ("total_vm", TaskColumn::TotalVm),
        ("rss", TaskColumn::Rss),
    ] {
        (space1, name).parse_next(input)?;
        columns.push(col);
    }
    if input.trim_start().starts_with("rss_anon") {
        for (name, col) in [
            ("rss_anon", TaskColumn::RssAnon),
            ("rss_file", TaskColumn::RssFile),
            ("rss_shmem", TaskColumn::RssShmem),
        ] {
            (space1, name).parse_next(input)?;
            columns.push(col);
        }
    }
    for (name, col) in [
        ("pgtables_bytes", TaskColumn::PageTablesBytes),
        ("swapents", TaskColumn::SwapEntries),
        ("oom_score_adj", TaskColumn::OomScoreAdj),
        ("name", TaskColumn::Name),
    ] {
        (space1, name).parse_next(input)?;
        columns.push(col);
    }
    Ok(OomMessage::TaskColumns(columns))
}
fn task(input: &mut &str, layout: Option<TaskLayout>) -> Result<OomMessage> {
    let layout = layout.unwrap_or_else(|| {
        // Standalone lines have no header. Use the number of leading numeric
        // columns; callers with ambiguous numeric task names can supply a layout.
        let after_pid = input.split_once(']').map(|(_, rest)| rest).unwrap_or("");
        let numeric = after_pid
            .split_ascii_whitespace()
            .take_while(|s| s.parse::<i128>().is_ok())
            .count();
        if numeric >= 10 {
            TaskLayout::RssBreakdown
        } else {
            TaskLayout::TotalRss
        }
    });
    ("[", space0).parse_next(input)?;
    let pid = dec_uint.parse_next(input)?;
    (space0, "]", space1).parse_next(input)?;
    let uid = dec_uint.parse_next(input)?;
    space1.parse_next(input)?;
    let tgid = dec_uint.parse_next(input)?;
    let total_vm_pages = number(input)?;
    let rss_pages = number(input)?;
    let (rss_anon_pages, rss_file_pages, rss_shmem_pages) = match layout {
        TaskLayout::RssBreakdown => (
            Some(number(input)?),
            Some(number(input)?),
            Some(number(input)?),
        ),
        TaskLayout::TotalRss => (None, None, None),
    };
    let page_tables = ByteSize::b(number(input)?);
    let swap_entries = number(input)?;
    space1.parse_next(input)?;
    let oom_score_adj = dec_int.parse_next(input)?;
    space1.parse_next(input)?;
    let name = tail(input)?;
    Ok(OomMessage::Task(Task {
        pid,
        uid,
        tgid,
        total_vm_pages,
        rss_pages,
        rss_anon_pages,
        rss_file_pages,
        rss_shmem_pages,
        page_tables,
        swap_entries,
        oom_score_adj,
        name,
    }))
}
fn nodes(input: &mut &str) -> Result<Vec<NodeRange>> {
    let mut ranges = Vec::new();
    loop {
        let start = dec_uint.parse_next(input)?;
        let end = opt(("-", dec_uint::<_, u32, _>).map(|(_, n)| n))
            .parse_next(input)?
            .unwrap_or(start);
        if end < start {
            return invalid();
        }
        ranges.push(NodeRange { start, end });
        if input.is_empty() {
            break;
        }
        ",".parse_next(input)?;
    }
    Ok(ranges)
}
fn context(input: &mut &str) -> Result<OomMessage> {
    "oom-kill:constraint=".parse_next(input)?;
    let text = take_until(1.., ",nodemask=").parse_next(input)?;
    let constraint = match text {
        "CONSTRAINT_NONE" => Constraint::None,
        "CONSTRAINT_CPUSET" => Constraint::Cpuset,
        "CONSTRAINT_MEMORY_POLICY" => Constraint::MemoryPolicy,
        "CONSTRAINT_MEMCG" => Constraint::MemoryCgroup,
        s => Constraint::Unknown(s.into()),
    };
    ",nodemask=".parse_next(input)?;
    let mask = take_until(1.., ",cpuset=").parse_next(input)?;
    let nodemask = if mask == "(null)" {
        None
    } else {
        Some(nodes.parse(mask).map_err(|_| ContextError::new())?)
    };
    ",cpuset=".parse_next(input)?;
    let cpuset = take_until(1.., ",mems_allowed=")
        .parse_next(input)?
        .to_owned();
    ",mems_allowed=".parse_next(input)?;
    let (mems, scope) = if let Some((mems, after)) = input.split_once(",global_oom") {
        *input = after;
        (mems, OomScope::Global)
    } else {
        let mems = take_until(1.., ",oom_memcg=").parse_next(input)?;
        ",oom_memcg=".parse_next(input)?;
        let path = take_until(1.., ",task_memcg=")
            .parse_next(input)?
            .to_owned();
        (mems, OomScope::MemoryCgroup(path))
    };
    let mems_allowed = nodes.parse(mems).map_err(|_| ContextError::new())?;
    ",task_memcg=".parse_next(input)?;
    let task_memcg = take_until(1.., ",task=").parse_next(input)?.to_owned();
    ",task=".parse_next(input)?;
    let task = take_until(0.., ",pid=").parse_next(input)?.to_owned();
    ",pid=".parse_next(input)?;
    let pid = dec_uint.parse_next(input)?;
    ",uid=".parse_next(input)?;
    let uid = dec_uint.parse_next(input)?;
    Ok(OomMessage::OomContext(OomContext {
        constraint,
        nodemask,
        cpuset,
        mems_allowed,
        scope,
        task_memcg,
        task,
        pid,
        uid,
    }))
}

fn instruction_pointer(input: &mut &str) -> Result<OomMessage> {
    "RIP: ".parse_next(input)?;
    let segment = hex_uint.parse_next(input)?;
    ":".parse_next(input)?;
    let location = if input.starts_with("0x") {
        "0x".parse_next(input)?;
        InstructionLocation::Address(hex_uint.parse_next(input)?)
    } else {
        let OomMessage::StackFrame(frame) = frame(input)? else {
            unreachable!()
        };
        InstructionLocation::Symbol(frame)
    };
    Ok(OomMessage::InstructionPointer(InstructionPointer {
        segment,
        location,
    }))
}

fn instruction_code(input: &mut &str) -> Result<OomMessage> {
    "Code: ".parse_next(input)?;
    if input.starts_with("Unable to access opcode bytes at 0x") {
        "Unable to access opcode bytes at 0x".parse_next(input)?;
        let address = hex_uint.parse_next(input)?;
        ".".parse_next(input)?;
        return Ok(OomMessage::InstructionCode(InstructionCode::Unavailable(
            address,
        )));
    }
    let mut bytes = Vec::new();
    let mut instruction_index = None;
    loop {
        let marked = opt("<").parse_next(input)?.is_some();
        if marked {
            if instruction_index.is_some() {
                return invalid();
            }
            instruction_index = Some(bytes.len());
        }
        let byte = take_while(2, |c: char| c.is_ascii_hexdigit())
            .try_map(|s| u8::from_str_radix(s, 16))
            .parse_next(input)?;
        bytes.push(byte);
        if marked {
            ">".parse_next(input)?;
        }
        if input.is_empty() {
            break;
        }
        space1.parse_next(input)?;
    }
    Ok(OomMessage::InstructionCode(InstructionCode::Bytes {
        bytes,
        instruction_index,
    }))
}

fn registers(input: &mut &str) -> Result<OomMessage> {
    let mut values = Vec::new();
    loop {
        let name = take_until(1.., ":").parse_next(input)?;
        let register = Register::from_name(name).ok_or_else(ContextError::new)?;
        (":", space1).parse_next(input)?;
        let first: u64 = hex_uint.parse_next(input)?;
        let (segment, value) = if opt(":").parse_next(input)?.is_some() {
            (
                Some(first.try_into().map_err(|_| ContextError::new())?),
                hex_uint.parse_next(input)?,
            )
        } else {
            (None, first)
        };
        values.push(RegisterValue {
            register,
            segment,
            value,
        });
        if input.is_empty() {
            break;
        }
        space1.parse_next(input)?;
    }
    Ok(OomMessage::Registers(values))
}

fn cgroup_budget(input: &mut &str) -> Result<OomMessage> {
    let resource = alt((
        "memory: usage ".value(CgroupResource::Memory),
        "memory+swap: usage ".value(CgroupResource::MemoryAndSwap),
        "swap: usage ".value(CgroupResource::Swap),
        "kmem: usage ".value(CgroupResource::KernelMemory),
    ))
    .parse_next(input)?;
    let usage = kb(input)?;
    ", limit ".parse_next(input)?;
    let limit = kb(input)?;
    ", failcnt ".parse_next(input)?;
    let fail_count = dec_uint.parse_next(input)?;
    Ok(OomMessage::CgroupBudget(CgroupBudget {
        resource,
        usage,
        limit,
        fail_count,
    }))
}
fn cgroup_path(input: &mut &str) -> Result<OomMessage> {
    "Memory cgroup stats for ".parse_next(input)?;
    let text = rest.parse_next(input)?;
    let path = text
        .strip_suffix(':')
        .filter(|s| !s.is_empty())
        .ok_or_else(ContextError::new)?;
    Ok(OomMessage::CgroupStatsPath(path.to_owned()))
}
/// Called only within an explicitly introduced cgroup memory.stat block.
pub(crate) fn cgroup_stat(body: &str) -> Option<std::result::Result<OomMessage, String>> {
    let (name, _) = body.split_once(char::is_whitespace)?;
    if !name.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
    {
        return None;
    }
    let mut parser = |input: &mut &str| -> Result<OomMessage> {
        let name = word(input)?.to_owned();
        space1.parse_next(input)?;
        let number = dec_uint.parse_next(input)?;
        let base = name.strip_prefix("total_").unwrap_or(&name);
        let value = if matches!(
            base,
            "anon"
                | "file"
                | "kernel"
                | "kernel_stack"
                | "pagetables"
                | "sec_pagetables"
                | "percpu"
                | "sock"
                | "vmalloc"
                | "shmem"
                | "zswap"
                | "zswapped"
                | "file_mapped"
                | "file_dirty"
                | "file_writeback"
                | "swapcached"
                | "anon_thp"
                | "file_thp"
                | "shmem_thp"
                | "inactive_anon"
                | "active_anon"
                | "inactive_file"
                | "active_file"
                | "unevictable"
                | "slab_reclaimable"
                | "slab_unreclaimable"
                | "slab"
                | "cache"
                | "rss"
                | "rss_huge"
                | "mapped_file"
                | "dirty"
                | "writeback"
                | "swap"
        ) {
            CgroupStatValue::Bytes(ByteSize::b(number))
        } else if base.starts_with("workingset_")
            || base.starts_with("pg")
            || base.starts_with("thp_")
        {
            CgroupStatValue::Count(number)
        } else {
            CgroupStatValue::Unknown(number)
        };
        Ok(OomMessage::CgroupStat(CgroupStat { name, value }))
    };
    Some(parser.parse(body).map_err(|e| e.to_string()))
}
