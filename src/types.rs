//! Typed Linux OOM diagnostic data. Counts retain the units printed by Linux.
use bytesize::ByteSize;
/// A printed GFP allocation class or modifier. The raw mask remains on Invocation; numeric bit assignments can depend on kernel version/configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GfpFlag {
    /// GFP_KERNEL.
    Kernel,
    /// GFP_KERNEL_ACCOUNT.
    KernelAccount,
    /// GFP_ATOMIC.
    Atomic,
    /// GFP_NOWAIT.
    Nowait,
    /// GFP_NOIO.
    Noio,
    /// GFP_NOFS.
    Nofs,
    /// GFP_USER.
    User,
    /// GFP_DMA.
    Dma,
    /// GFP_DMA32.
    Dma32,
    /// GFP_HIGHUSER.
    Highuser,
    /// GFP_HIGHUSER_MOVABLE.
    HighuserMovable,
    /// GFP_TRANSHUGE.
    Transhuge,
    /// GFP_TRANSHUGE_LIGHT.
    TranshugeLight,
    /// __GFP_DMA.
    FlagDma,
    /// __GFP_HIGHMEM.
    FlagHighmem,
    /// __GFP_DMA32.
    FlagDma32,
    /// __GFP_MOVABLE.
    FlagMovable,
    /// __GFP_RECLAIMABLE.
    FlagReclaimable,
    /// __GFP_HIGH.
    FlagHigh,
    /// __GFP_IO.
    FlagIo,
    /// __GFP_FS.
    FlagFs,
    /// __GFP_ZERO.
    FlagZero,
    /// __GFP_DIRECT_RECLAIM.
    FlagDirectReclaim,
    /// __GFP_KSWAPD_RECLAIM.
    FlagKswapdReclaim,
    /// __GFP_RECLAIM.
    FlagReclaim,
    /// __GFP_WRITE.
    FlagWrite,
    /// __GFP_NOWARN.
    FlagNowarn,
    /// __GFP_RETRY_MAYFAIL.
    FlagRetryMayfail,
    /// __GFP_NOFAIL.
    FlagNofail,
    /// __GFP_NORETRY.
    FlagNoretry,
    /// __GFP_MEMALLOC.
    FlagMemalloc,
    /// __GFP_COMP.
    FlagComp,
    /// __GFP_NOMEMALLOC.
    FlagNomemalloc,
    /// __GFP_HARDWALL.
    FlagHardwall,
    /// __GFP_THISNODE.
    FlagThisnode,
    /// __GFP_ACCOUNT.
    FlagAccount,
    /// __GFP_ZEROTAGS.
    FlagZerotags,
    /// __GFP_SKIP_ZERO.
    FlagSkipZero,
    /// __GFP_SKIP_KASAN.
    FlagSkipKasan,
    /// __GFP_NOLOCKDEP.
    FlagNolockdep,
    /// __GFP_NO_OBJ_EXT.
    FlagNoObjExt,
    /// Legacy or modifier flag `__GFP_WAIT`.
    FlagWait,
    /// Legacy or modifier flag `__GFP_COLD`.
    FlagCold,
    /// Legacy or modifier flag `__GFP_REPEAT`.
    FlagRepeat,
    /// Legacy or modifier flag `__GFP_KMEMCG`.
    FlagKmemcg,
    /// Legacy or modifier flag `__GFP_NOTRACK`.
    FlagNotrack,
    /// Legacy or modifier flag `__GFP_NO_KSWAPD`.
    FlagNoKswapd,
    /// Legacy or modifier flag `__GFP_OTHER_NODE`.
    FlagOtherNode,
    /// Legacy or modifier flag `__GFP_ATOMIC`.
    FlagAtomic,
    /// A symbolic flag introduced by another kernel.
    Unknown(String),
    /// Unresolved bits printed as a hexadecimal token.
    UnknownBits(u64),
}
impl GfpFlag {
    pub(crate) fn from_name(name: &str) -> Self {
        match name {
            "__GFP_WAIT" => Self::FlagWait,
            "__GFP_COLD" => Self::FlagCold,
            "__GFP_REPEAT" => Self::FlagRepeat,
            "__GFP_KMEMCG" => Self::FlagKmemcg,
            "__GFP_NOTRACK" => Self::FlagNotrack,
            "__GFP_NO_KSWAPD" => Self::FlagNoKswapd,
            "__GFP_OTHER_NODE" => Self::FlagOtherNode,
            "__GFP_ATOMIC" => Self::FlagAtomic,
            "GFP_KERNEL" => Self::Kernel,
            "GFP_KERNEL_ACCOUNT" => Self::KernelAccount,
            "GFP_ATOMIC" => Self::Atomic,
            "GFP_NOWAIT" => Self::Nowait,
            "GFP_NOIO" => Self::Noio,
            "GFP_NOFS" => Self::Nofs,
            "GFP_USER" => Self::User,
            "GFP_DMA" => Self::Dma,
            "GFP_DMA32" => Self::Dma32,
            "GFP_HIGHUSER" => Self::Highuser,
            "GFP_HIGHUSER_MOVABLE" => Self::HighuserMovable,
            "GFP_TRANSHUGE" => Self::Transhuge,
            "GFP_TRANSHUGE_LIGHT" => Self::TranshugeLight,
            "__GFP_DMA" => Self::FlagDma,
            "__GFP_HIGHMEM" => Self::FlagHighmem,
            "__GFP_DMA32" => Self::FlagDma32,
            "__GFP_MOVABLE" => Self::FlagMovable,
            "__GFP_RECLAIMABLE" => Self::FlagReclaimable,
            "__GFP_HIGH" => Self::FlagHigh,
            "__GFP_IO" => Self::FlagIo,
            "__GFP_FS" => Self::FlagFs,
            "__GFP_ZERO" => Self::FlagZero,
            "__GFP_DIRECT_RECLAIM" => Self::FlagDirectReclaim,
            "__GFP_KSWAPD_RECLAIM" => Self::FlagKswapdReclaim,
            "__GFP_RECLAIM" => Self::FlagReclaim,
            "__GFP_WRITE" => Self::FlagWrite,
            "__GFP_NOWARN" => Self::FlagNowarn,
            "__GFP_RETRY_MAYFAIL" => Self::FlagRetryMayfail,
            "__GFP_NOFAIL" => Self::FlagNofail,
            "__GFP_NORETRY" => Self::FlagNoretry,
            "__GFP_MEMALLOC" => Self::FlagMemalloc,
            "__GFP_COMP" => Self::FlagComp,
            "__GFP_NOMEMALLOC" => Self::FlagNomemalloc,
            "__GFP_HARDWALL" => Self::FlagHardwall,
            "__GFP_THISNODE" => Self::FlagThisnode,
            "__GFP_ACCOUNT" => Self::FlagAccount,
            "__GFP_ZEROTAGS" => Self::FlagZerotags,
            "__GFP_SKIP_ZERO" => Self::FlagSkipZero,
            "__GFP_SKIP_KASAN" => Self::FlagSkipKasan,
            "__GFP_NOLOCKDEP" => Self::FlagNolockdep,
            "__GFP_NO_OBJ_EXT" => Self::FlagNoObjExt,
            other => Self::Unknown(other.into()),
        }
    }
}
impl std::fmt::Display for GfpFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FlagWait => f.write_str("__GFP_WAIT"),
            Self::FlagCold => f.write_str("__GFP_COLD"),
            Self::FlagRepeat => f.write_str("__GFP_REPEAT"),
            Self::FlagKmemcg => f.write_str("__GFP_KMEMCG"),
            Self::FlagNotrack => f.write_str("__GFP_NOTRACK"),
            Self::FlagNoKswapd => f.write_str("__GFP_NO_KSWAPD"),
            Self::FlagOtherNode => f.write_str("__GFP_OTHER_NODE"),
            Self::FlagAtomic => f.write_str("__GFP_ATOMIC"),
            Self::Kernel => f.write_str("GFP_KERNEL"),
            Self::KernelAccount => f.write_str("GFP_KERNEL_ACCOUNT"),
            Self::Atomic => f.write_str("GFP_ATOMIC"),
            Self::Nowait => f.write_str("GFP_NOWAIT"),
            Self::Noio => f.write_str("GFP_NOIO"),
            Self::Nofs => f.write_str("GFP_NOFS"),
            Self::User => f.write_str("GFP_USER"),
            Self::Dma => f.write_str("GFP_DMA"),
            Self::Dma32 => f.write_str("GFP_DMA32"),
            Self::Highuser => f.write_str("GFP_HIGHUSER"),
            Self::HighuserMovable => f.write_str("GFP_HIGHUSER_MOVABLE"),
            Self::Transhuge => f.write_str("GFP_TRANSHUGE"),
            Self::TranshugeLight => f.write_str("GFP_TRANSHUGE_LIGHT"),
            Self::FlagDma => f.write_str("__GFP_DMA"),
            Self::FlagHighmem => f.write_str("__GFP_HIGHMEM"),
            Self::FlagDma32 => f.write_str("__GFP_DMA32"),
            Self::FlagMovable => f.write_str("__GFP_MOVABLE"),
            Self::FlagReclaimable => f.write_str("__GFP_RECLAIMABLE"),
            Self::FlagHigh => f.write_str("__GFP_HIGH"),
            Self::FlagIo => f.write_str("__GFP_IO"),
            Self::FlagFs => f.write_str("__GFP_FS"),
            Self::FlagZero => f.write_str("__GFP_ZERO"),
            Self::FlagDirectReclaim => f.write_str("__GFP_DIRECT_RECLAIM"),
            Self::FlagKswapdReclaim => f.write_str("__GFP_KSWAPD_RECLAIM"),
            Self::FlagReclaim => f.write_str("__GFP_RECLAIM"),
            Self::FlagWrite => f.write_str("__GFP_WRITE"),
            Self::FlagNowarn => f.write_str("__GFP_NOWARN"),
            Self::FlagRetryMayfail => f.write_str("__GFP_RETRY_MAYFAIL"),
            Self::FlagNofail => f.write_str("__GFP_NOFAIL"),
            Self::FlagNoretry => f.write_str("__GFP_NORETRY"),
            Self::FlagMemalloc => f.write_str("__GFP_MEMALLOC"),
            Self::FlagComp => f.write_str("__GFP_COMP"),
            Self::FlagNomemalloc => f.write_str("__GFP_NOMEMALLOC"),
            Self::FlagHardwall => f.write_str("__GFP_HARDWALL"),
            Self::FlagThisnode => f.write_str("__GFP_THISNODE"),
            Self::FlagAccount => f.write_str("__GFP_ACCOUNT"),
            Self::FlagZerotags => f.write_str("__GFP_ZEROTAGS"),
            Self::FlagSkipZero => f.write_str("__GFP_SKIP_ZERO"),
            Self::FlagSkipKasan => f.write_str("__GFP_SKIP_KASAN"),
            Self::FlagNolockdep => f.write_str("__GFP_NOLOCKDEP"),
            Self::FlagNoObjExt => f.write_str("__GFP_NO_OBJ_EXT"),
            Self::Unknown(name) => f.write_str(name),
            Self::UnknownBits(bits) => write!(f, "{bits:#x}"),
        }
    }
}

/// Kernel taint reason, decoded from its printed letter.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TaintFlag {
    /// Kernel taint `P`.
    ProprietaryModule,
    /// Kernel taint `F`.
    ForcedModule,
    /// Kernel taint `S`.
    OutOfSpecification,
    /// Kernel taint `R`.
    ForcedUnload,
    /// Kernel taint `M`.
    MachineCheck,
    /// Kernel taint `B`.
    BadPage,
    /// Kernel taint `U`.
    Userspace,
    /// Kernel taint `D`.
    KernelDied,
    /// Kernel taint `A`.
    AcpiOverride,
    /// Kernel taint `W`.
    Warning,
    /// Kernel taint `C`.
    StagingDriver,
    /// Kernel taint `I`.
    FirmwareWorkaround,
    /// Kernel taint `O`.
    OutOfTreeModule,
    /// Kernel taint `E`.
    UnsignedModule,
    /// Kernel taint `L`.
    SoftLockup,
    /// Kernel taint `K`.
    LivePatch,
    /// Kernel taint `X`.
    Auxiliary,
    /// Kernel taint `T`.
    Randstruct,
    /// Kernel taint `N`.
    Test,
    /// Kernel taint `J`.
    FwctlDebug,
    /// A future or vendor-specific taint letter.
    Unknown(char),
}
impl TaintFlag {
    /// Decode a taint letter. `G` and space indicate no taint and return `None`.
    pub fn from_code(code: char) -> Option<Self> {
        Some(match code {
            'G' | ' ' => return None,
            'P' => Self::ProprietaryModule,
            'F' => Self::ForcedModule,
            'S' => Self::OutOfSpecification,
            'R' => Self::ForcedUnload,
            'M' => Self::MachineCheck,
            'B' => Self::BadPage,
            'U' => Self::Userspace,
            'D' => Self::KernelDied,
            'A' => Self::AcpiOverride,
            'W' => Self::Warning,
            'C' => Self::StagingDriver,
            'I' => Self::FirmwareWorkaround,
            'O' => Self::OutOfTreeModule,
            'E' => Self::UnsignedModule,
            'L' => Self::SoftLockup,
            'K' => Self::LivePatch,
            'X' => Self::Auxiliary,
            'T' => Self::Randstruct,
            'N' => Self::Test,
            'J' => Self::FwctlDebug,
            other => Self::Unknown(other),
        })
    }
}
/// A taint letter and the explanatory identifier printed by the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TaintDescription {
    /// Decoded reason.
    pub flag: TaintFlag,
    /// Kernel identifier, e.g. OOT_MODULE; retained to support vendor descriptions.
    pub identifier: String,
}
/// Kernel preemption mode.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Preemption {
    /// None mode.
    None,
    /// Voluntary mode.
    Voluntary,
    /// Full mode.
    Full,
    /// Lazy mode.
    Lazy,
    /// Dynamic mode.
    Dynamic,
    /// An unrecognized mode.
    Unknown(String),
}
/// CPU and task context from the diagnostic header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CpuContext {
    /// CPU index.
    pub cpu: u32,
    /// User ID, if printed.
    pub uid: Option<u32>,
    /// Invoking process ID.
    pub pid: u32,
    /// Task command.
    pub command: String,
    /// Active taint reasons; empty for Not tainted.
    pub taints: Vec<TaintFlag>,
    /// Kernel release including distribution suffix.
    pub kernel_release: String,
    /// Build identifier such as #1-NixOS.
    pub kernel_build: String,
    /// Preemption mode, if printed.
    pub preemption: Option<Preemption>,
    /// Other kernel build flags such as SMP or PTI.
    pub build_flags: Vec<String>,
}
/// Machine and firmware identity.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Hardware {
    /// Machine identification.
    pub name: String,
    /// BIOS version.
    pub bios_version: String,
    /// Firmware date as printed; no locale assumption.
    pub bios_date: String,
}
/// Workqueue callback context.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Workqueue {
    /// Queue name.
    pub name: String,
    /// Callback symbol.
    pub function: String,
}
/// A diagnostic section header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Section {
    /// Stack trace begins.
    CallTrace,
    /// Memory statistics begin.
    MemoryInfo,
    /// Task table begins; memory columns use pages.
    Tasks,
    /// Allocation profiling header and its enabled state.
    Allocations {
        /// Whether allocation profiling is enabled.
        enabled: bool,
    },
}
/// Stack context boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StackBoundary {
    /// Task stack begins.
    TaskStart,
    /// Task stack ends.
    TaskEnd,
    /// IRQ stack begins.
    IrqStart,
    /// IRQ stack ends.
    IrqEnd,
    /// NMI stack begins.
    NmiStart,
    /// NMI stack ends.
    NmiEnd,
}
/// A stack frame symbol and hexadecimal byte offsets.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StackFrame {
    /// Absolute frame address, printed by older kernels.
    pub address: Option<u64>,
    /// Function symbol.
    pub symbol: String,
    /// Byte offset within the symbol.
    pub offset: ByteSize,
    /// Symbol size in bytes.
    pub size: ByteSize,
    /// Whether the kernel prefixed this frame with a question mark.
    pub uncertain: bool,
    /// Module name, if printed.
    pub module: Option<String>,
}
/// A named memory counter or state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemoryMetric {
    /// Kernel `active_anon` field.
    ActiveAnon,
    /// Kernel `inactive_anon` field.
    InactiveAnon,
    /// Kernel `isolated_anon` field.
    IsolatedAnon,
    /// Kernel `active_file` field.
    ActiveFile,
    /// Kernel `inactive_file` field.
    InactiveFile,
    /// Kernel `isolated_file` field.
    IsolatedFile,
    /// Kernel `unevictable` field.
    Unevictable,
    /// Kernel `dirty` field.
    Dirty,
    /// Kernel `writeback` field.
    Writeback,
    /// Unstable pages, older kernels.
    Unstable,
    /// Temporary writeback pages (older kernels).
    WritebackTmp,
    /// Kernel `slab_reclaimable` field.
    SlabReclaimable,
    /// Kernel `slab_unreclaimable` field.
    SlabUnreclaimable,
    /// Kernel `mapped` field.
    Mapped,
    /// Kernel `shmem` field.
    Shmem,
    /// Kernel `pagetables` field.
    Pagetables,
    /// Kernel `sec_pagetables` field.
    SecPagetables,
    /// Kernel `bounce` field.
    Bounce,
    /// Kernel `kernel_misc_reclaimable` field.
    KernelMiscReclaimable,
    /// Kernel `free` field.
    Free,
    /// Kernel `free_pcp` field.
    FreePcp,
    /// Kernel `free_cma` field.
    FreeCma,
    /// Kernel `shmem_thp` field.
    ShmemThp,
    /// Kernel `shmem_pmdmapped` field.
    ShmemPmdmapped,
    /// Kernel `anon_thp` field.
    AnonThp,
    /// Kernel `kernel_stack` field.
    KernelStack,
    /// Shadow call stack memory, when CONFIG_SHADOW_CALL_STACK is enabled.
    ShadowCallStack,
    /// Kernel `all_unreclaimable` field.
    AllUnreclaimable,
    /// Kernel `Balloon` field.
    Balloon,
    /// Kernel `boost` field.
    Boost,
    /// Kernel `min` field.
    Min,
    /// Kernel `low` field.
    Low,
    /// Kernel `high` field.
    High,
    /// Kernel `reserved_highatomic` field.
    ReservedHighatomic,
    /// Kernel `free_highatomic` field.
    FreeHighatomic,
    /// Kernel `writepending` field.
    Writepending,
    /// Kernel `zspages` field.
    Zspages,
    /// Kernel `present` field.
    Present,
    /// Kernel `managed` field.
    Managed,
    /// Kernel `mlocked` field.
    Mlocked,
    /// Older kernel reclaim scan count, not a memory quantity.
    PagesScanned,
    /// Kernel `local_pcp` field.
    LocalPcp,
}
impl MemoryMetric {
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "active_anon" => Self::ActiveAnon,
            "inactive_anon" => Self::InactiveAnon,
            "isolated_anon" => Self::IsolatedAnon,
            "active_file" => Self::ActiveFile,
            "inactive_file" => Self::InactiveFile,
            "isolated_file" => Self::IsolatedFile,
            "unevictable" => Self::Unevictable,
            "dirty" => Self::Dirty,
            "writeback" => Self::Writeback,
            "unstable" => Self::Unstable,
            "writeback_tmp" => Self::WritebackTmp,
            "slab_reclaimable" => Self::SlabReclaimable,
            "slab_unreclaimable" => Self::SlabUnreclaimable,
            "mapped" => Self::Mapped,
            "shmem" => Self::Shmem,
            "pagetables" => Self::Pagetables,
            "sec_pagetables" => Self::SecPagetables,
            "bounce" => Self::Bounce,
            "kernel_misc_reclaimable" => Self::KernelMiscReclaimable,
            "free" => Self::Free,
            "free_pcp" => Self::FreePcp,
            "free_cma" => Self::FreeCma,
            "shmem_thp" => Self::ShmemThp,
            "shmem_pmdmapped" => Self::ShmemPmdmapped,
            "anon_thp" => Self::AnonThp,
            "kernel_stack" => Self::KernelStack,
            "shadow_call_stack" => Self::ShadowCallStack,
            "all_unreclaimable" => Self::AllUnreclaimable,
            "Balloon" => Self::Balloon,
            "boost" => Self::Boost,
            "min" => Self::Min,
            "low" => Self::Low,
            "high" => Self::High,
            "reserved_highatomic" => Self::ReservedHighatomic,
            "free_highatomic" => Self::FreeHighatomic,
            "writepending" => Self::Writepending,
            "zspages" => Self::Zspages,
            "present" => Self::Present,
            "managed" => Self::Managed,
            "mlocked" => Self::Mlocked,
            "pages_scanned" => Self::PagesScanned,
            "local_pcp" => Self::LocalPcp,
            "isolated(anon)" => Self::IsolatedAnon,
            "isolated(file)" => Self::IsolatedFile,
            _ => return None,
        })
    }
}
/// Unit-tagged memory quantity or boolean state. Page size is deliberately not assumed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemoryValue {
    /// A page count.
    Pages(u64),
    /// A byte size converted from kernel kB or KB (1024 bytes).
    Bytes(ByteSize),
    /// Count of operations/pages scanned; not a resident memory quantity.
    Count(u64),
    /// Boolean state, such as all_unreclaimable.
    State(bool),
}
/// One named memory measurement.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemoryCounter {
    /// Counter identity.
    pub metric: MemoryMetric,
    /// Counter value with its unit.
    pub value: MemoryValue,
}
/// Kernel memory zone.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemoryZone {
    /// DMA zone.
    Dma,
    /// DMA32 zone.
    Dma32,
    /// Normal zone.
    Normal,
    /// High memory zone.
    HighMem,
    /// Movable zone.
    Movable,
    /// Device zone.
    Device,
    /// A vendor or future zone.
    Unknown(String),
}
impl std::fmt::Display for MemoryZone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Dma => "DMA",
            Self::Dma32 => "DMA32",
            Self::Normal => "Normal",
            Self::HighMem => "HighMem",
            Self::Movable => "Movable",
            Self::Device => "Device",
            Self::Unknown(name) => name,
        })
    }
}
/// Memory counters for a NUMA node, optionally within a zone.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NodeMemory {
    /// NUMA node ID.
    pub node: u32,
    /// Zone, absent for node-wide totals.
    pub zone: Option<MemoryZone>,
    /// Measurements in print order.
    pub counters: Vec<MemoryCounter>,
}
/// Buddy allocator migration type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MigrationType {
    /// U.
    Unmovable,
    /// M.
    Movable,
    /// E.
    Reclaimable,
    /// H.
    HighAtomic,
    /// C.
    Cma,
    /// I.
    Isolate,
    /// A future migration type.
    Unknown(char),
}
/// A buddy allocator order bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FreeBlock {
    /// Available block count.
    pub count: u64,
    /// Size of each block as bytes.
    pub size: ByteSize,
    /// Migration types with available blocks.
    pub migration_types: Vec<MigrationType>,
}
/// Free blocks for a node and zone.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BuddyInfo {
    /// NUMA node ID.
    pub node: u32,
    /// Memory zone.
    pub zone: MemoryZone,
    /// Block buckets in print order.
    pub blocks: Vec<FreeBlock>,
    /// Reported total; not recomputed from rounded counters.
    pub total: ByteSize,
}
/// Hugepage pool counters for a node and page size.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HugePages {
    /// NUMA node ID.
    pub node: u32,
    /// Total huge pages.
    pub total: u64,
    /// Free huge pages.
    pub free: u64,
    /// Surplus huge pages.
    pub surplus: u64,
    /// Hugepage size as bytes.
    pub size: ByteSize,
}
/// System memory summary counter.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TotalKind {
    /// Total pagecache pages.
    PageCache,
    /// Pages in swap cache.
    SwapCache,
    /// Free swap in KiB.
    FreeSwap,
    /// Total swap in KiB.
    TotalSwap,
    /// RAM pages.
    Ram,
    /// HighMem/MovableOnly pages.
    HighMemMovable,
    /// Reserved pages.
    Reserved,
    /// CMA reserved pages.
    CmaReserved,
    /// Pages in the page-table cache, older kernels.
    PageTableCache,
    /// Hardware poisoned pages.
    HardwarePoisoned,
}
/// A system-wide total with explicit units.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemoryTotal {
    /// Summary counter identity.
    pub kind: TotalKind,
    /// Value and unit.
    pub value: MemoryValue,
}
/// Unit printed by allocation profiling.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SizeUnit {
    /// Bytes.
    Bytes,
    /// KiB.
    KiB,
    /// MiB.
    MiB,
    /// GiB.
    GiB,
    /// TiB.
    TiB,
}
/// An exact decimal representation of a rounded profiling measurement; not an exact allocation byte count.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReportedSize {
    /// Printed magnitude converted to bytes, rounded down to a whole byte.
    /// The kernel already rounded this measurement; this is not an exact allocation count.
    pub bytes: ByteSize,
    /// Decimal digits with the decimal point removed.
    pub mantissa: u64,
    /// Number of fractional digits.
    pub decimal_places: u32,
    /// Printed size unit.
    pub unit: SizeUnit,
}
/// Allocation profiling entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Allocation {
    /// Rounded size as printed, without floating point loss.
    pub size: ReportedSize,
    /// Allocation count.
    pub count: u64,
    /// Source path.
    pub file: String,
    /// Source line number.
    pub line: u32,
    /// Module identifier, if present.
    pub module: Option<String>,
    /// Allocation function.
    pub function: String,
}
/// Task table column identity.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TaskColumn {
    /// pid.
    Pid,
    /// uid.
    Uid,
    /// tgid.
    Tgid,
    /// total_vm.
    TotalVm,
    /// rss.
    Rss,
    /// rss_anon.
    RssAnon,
    /// rss_file.
    RssFile,
    /// rss_shmem.
    RssShmem,
    /// pgtables_bytes.
    PageTablesBytes,
    /// Legacy page-table page count.
    NrPtes,
    /// Legacy PMD table page count.
    NrPmds,
    /// Legacy PUD table page count.
    NrPuds,
    /// swapents.
    SwapEntries,
    /// oom_score_adj.
    OomScoreAdj,
    /// name.
    Name,
}
/// Task memory snapshot (Linux 6.6 or 6.18 table layout). No page-size conversion is performed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Task {
    /// Process ID.
    pub pid: u32,
    /// User ID.
    pub uid: u32,
    /// Thread group ID.
    pub tgid: u32,
    /// Virtual memory pages.
    pub total_vm_pages: u64,
    /// Resident pages.
    pub rss_pages: u64,
    /// Anonymous resident pages, absent in the older total-RSS-only layout.
    pub rss_anon_pages: Option<u64>,
    /// File-backed resident pages, absent in the older layout.
    pub rss_file_pages: Option<u64>,
    /// Shared resident pages, absent in the older layout.
    pub rss_shmem_pages: Option<u64>,
    /// Page table size in bytes, absent when the legacy header prints page counts.
    pub page_tables: Option<ByteSize>,
    /// Legacy nr_ptes page count; never silently treated as bytes.
    pub page_table_pages: Option<u64>,
    /// Legacy nr_pmds page count, when present in the header.
    pub pmd_table_pages: Option<u64>,
    /// Legacy nr_puds page count, when present in the header.
    pub pud_table_pages: Option<u64>,
    /// Swap entry count.
    pub swap_entries: u64,
    /// OOM score adjustment.
    pub oom_score_adj: i32,
    /// Task name.
    pub name: String,
}
/// OOM allocation constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Constraint {
    /// None constraint.
    None,
    /// Cpuset constraint.
    Cpuset,
    /// MemoryPolicy constraint.
    MemoryPolicy,
    /// MemoryCgroup constraint.
    MemoryCgroup,
    /// A future constraint identifier.
    Unknown(String),
}
/// Inclusive NUMA node range; retained compactly instead of allocating every node.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NodeRange {
    /// First node ID.
    pub start: u32,
    /// Last node ID, inclusive.
    pub end: u32,
}
/// Whether the OOM occurred globally or within a memory cgroup.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OomScope {
    /// Global OOM.
    Global,
    /// Memory cgroup path.
    MemoryCgroup(String),
    /// No scope marker was printed, as on kernels without CONFIG_MEMCG.
    Unknown,
}
/// OOM constraint and victim summary.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OomContext {
    /// Allocation constraint.
    pub constraint: Constraint,
    /// Allowed nodes; None represents (null).
    pub nodemask: Option<Vec<NodeRange>>,
    /// Cpuset path; absent on kernels without CONFIG_CPUSETS.
    pub cpuset: Option<String>,
    /// Allowed memory nodes; absent restrictions are unknown, not an empty set.
    pub mems_allowed: Option<Vec<NodeRange>>,
    /// Printed global or memory-cgroup scope, or Unknown when omitted.
    pub scope: OomScope,
    /// Victim memory cgroup path; absent on kernels without CONFIG_MEMCG.
    pub task_memcg: Option<String>,
    /// Victim command.
    pub task: String,
    /// Victim process ID.
    pub pid: u32,
    /// Victim user ID.
    pub uid: u32,
}

/// Column layout used for a task memory table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TaskLayout {
    /// Legacy nr_ptes page counts, optionally followed by PMD/PUD page counts.
    Legacy {
        /// Header includes nr_pmds.
        pmds: bool,
        /// Header includes nr_puds.
        puds: bool,
    },
    /// Total RSS only, as in Linux 6.6.
    TotalRss,
    /// Total RSS and anonymous/file/shared breakdown, as in Linux 6.18.
    RssBreakdown,
}

/// One OOM invocation and its diagnostics, or an isolated OOM-specific message.
/// Records retain original line numbers. An event can be incomplete (no kill),
/// and a delayed reaper may appear after unrelated messages or another event.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OomEvent {
    /// Typed OOM records in source order. No unrelated kernel messages are stored.
    pub records: Vec<crate::Record>,
}

/// Register value, optionally qualified by a segment selector.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RegisterValue {
    /// Register identity.
    pub register: Register,
    /// Segment selector when printed (for example, RSP's 002b).
    pub segment: Option<u16>,
    /// Raw unsigned bits; negative machine values are not sign-converted.
    pub value: u64,
}

/// Instruction pointer captured in a stack dump.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InstructionPointer {
    /// Code segment selector.
    pub segment: u16,
    /// Numeric address or resolved kernel symbol.
    pub location: InstructionLocation,
}

/// Location of an instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InstructionLocation {
    /// Absolute virtual address.
    Address(u64),
    /// Resolved function with offset, size, and optional module.
    Symbol(StackFrame),
}

/// Instruction bytes surrounding a fault site.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InstructionCode {
    /// Byte dump, with the index of the byte marked by angle brackets.
    Bytes {
        /// Bytes in their printed order.
        bytes: Vec<u8>,
        /// Index of the marked instruction byte, if present.
        instruction_index: Option<usize>,
    },
    /// Kernel could not read bytes at this address.
    Unavailable(u64),
}

/// x86-64 register identity in an OOM stack dump.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Register {
    /// RSP register.
    Rsp,
    /// EFLAGS register.
    Eflags,
    /// ORIG_RAX register.
    OrigRax,
    /// RAX register.
    Rax,
    /// RBX register.
    Rbx,
    /// RCX register.
    Rcx,
    /// RDX register.
    Rdx,
    /// RSI register.
    Rsi,
    /// RDI register.
    Rdi,
    /// RBP register.
    Rbp,
    /// R08 register.
    R08,
    /// R09 register.
    R09,
    /// R10 register.
    R10,
    /// R11 register.
    R11,
    /// R12 register.
    R12,
    /// R13 register.
    R13,
    /// R14 register.
    R14,
    /// R15 register.
    R15,
}
impl Register {
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "RSP" => Self::Rsp,
            "EFLAGS" => Self::Eflags,
            "ORIG_RAX" => Self::OrigRax,
            "RAX" => Self::Rax,
            "RBX" => Self::Rbx,
            "RCX" => Self::Rcx,
            "RDX" => Self::Rdx,
            "RSI" => Self::Rsi,
            "RDI" => Self::Rdi,
            "RBP" => Self::Rbp,
            "R08" => Self::R08,
            "R09" => Self::R09,
            "R10" => Self::R10,
            "R11" => Self::R11,
            "R12" => Self::R12,
            "R13" => Self::R13,
            "R14" => Self::R14,
            "R15" => Self::R15,
            _ => return None,
        })
    }
}

/// Resource charged to a memory cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CgroupResource {
    /// Memory charge (RAM).
    Memory,
    /// Combined memory and swap charge, cgroup v1.
    MemoryAndSwap,
    /// Separate swap charge, cgroup v2.
    Swap,
    /// Separate kernel-memory charge, older cgroup v1.
    KernelMemory,
}
impl std::fmt::Display for CgroupResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Memory => "memory",
            Self::MemoryAndSwap => "memory + swap",
            Self::Swap => "swap",
            Self::KernelMemory => "kernel memory",
        })
    }
}
/// Printed cgroup budget snapshot. Very large sentinel limits are retained verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CgroupBudget {
    /// Charged resource.
    pub resource: CgroupResource,
    /// Current usage.
    pub usage: ByteSize,
    /// Printed limit; kernel unlimited sentinels are not silently reinterpreted.
    pub limit: ByteSize,
    /// Cumulative failed charge count, not a count of OOM kills.
    pub fail_count: u64,
}
/// One cgroup memory.stat measurement with explicit units.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CgroupStat {
    /// Original field name, including vendor/future names.
    pub name: String,
    /// Quantity; unknown fields retain an unclassified integer.
    pub value: CgroupStatValue,
}
/// Units used by cgroup memory.stat.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CgroupStatValue {
    /// Byte-valued memory quantity.
    Bytes(ByteSize),
    /// Cumulative event count; not a byte quantity or rate.
    Count(u64),
    /// Unknown field's integer, with no inferred unit.
    Unknown(u64),
}

/// Cumulative swap-cache operations, printed by older kernels.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SwapCacheStats {
    /// Pages added to swap cache.
    pub added: u64,
    /// Pages deleted from swap cache.
    pub deleted: u64,
    /// Successful swap-cache lookups.
    pub found: u64,
    /// Total swap-cache lookups.
    pub searched: u64,
}

impl std::fmt::Display for MemoryMetric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ActiveAnon => "active_anon",
            Self::InactiveAnon => "inactive_anon",
            Self::IsolatedAnon => "isolated_anon",
            Self::ActiveFile => "active_file",
            Self::InactiveFile => "inactive_file",
            Self::IsolatedFile => "isolated_file",
            Self::Unevictable => "unevictable",
            Self::Dirty => "dirty",
            Self::Writeback => "writeback",
            Self::Unstable => "unstable",
            Self::WritebackTmp => "writeback_tmp",
            Self::SlabReclaimable => "slab_reclaimable",
            Self::SlabUnreclaimable => "slab_unreclaimable",
            Self::Mapped => "mapped",
            Self::Shmem => "shmem",
            Self::Pagetables => "pagetables",
            Self::SecPagetables => "sec_pagetables",
            Self::Bounce => "bounce",
            Self::KernelMiscReclaimable => "kernel_misc_reclaimable",
            Self::Free => "free",
            Self::FreePcp => "free_pcp",
            Self::FreeCma => "free_cma",
            Self::ShmemThp => "shmem_thp",
            Self::ShmemPmdmapped => "shmem_pmdmapped",
            Self::AnonThp => "anon_thp",
            Self::KernelStack => "kernel_stack",
            Self::ShadowCallStack => "shadow_call_stack",
            Self::AllUnreclaimable => "all_unreclaimable",
            Self::Boost => "boost",
            Self::Min => "min",
            Self::Low => "low",
            Self::High => "high",
            Self::ReservedHighatomic => "reserved_highatomic",
            Self::FreeHighatomic => "free_highatomic",
            Self::Writepending => "writepending",
            Self::Zspages => "zspages",
            Self::Present => "present",
            Self::Managed => "managed",
            Self::Mlocked => "mlocked",
            Self::PagesScanned => "pages_scanned",
            Self::LocalPcp => "local_pcp",
            Self::Balloon => "Balloon",
        })
    }
}

/// Legacy invoking-task cpuset membership, not proof of allocation constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LegacyCpuset {
    /// Invoking task name.
    pub task: String,
    /// Cpuset path.
    pub cpuset: String,
    /// Allowed memory nodes.
    pub mems_allowed: Vec<NodeRange>,
}
/// Legacy OOM victim selection. Selection does not confirm a completed kill.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VictimSelection {
    /// Selected PID.
    pub pid: u32,
    /// Selected task name.
    pub name: String,
    /// Printed badness score, distinct from oom_score_adj.
    pub score: u64,
    /// Message explicitly reports memory-cgroup OOM.
    pub memory_cgroup: bool,
}
