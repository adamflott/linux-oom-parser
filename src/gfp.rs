//! Numeric GFP decoding for explicitly verified upstream kernel releases.
//! Bit assignments are facts from include/linux/gfp.h (3.10, 4.14, 5.x)
//! and include/linux/gfp_types.h (6.x). Version suffixes do not establish that
//! a vendor kernel retained the upstream layout. Conditional extension bits
//! remain unresolved without the source kernel configuration.
use crate::GfpFlag;

const LINUX_3_10: &[(u64, &str)] = &[
    (0x1, "__GFP_DMA"),
    (0x2, "__GFP_HIGHMEM"),
    (0x4, "__GFP_DMA32"),
    (0x8, "__GFP_MOVABLE"),
    (0x10, "__GFP_WAIT"),
    (0x20, "__GFP_HIGH"),
    (0x40, "__GFP_IO"),
    (0x80, "__GFP_FS"),
    (0x100, "__GFP_COLD"),
    (0x200, "__GFP_NOWARN"),
    (0x400, "__GFP_REPEAT"),
    (0x800, "__GFP_NOFAIL"),
    (0x1000, "__GFP_NORETRY"),
    (0x2000, "__GFP_MEMALLOC"),
    (0x4000, "__GFP_COMP"),
    (0x8000, "__GFP_ZERO"),
    (0x10000, "__GFP_NOMEMALLOC"),
    (0x20000, "__GFP_HARDWALL"),
    (0x40000, "__GFP_THISNODE"),
    (0x80000, "__GFP_RECLAIMABLE"),
    (0x100000, "__GFP_KMEMCG"),
    (0x200000, "__GFP_NOTRACK"),
    (0x400000, "__GFP_NO_KSWAPD"),
    (0x800000, "__GFP_OTHER_NODE"),
    (0x1000000, "__GFP_WRITE"),
];

const LINUX_4_14: &[(u64, &str)] = &[
    (0x1, "__GFP_DMA"),
    (0x2, "__GFP_HIGHMEM"),
    (0x4, "__GFP_DMA32"),
    (0x8, "__GFP_MOVABLE"),
    (0x10, "__GFP_RECLAIMABLE"),
    (0x20, "__GFP_HIGH"),
    (0x40, "__GFP_IO"),
    (0x80, "__GFP_FS"),
    (0x100, "__GFP_COLD"),
    (0x200, "__GFP_NOWARN"),
    (0x400, "__GFP_RETRY_MAYFAIL"),
    (0x800, "__GFP_NOFAIL"),
    (0x1000, "__GFP_NORETRY"),
    (0x2000, "__GFP_MEMALLOC"),
    (0x4000, "__GFP_COMP"),
    (0x8000, "__GFP_ZERO"),
    (0x10000, "__GFP_NOMEMALLOC"),
    (0x20000, "__GFP_HARDWALL"),
    (0x40000, "__GFP_THISNODE"),
    (0x80000, "__GFP_ATOMIC"),
    (0x100000, "__GFP_ACCOUNT"),
    (0x200000, "__GFP_NOTRACK"),
    (0x400000, "__GFP_DIRECT_RECLAIM"),
    (0x800000, "__GFP_WRITE"),
    (0x1000000, "__GFP_KSWAPD_RECLAIM"),
];

const MODERN: &[(u64, &str)] = &[
    (0x1, "__GFP_DMA"),
    (0x2, "__GFP_HIGHMEM"),
    (0x4, "__GFP_DMA32"),
    (0x8, "__GFP_MOVABLE"),
    (0x10, "__GFP_RECLAIMABLE"),
    (0x20, "__GFP_HIGH"),
    (0x40, "__GFP_IO"),
    (0x80, "__GFP_FS"),
    (0x100, "__GFP_ZERO"),
    (0x400, "__GFP_DIRECT_RECLAIM"),
    (0x800, "__GFP_KSWAPD_RECLAIM"),
    (0x1000, "__GFP_WRITE"),
    (0x2000, "__GFP_NOWARN"),
    (0x4000, "__GFP_RETRY_MAYFAIL"),
    (0x8000, "__GFP_NOFAIL"),
    (0x10000, "__GFP_NORETRY"),
    (0x20000, "__GFP_MEMALLOC"),
    (0x40000, "__GFP_COMP"),
    (0x80000, "__GFP_NOMEMALLOC"),
    (0x100000, "__GFP_HARDWALL"),
    (0x200000, "__GFP_THISNODE"),
    (0x400000, "__GFP_ACCOUNT"),
];

/// Decode the configuration-independent part of a numeric GFP mask.
///
/// Supports upstream 3.10, 4.14, 5.4, 5.10, 5.13, 5.15, 6.1, 6.6,
/// 6.12 and 6.18 layouts, including patch and vendor suffixes. Returns `None`
/// for unverified releases. Printed symbolic flags should take precedence.
/// Unrecognized, unused and configuration-dependent bits are retained as
/// [`GfpFlag::UnknownBits`]. A vendor/backported layout may differ from upstream.
///
/// Sources: <https://github.com/torvalds/linux/blob/v3.10/include/linux/gfp.h>
/// and <https://github.com/torvalds/linux/blob/v6.18/include/linux/gfp_types.h>.
pub fn decode_gfp_mask(mask: u64, kernel_release: &str) -> Option<Vec<GfpFlag>> {
    let mut parts = kernel_release.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts
        .next()?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse::<u32>()
        .ok()?;
    let (table, atomic, zerotags) = match (major, minor) {
        (3, 10) => (LINUX_3_10, false, false),
        (4, 14) => (LINUX_4_14, false, false),
        (5, 4 | 10 | 13) => (MODERN, true, false),
        (5, 15) | (6, 1) => (MODERN, true, true),
        (6, 6 | 12 | 18) => (MODERN, false, true),
        _ => return None,
    };
    let mut remaining = mask;
    let mut flags = Vec::new();
    for &(bit, name) in table {
        if remaining & bit != 0 {
            flags.push(GfpFlag::from_name(name));
            remaining &= !bit;
        }
    }
    if atomic && remaining & 0x200 != 0 {
        flags.push(GfpFlag::FlagAtomic);
        remaining &= !0x200;
    }
    if zerotags && remaining & 0x800000 != 0 {
        flags.push(GfpFlag::FlagZerotags);
        remaining &= !0x800000;
    }
    if remaining != 0 {
        flags.push(GfpFlag::UnknownBits(remaining));
    }
    Some(flags)
}
