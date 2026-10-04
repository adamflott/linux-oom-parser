#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test assertions")]
use linux_oom_parser::*;

#[test]
fn bit_interpretation_changes_with_verified_kernel_layout() {
    assert_eq!(
        decode_gfp_mask(0x10, "3.10.0-514.el7.x86_64"),
        Some(vec![GfpFlag::FlagWait])
    );
    assert_eq!(
        decode_gfp_mask(0x10, "4.14.10"),
        Some(vec![GfpFlag::FlagReclaimable])
    );
    assert_eq!(
        decode_gfp_mask(0x100, "3.10.0"),
        Some(vec![GfpFlag::FlagCold])
    );
    assert_eq!(
        decode_gfp_mask(0x100, "6.18.0"),
        Some(vec![GfpFlag::FlagZero])
    );
    assert_eq!(
        decode_gfp_mask(0x200, "6.1.1-arch"),
        Some(vec![GfpFlag::FlagAtomic])
    );
    assert_eq!(
        decode_gfp_mask(0x200, "6.6.0"),
        Some(vec![GfpFlag::UnknownBits(0x200)])
    );
    assert_eq!(
        decode_gfp_mask(0x1000000, "6.18.0"),
        Some(vec![GfpFlag::UnknownBits(0x1000000)])
    );
    assert_eq!(
        decode_gfp_mask(0x800000, "5.4.0"),
        Some(vec![GfpFlag::UnknownBits(0x800000)])
    );
    assert_eq!(
        decode_gfp_mask(0x800000, "5.15.158-2-pve"),
        Some(vec![GfpFlag::FlagZerotags])
    );
    for version in ["3.9.0", "6.2.0", "7.0", "unknown", "", "6.", "6"] {
        assert_eq!(decode_gfp_mask(0xcc0, version), None);
    }
    for version in [
        "3.10", "4.14", "5.4", "5.10", "5.13", "5.15", "6.1", "6.6", "6.12", "6.18",
    ] {
        assert_eq!(decode_gfp_mask(0, version), Some(vec![]));
        assert!(
            decode_gfp_mask(u64::MAX, version)
                .unwrap()
                .iter()
                .any(|f| matches!(f, GfpFlag::UnknownBits(_)))
        );
    }
}

#[test]
fn analysis_decodes_only_when_symbols_are_missing() {
    let cpu = "CPU: 0 PID: 7 Comm: worker Not tainted 3.10.0-514.el7.x86_64 #1\n";
    let invocation = "worker invoked oom-killer: gfp_mask=0x201da, order=0, oom_score_adj=0\n";
    let event = parse_events(format!("{invocation}{cpu}"))
        .unwrap()
        .remove(0);
    let report = analyze_event(&event);
    let decoded = report
        .evidence
        .iter()
        .find(|e| e.description.starts_with("Numeric GFP mask decoded"))
        .unwrap();
    assert_eq!(decoded.lines, [1, 2]);
    assert!(decoded.description.contains("__GFP_WAIT"));
    assert!(decoded.description.contains("__GFP_HARDWALL"));
    assert!(
        !report
            .limitations
            .iter()
            .any(|s| s.contains("mask was not decoded"))
    );
    let printed = invocation.replace("0x201da", "0x201da(GFP_KERNEL)");
    let event = parse_events(format!("{printed}{cpu}")).unwrap().remove(0);
    assert!(
        !analyze_event(&event)
            .evidence
            .iter()
            .any(|e| e.description.starts_with("Numeric GFP mask decoded"))
    );
    let unknown = parse_events(format!("{invocation}{}", cpu.replace("3.10.0", "7.0.0")))
        .unwrap()
        .remove(0);
    assert!(
        analyze_event(&unknown)
            .limitations
            .iter()
            .any(|s| s.contains("mask was not decoded"))
    );
}
