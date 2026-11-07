use zkhypervm::ept::HostEpte;
use zkhypervm::leakage::{
    verify_l1tf_immunity, verify_spec_ctrl, MicroarchTaint, SPEC_CTRL_REQUIRED_MASK,
};

#[test]
fn test_multi_domain_taint_and_selective_flush() {
    let mut taint = MicroarchTaint::new();

    // VM 1 runs and accumulates taint
    taint.accumulate(1);
    assert_eq!(taint.foreign_taint(2, 4), 4); // 4 foreign components from VM 1

    // Switching to VM 2 without any flush barrier fails
    assert!(taint.verify_sanitization(1, 2).is_err());
    assert!(taint.verify_cross_domain_entry_gate(2, 4).is_err());

    // Flush only L1D
    taint.apply_barriers(true, false, false);
    assert_eq!(taint.l1d, 0);
    // Still fails because BTB and LFB are dirty!
    let btb_err = taint.verify_sanitization(1, 2);
    assert_eq!(
        btb_err.err(),
        Some("Microarchitectural Leakage: BTB contains residual branch prediction taint!")
    );

    // Flush BTB as well, but leave LFB dirty
    taint.apply_barriers(false, true, false);
    assert_eq!(taint.btb, 0);
    let lfb_err = taint.verify_sanitization(1, 2);
    assert_eq!(
        lfb_err.err(),
        Some("Microarchitectural Leakage: Line fill buffers contain residual MDS taint!")
    );

    // Finally apply VERW to clear LFB
    taint.apply_barriers(false, false, true);
    assert_eq!(taint.lfb_mds, 0);

    // Now sanitization and cross-domain entry gate must succeed!
    assert!(taint.verify_sanitization(1, 2).is_ok());
    assert!(taint.verify_cross_domain_entry_gate(2, 4).is_ok());
}

#[test]
fn test_l1tf_foreshadow_immunity_edge_cases() {
    let base_epte = HostEpte {
        raw: 0,
        read: false,
        write: false,
        execute: false,
        mem_type: 0,
        ignore_pat: false,
        page_size: false,
        accessed: false,
        dirty: false,
        execute_user: false,
        hfn: 0,
        suppress_ve: false,
    };

    // 1. Non-present EPTE with PFN = 0 -> PASS (L1TF immune)
    let non_present_zero = HostEpte {
        hfn: 0,
        ..base_epte
    };
    assert!(verify_l1tf_immunity(&non_present_zero).is_ok());

    // 2. Non-present EPTE with non-zero PFN -> FAIL (Vulnerable to Foreshadow)
    let non_present_nonzero = HostEpte {
        hfn: 0x1234_5678,
        ..base_epte
    };
    let res = verify_l1tf_immunity(&non_present_nonzero);
    assert!(res.is_err());
    assert_eq!(
        res.err().unwrap(),
        "L1TF (Foreshadow) Vulnerability: Non-present EPT entry contains non-zero physical frame number!"
    );

    // 3. Present EPTE (read = true) with non-zero PFN -> PASS
    let present_nonzero = HostEpte {
        read: true,
        hfn: 0x1234_5678,
        ..base_epte
    };
    assert!(verify_l1tf_immunity(&present_nonzero).is_ok());
}

#[test]
fn test_spec_ctrl_mitigation_flags() {
    // 1. Value with all required flags (IBRS, STIBP, SSBD, BHI_DIS_S)
    let valid_spec_ctrl = SPEC_CTRL_REQUIRED_MASK | 0x8; // with extra optional bit
    assert!(verify_spec_ctrl(valid_spec_ctrl).is_ok());

    // 2. Missing SSBD (bit 2)
    let missing_ssbd = SPEC_CTRL_REQUIRED_MASK & !(1 << 2);
    let res_ssbd = verify_spec_ctrl(missing_ssbd);
    assert!(res_ssbd.is_err());
    assert_eq!(
        res_ssbd.err().unwrap(),
        "Speculative Isolation Violation: Required SPEC_CTRL mitigation bits were stripped!"
    );

    // 3. Missing IBRS (bit 0)
    let missing_ibrs = SPEC_CTRL_REQUIRED_MASK & !1;
    assert!(verify_spec_ctrl(missing_ibrs).is_err());

    // 4. Missing BHI_DIS_S (bit 10)
    let missing_bhi = SPEC_CTRL_REQUIRED_MASK & !(1 << 10);
    assert!(verify_spec_ctrl(missing_bhi).is_err());
}
