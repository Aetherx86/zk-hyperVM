use zkhypervm::ept::{
    DecomposedGpa, DecomposedGva, GuestPte, HostEpte, MemoryOwner, NestedMemoryManager,
};

#[test]
fn test_ept_missing_entries_and_fault_classification() {
    let mut mem = NestedMemoryManager::new();
    let eptp = 0x1000u64;

    // 1. Missing EPML4E -> EPML4 non-present fault
    let res_epml4 = mem.walk_ept_1d(eptp, 0x50);
    assert_eq!(
        res_epml4.err(),
        Some("EPT Violation at EPML4 (Non-Present)")
    );

    // Populate valid EPML4E pointing to EPDPT at HFN 2
    let epte_valid = HostEpte {
        raw: 0,
        read: true,
        write: true,
        execute: true,
        mem_type: 6,
        ignore_pat: false,
        page_size: false,
        accessed: true,
        dirty: true,
        execute_user: true,
        hfn: 2,
        suppress_ve: false,
    };
    mem.write_hpa_word(0x1000, epte_valid.encode());

    // 2. Missing EPDPT -> EPDPT non-present fault
    let res_epdpt = mem.walk_ept_1d(eptp, 0x50);
    assert_eq!(
        res_epdpt.err(),
        Some("EPT Violation at EPDPT (Non-Present)")
    );

    // Populate valid EPDPTE pointing to EPD at HFN 3
    mem.write_hpa_word(
        0x2000,
        HostEpte {
            hfn: 3,
            ..epte_valid
        }
        .encode(),
    );

    // 3. Missing EPD -> EPD non-present fault
    let res_epd = mem.walk_ept_1d(eptp, 0x50);
    assert_eq!(res_epd.err(), Some("EPT Violation at EPD (Non-Present)"));

    // Populate valid EPDE pointing to EPTE at HFN 4
    mem.write_hpa_word(
        0x3000,
        HostEpte {
            hfn: 4,
            ..epte_valid
        }
        .encode(),
    );

    // 4. Missing EPTE -> EPTE non-present fault
    let dec = DecomposedGpa::from_gpa(0x50 << 12);
    let epte_hpa = (4 << 12) + (dec.idx_ept as u64) * 8;
    // Currently 0 at epte_hpa
    let res_epte = mem.walk_ept_1d(eptp, 0x50);
    assert_eq!(res_epte.err(), Some("EPT Violation at EPTE (Non-Present)"));

    // Now populate EPTE -> walk succeeds!
    mem.write_hpa_word(
        epte_hpa,
        HostEpte {
            hfn: 100,
            ..epte_valid
        }
        .encode(),
    );
    let res_ok = mem.walk_ept_1d(eptp, 0x50);
    assert!(res_ok.is_ok());
    assert_eq!(res_ok.unwrap().hfn, 100);
}

#[test]
fn test_ept_host_huge_pages_1gb_and_2mb() {
    let mut mem = NestedMemoryManager::new();
    let eptp = 0x1000u64;

    let epte_base = HostEpte {
        raw: 0,
        read: true,
        write: true,
        execute: true,
        mem_type: 6,
        ignore_pat: false,
        page_size: false,
        accessed: true,
        dirty: true,
        execute_user: true,
        hfn: 2,
        suppress_ve: false,
    };
    mem.write_hpa_word(0x1000, epte_base.encode());

    // Case 1: 1GB Huge Page in EPDPT (page_size = true)
    let epdpt_1gb = HostEpte {
        page_size: true,
        hfn: 0x8000, // base 1GB frame
        ..epte_base
    };
    mem.write_hpa_word(0x2000, epdpt_1gb.encode());

    let trans_1gb = mem.walk_ept_1d(eptp, 0x123).unwrap();
    assert_eq!(trans_1gb.perms_ept & 0x7, 0x7); // R, W, X active

    // Case 2: 2MB Huge Page in EPD (page_size = true)
    // Configure regular EPDPT pointing to EPD at HFN 5
    mem.write_hpa_word(
        0x2000,
        HostEpte {
            hfn: 5,
            page_size: false,
            ..epte_base
        }
        .encode(),
    );
    let epd_2mb = HostEpte {
        page_size: true,
        hfn: 0x4000, // base 2MB frame
        ..epte_base
    };
    mem.write_hpa_word(0x5000, epd_2mb.encode());

    let trans_2mb = mem.walk_ept_1d(eptp, 0x45).unwrap();
    assert_eq!(trans_2mb.perms_ept & 0x7, 0x7);
}

#[test]
fn test_guest_page_fault_classification() {
    let mut mem = NestedMemoryManager::new();
    let eptp = 0x1000u64;
    let cr3 = 0x2000u64;

    let epte_base = HostEpte {
        raw: 0,
        read: true,
        write: true,
        execute: true,
        mem_type: 6,
        ignore_pat: false,
        page_size: false,
        accessed: true,
        dirty: true,
        execute_user: true,
        hfn: 2,
        suppress_ve: false,
    };
    // Identity host EPT mappings for tables
    mem.write_hpa_word(0x1000, epte_base.encode());
    mem.write_hpa_word(
        0x2000,
        HostEpte {
            hfn: 3,
            ..epte_base
        }
        .encode(),
    );
    mem.write_hpa_word(
        0x3000,
        HostEpte {
            hfn: 4,
            ..epte_base
        }
        .encode(),
    );
    mem.write_hpa_word(
        0x4000 + 2 * 8,
        HostEpte {
            hfn: 2,
            ..epte_base
        }
        .encode(),
    );

    let gva = 0x0000_1234_5678_9000u64;

    // 1. Guest PML4E non-present
    let res = mem.walk_2d_nested(1, cr3, eptp, gva);
    assert_eq!(res.err(), Some("Guest Page Fault: PML4E not present"));

    // Populate guest PML4E
    let guest_pte_base = GuestPte {
        raw: 0,
        present: true,
        read_write: true,
        user_supervisor: true,
        page_write_through: false,
        page_cache_disable: false,
        accessed: true,
        dirty: true,
        page_size: false,
        global: false,
        gfn: 10,
        no_execute: false,
    };
    let dec = DecomposedGva::from_gva(gva);
    let pml4e_hpa = (2 << 12) + (dec.idx_pml4 as u64) * 8;
    mem.write_hpa_word(pml4e_hpa, guest_pte_base.encode());

    // Host translation for GFN 10
    let dec_gpa10 = DecomposedGpa::from_gpa(10 << 12);
    let epte_hpa10 = (4 << 12) + (dec_gpa10.idx_ept as u64) * 8;
    mem.write_hpa_word(
        epte_hpa10,
        HostEpte {
            hfn: 20,
            ..epte_base
        }
        .encode(),
    );

    // 2. Guest PDPTE non-present
    let res_pdpt = mem.walk_2d_nested(1, cr3, eptp, gva);
    assert_eq!(res_pdpt.err(), Some("Guest Page Fault: PDPTE not present"));
}

#[test]
fn test_ept_memory_epoch_tracking() {
    let mut mem = NestedMemoryManager::new();
    assert_eq!(mem.tau_ept, 1);

    // Tag HFN 5 as belonging to EPT Tree
    mem.ownership.insert(5, MemoryOwner::EptTree(1));
    // Tag HFN 6 as Guest Exclusive memory
    mem.ownership.insert(6, MemoryOwner::GuestExclusive(1));

    // Writing to EptTree frame must increment tau_ept
    mem.write_hpa_word(5 << 12, 0x1234);
    assert_eq!(mem.tau_ept, 2);

    mem.write_hpa_word((5 << 12) + 8, 0x5678);
    assert_eq!(mem.tau_ept, 3);

    // Writing to GuestExclusive frame must NOT increment tau_ept
    mem.write_hpa_word(6 << 12, 0x9999);
    assert_eq!(mem.tau_ept, 3);
}
