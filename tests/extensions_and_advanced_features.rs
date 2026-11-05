use std::collections::HashMap;
use zkhypervm::ept::{HostEpte, NestedMemoryManager};
use zkhypervm::extensions::{LatticeFoldWitnessLimb, LiveMigrationCoordinator, Nested3DEptManager};

#[test]
fn test_3d_ept_nested_translation_lifecycle() {
    let mut mem = NestedMemoryManager::new();
    let eptp_01 = 0x1000u64; // L0 host EPT root
    let eptp_12 = 0x5000u64; // L1 virtualized EPT root

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

    // Setup EPT_01 (L0 host maps GFN_L1 10 -> HFN_L0 100)
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
        0x4000 + 10 * 8,
        HostEpte {
            hfn: 100,
            ..epte_base
        }
        .encode(),
    );

    // Setup EPT_12 (L1 guest hypervisor maps GFN_L2 5 -> GFN_L1 10)
    // Note: EPT_12 tables are stored in host physical memory
    mem.write_hpa_word(
        0x5000,
        HostEpte {
            hfn: 6,
            ..epte_base
        }
        .encode(),
    );
    mem.write_hpa_word(
        0x6000,
        HostEpte {
            hfn: 7,
            ..epte_base
        }
        .encode(),
    );
    mem.write_hpa_word(
        0x7000,
        HostEpte {
            hfn: 8,
            ..epte_base
        }
        .encode(),
    );
    mem.write_hpa_word(
        0x8000 + 5 * 8,
        HostEpte {
            hfn: 10,
            ..epte_base
        }
        .encode(),
    );

    let mgr = Nested3DEptManager::new(mem, eptp_01, eptp_12);

    // Translate GPA_L2 (GFN 5, offset 0x120) -> HPA_L0 (HFN 100, offset 0x120)
    let gpa_l2 = (5 << 12) | 0x120;
    let (hpa_l0, perms) = mgr.translate_gpa_l2_to_hpa_l0(gpa_l2).unwrap();

    assert_eq!(hpa_l0, (100 << 12) | 0x120);
    assert_eq!(perms & 0x7, 0x7);

    // Unmapped GPA_L2 -> EPT Violation
    let unmapped_gpa_l2 = (99 << 12) | 0x120;
    assert!(mgr.translate_gpa_l2_to_hpa_l0(unmapped_gpa_l2).is_err());
}

#[test]
fn test_3d_ept_nested_full_page_walk() {
    use zkhypervm::ept::GuestPte;

    let mut mem = NestedMemoryManager::new();
    let eptp_01 = 0x1000u64; // L0 host EPT root
    let eptp_12 = 0x5000u64; // L1 virtualized EPT root

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

    // EPT_01: L0 host mapping (EPML4: 1, EPDPT: 2, EPD: 3, EPTE: 4)
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

    // EPT_01 table (at HFN 4):
    // GFN_L1 10 -> HFN_L0 100 (for PML4_L2)
    mem.write_hpa_word(
        0x4000 + 10 * 8,
        HostEpte {
            hfn: 100,
            ..epte_base
        }
        .encode(),
    );
    // GFN_L1 11 -> HFN_L0 101 (for PDPT_L2)
    mem.write_hpa_word(
        0x4000 + 11 * 8,
        HostEpte {
            hfn: 101,
            ..epte_base
        }
        .encode(),
    );
    // GFN_L1 12 -> HFN_L0 102 (for PD_L2)
    mem.write_hpa_word(
        0x4000 + 12 * 8,
        HostEpte {
            hfn: 102,
            ..epte_base
        }
        .encode(),
    );
    // GFN_L1 13 -> HFN_L0 103 (for PT_L2)
    mem.write_hpa_word(
        0x4000 + 13 * 8,
        HostEpte {
            hfn: 103,
            ..epte_base
        }
        .encode(),
    );
    // GFN_L1 14 -> HFN_L0 104 (for Data Page)
    mem.write_hpa_word(
        0x4000 + 14 * 8,
        HostEpte {
            hfn: 104,
            ..epte_base
        }
        .encode(),
    );

    // EPT_12: L1 virtualized mapping (EPML4: 6, EPDPT: 7, EPD: 8)
    mem.write_hpa_word(
        0x5000,
        HostEpte {
            hfn: 6,
            ..epte_base
        }
        .encode(),
    );
    mem.write_hpa_word(
        0x6000,
        HostEpte {
            hfn: 7,
            ..epte_base
        }
        .encode(),
    );
    mem.write_hpa_word(
        0x7000,
        HostEpte {
            hfn: 8,
            ..epte_base
        }
        .encode(),
    );

    // EPT_12 table (at HFN 8):
    // GFN_L2 1 -> GFN_L1 10
    mem.write_hpa_word(
        0x8000 + 8,
        HostEpte {
            hfn: 10,
            ..epte_base
        }
        .encode(),
    );
    // GFN_L2 2 -> GFN_L1 11
    mem.write_hpa_word(
        0x8000 + 2 * 8,
        HostEpte {
            hfn: 11,
            ..epte_base
        }
        .encode(),
    );
    // GFN_L2 3 -> GFN_L1 12
    mem.write_hpa_word(
        0x8000 + 3 * 8,
        HostEpte {
            hfn: 12,
            ..epte_base
        }
        .encode(),
    );
    // GFN_L2 4 -> GFN_L1 13
    mem.write_hpa_word(
        0x8000 + 4 * 8,
        HostEpte {
            hfn: 13,
            ..epte_base
        }
        .encode(),
    );
    // GFN_L2 5 -> GFN_L1 14
    mem.write_hpa_word(
        0x8000 + 5 * 8,
        HostEpte {
            hfn: 14,
            ..epte_base
        }
        .encode(),
    );

    // Setup L2 guest page tables
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
        gfn: 2,
        no_execute: false,
    };

    // PML4_L2 at HFN_L0 100: index 0 points to GFN_L2 2
    mem.write_hpa_word(
        100 << 12,
        GuestPte {
            gfn: 2,
            ..guest_pte_base
        }
        .encode(),
    );
    // PDPT_L2 at HFN_L0 101: index 0 points to GFN_L2 3
    mem.write_hpa_word(
        101 << 12,
        GuestPte {
            gfn: 3,
            ..guest_pte_base
        }
        .encode(),
    );
    // PD_L2 at HFN_L0 102: index 0 points to GFN_L2 4
    mem.write_hpa_word(
        102 << 12,
        GuestPte {
            gfn: 4,
            ..guest_pte_base
        }
        .encode(),
    );
    // PT_L2 at HFN_L0 103: index 0 points to GFN_L2 5
    mem.write_hpa_word(
        103 << 12,
        GuestPte {
            gfn: 5,
            ..guest_pte_base
        }
        .encode(),
    );
    // Data Page at HFN_L0 104: offset 0x30 has 0xCAFEBABE
    mem.write_hpa_word((104 << 12) + 0x30, 0xCAFEBABE);

    let mgr = Nested3DEptManager::new(mem, eptp_01, eptp_12);

    // CR3_L2 has GFN_L2 = 1. Translate GVA_L2 0x0030
    let (tlb, final_hpa) = mgr.walk_3d_nested(1, 1 << 12, 0x0030).unwrap();

    assert_eq!(final_hpa, (104 << 12) + 0x30);
    assert_eq!(tlb.hfn_host, 104);
    assert_eq!(mgr.l0_memory.read_hpa_word(final_hpa), 0xCAFEBABE);
}

#[test]
fn test_live_migration_unmapped_destination_failure() {
    let mut src_map = HashMap::new();
    src_map.insert(1, 10);
    src_map.insert(2, 20);
    src_map.insert(3, 30); // guest page 3 is active on source

    let mut dest_map = HashMap::new();
    dest_map.insert(1, 100);
    dest_map.insert(2, 200);
    // Page 3 is omitted in destination mapping!

    let res = LiveMigrationCoordinator::rebase_destination_ept(&src_map, &dest_map);
    assert!(res.is_err());
    assert_eq!(
        res.err().unwrap(),
        "Live Migration Failure: Unmapped guest page in destination EPT!"
    );
}

#[test]
fn test_lattice_fold_boundary_conditions() {
    let beta = 256i64;
    let mut limb = LatticeFoldWitnessLimb::new(beta);

    // Exact boundary values: +/- beta must pass
    assert!(limb.push(beta).is_ok());
    assert!(limb.push(-beta).is_ok());
    assert!(limb.push(0).is_ok());
    assert!(limb.push(beta - 1).is_ok());
    assert!(limb.push(-beta + 1).is_ok());

    assert!(limb.verify_infinity_norm());

    // Boundary violation: beta + 1 and -(beta + 1) must fail
    let err_pos = limb.push(beta + 1);
    assert!(err_pos.is_err());
    assert_eq!(
        err_pos.err().unwrap(),
        "LatticeFold Norm Overflow: Coefficient exceeds beta_SIS bound!"
    );

    let err_neg = limb.push(-(beta + 1));
    assert!(err_neg.is_err());
    assert_eq!(
        err_neg.err().unwrap(),
        "LatticeFold Norm Overflow: Coefficient exceeds beta_SIS bound!"
    );
}
