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
