use zkhypervm::vmcs::{
    evaluate_cr_access_trap, verify_differential_vmentry, verify_vmcs_mediation_policy, ExitReason,
    VmcsCoord, VmcsVector,
};

#[test]
fn test_canonical_rip_edge_cases() {
    let mut omega = VmcsVector::new();

    // 1. Valid user canonical RIP (bit 47 = 0, bits 48..63 = 0x0000)
    omega.set_u64(VmcsCoord::RipGuest, 0x0000_7FFF_FFFF_0000);
    assert!(verify_differential_vmentry(&omega).is_ok());

    omega.set_u64(VmcsCoord::RipGuest, 0x0000_0000_0040_0000);
    assert!(verify_differential_vmentry(&omega).is_ok());

    // 2. Valid kernel canonical RIP (bit 47 = 1, bits 48..63 = 0xFFFF)
    omega.set_u64(VmcsCoord::RipGuest, 0xFFFF_8000_0000_0000);
    assert!(verify_differential_vmentry(&omega).is_ok());

    omega.set_u64(VmcsCoord::RipGuest, 0xFFFF_FFFF_8100_0000);
    assert!(verify_differential_vmentry(&omega).is_ok());

    // 3. Non-canonical edge cases:
    // Bit 47 is 1, but upper 16 bits are 0x0000
    omega.set_u64(VmcsCoord::RipGuest, 0x0000_8000_0000_0000);
    let res = verify_differential_vmentry(&omega);
    assert!(res.is_err());
    assert_eq!(
        res.err().unwrap(),
        "VMENTRY consistency check failed: Non-canonical guest RIP!"
    );

    // Bit 47 is 0, but upper 16 bits are 0xFFFF
    omega.set_u64(VmcsCoord::RipGuest, 0xFFFF_0000_0000_0000);
    assert!(verify_differential_vmentry(&omega).is_err());

    // Bit 48 set to 1 while bit 47 is 0
    omega.set_u64(VmcsCoord::RipGuest, 0x0001_0000_0000_0000);
    assert!(verify_differential_vmentry(&omega).is_err());
}

#[test]
fn test_cr0_paging_without_protection_rejection() {
    let mut omega = VmcsVector::new();
    omega.set_u64(VmcsCoord::RipGuest, 0x1000);

    // PE = bit 0, PG = bit 31
    // Case 1: PG = 1, PE = 0 -> Invalid x86 architecture state
    let invalid_cr0 = 1u64 << 31; // PG=1, PE=0
    omega.set_u64(VmcsCoord::Cr0Guest, invalid_cr0);
    let res = verify_differential_vmentry(&omega);
    assert!(res.is_err());
    assert_eq!(
        res.err().unwrap(),
        "VMENTRY consistency check failed: CR0 PG=1 requires PE=1!"
    );

    // Case 2: PG = 1, PE = 1 -> Valid protected paging
    let valid_cr0 = (1u64 << 31) | 1;
    omega.set_u64(VmcsCoord::Cr0Guest, valid_cr0);
    assert!(verify_differential_vmentry(&omega).is_ok());

    // Case 3: PG = 0, PE = 0 -> Valid real mode
    omega.set_u64(VmcsCoord::Cr0Guest, 0);
    assert!(verify_differential_vmentry(&omega).is_ok());
}

#[test]
fn test_cr_access_trapping_and_shadowing() {
    let cr0_initial = 0x0000_0000_8000_0001; // PE=1, PG=1
    let cr0_mask = 0x0000_0000_8000_0001; // hypervisor owns PE and PG
    let cr0_shadow = 0x0000_0000_8000_0001;

    // Guest attempts to write: clearing PE (bit 0)
    let guest_write = 0x0000_0000_8000_0000;
    let (trap, delta, new_cr) =
        evaluate_cr_access_trap(guest_write, cr0_mask, cr0_shadow, cr0_initial);

    // Must trap because bit 0 flipped under active mask
    assert!(trap);
    assert_eq!(delta, 1);
    // Guest state preserved upon trap
    assert_eq!(new_cr, cr0_initial);

    // Guest attempts to write unmasked bit (e.g. WP bit 16)
    let guest_write_wp = 0x0000_0000_8001_0001;
    let (trap_wp, delta_wp, new_cr_wp) =
        evaluate_cr_access_trap(guest_write_wp, cr0_mask, cr0_shadow, cr0_initial);

    // Unmasked bit write does NOT trap and updates state
    assert!(!trap_wp);
    assert_eq!(delta_wp, 0);
    assert_eq!(new_cr_wp, guest_write_wp);
}

#[test]
fn test_hypervisor_mediation_policy_invariance_enforcement() {
    let mut omega_prev = VmcsVector::new();
    let mut omega_next = VmcsVector::new();

    omega_prev.set_u64(VmcsCoord::RipGuest, 0x1000);
    omega_prev.set_u64(VmcsCoord::RspGuest, 0x8000);
    omega_prev.set_u64(VmcsCoord::Cr3Guest, 0x5000);
    omega_prev.set_u64(VmcsCoord::EptPointer, 0x2000);

    omega_next.set_u64(VmcsCoord::RipGuest, 0x1002); // 2-byte CPUID
    omega_next.set_u64(VmcsCoord::RspGuest, 0x8000);
    omega_next.set_u64(VmcsCoord::Cr3Guest, 0x5000);
    omega_next.set_u64(VmcsCoord::EptPointer, 0x2000);

    // Valid CPUID: RIP advanced by 2 bytes, GPR return values allowed
    omega_next.set_u64(VmcsCoord::RaxGuest, 0x0008_06EC);
    assert!(verify_vmcs_mediation_policy(
        &omega_prev,
        &omega_next,
        ExitReason::Cpuid as u32,
        0,
        2,
        false
    )
    .is_ok());

    // Violation 1: Tampering with invariant CR3 during CPUID exit
    omega_next.set_u64(VmcsCoord::Cr3Guest, 0x9000);
    let res = verify_vmcs_mediation_policy(
        &omega_prev,
        &omega_next,
        ExitReason::Cpuid as u32,
        0,
        2,
        false,
    );
    assert!(res.is_err());
    assert_eq!(
        res.err().unwrap(),
        "Violation of hypervisor mediation invariance mask!"
    );
    omega_next.set_u64(VmcsCoord::Cr3Guest, 0x5000); // restore

    // Violation 2: Incorrect RIP delta on synchronous instruction exit
    omega_next.set_u64(VmcsCoord::RipGuest, 0x1005); // expected 0x1002
    let res_rip = verify_vmcs_mediation_policy(
        &omega_prev,
        &omega_next,
        ExitReason::Cpuid as u32,
        0,
        2,
        false,
    );
    assert!(res_rip.is_err());
    assert_eq!(
        res_rip.err().unwrap(),
        "Synchronous exit failed instruction pointer advancement!"
    );
}

#[test]
fn test_asynchronous_exit_rip_invariance() {
    let mut omega_prev = VmcsVector::new();
    let mut omega_next = VmcsVector::new();

    omega_prev.set_u64(VmcsCoord::RipGuest, 0x4000);
    omega_next.set_u64(VmcsCoord::RipGuest, 0x4000); // Must be identical for asynchronous exit

    // External interrupt: RIP must not advance
    assert!(verify_vmcs_mediation_policy(
        &omega_prev,
        &omega_next,
        ExitReason::ExternalInterrupt as u32,
        0,
        0,
        false
    )
    .is_ok());

    // If an external interrupt illegally advances RIP -> rejected by invariance check
    omega_next.set_u64(VmcsCoord::RipGuest, 0x4004);
    let res = verify_vmcs_mediation_policy(
        &omega_prev,
        &omega_next,
        ExitReason::ExternalInterrupt as u32,
        0,
        0,
        false,
    );
    assert!(res.is_err());
    assert_eq!(
        res.err().unwrap(),
        "Violation of hypervisor mediation invariance mask!"
    );
}

#[test]
fn test_ept_ram_violation_invariance() {
    let mut omega_prev = VmcsVector::new();
    let mut omega_next = VmcsVector::new();

    omega_prev.set_u64(VmcsCoord::RipGuest, 0x2000);
    omega_prev.set_u64(VmcsCoord::RaxGuest, 0x1234);
    omega_prev.set_u64(VmcsCoord::EptPointer, 0x1000);

    omega_next.set_u64(VmcsCoord::RipGuest, 0x2000); // RAM fault restarts the faulting instruction
    omega_next.set_u64(VmcsCoord::RaxGuest, 0x1234);
    omega_next.set_u64(VmcsCoord::EptPointer, 0x3000); // EPTP allowed to update

    // Demand-paging RAM violation: is_mmio = false
    assert!(verify_vmcs_mediation_policy(
        &omega_prev,
        &omega_next,
        ExitReason::EptViolation as u32,
        0,
        0,
        false
    )
    .is_ok());

    // In a RAM violation, GPRs must NOT change
    omega_next.set_u64(VmcsCoord::RaxGuest, 0x5678);
    let res = verify_vmcs_mediation_policy(
        &omega_prev,
        &omega_next,
        ExitReason::EptViolation as u32,
        0,
        0,
        false,
    );
    assert!(res.is_err());
    assert_eq!(
        res.err().unwrap(),
        "Violation of hypervisor mediation invariance mask!"
    );
}
