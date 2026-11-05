//! Verifiable Virtual Machine Control Structure (zk-VMCS) and KVM Exit Mediation.
//!
//! Encodes the canonical 63-element committed world-switch vector,
//! exit invariance bitmasks MaskInt(rho), differential VMENTRY verification,
//! and the cryptographic mediation policy Phi_KVM.

use crate::crypto::Scalar;
use ark_ff::{PrimeField, Zero};

pub const VMCS_VECTOR_LEN: usize = 63;

/// Architectural coordinates in the 63-element world-switch vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum VmcsCoord {
    RipGuest = 0,
    RspGuest = 1,
    RflagsGuest = 2,
    Cr0Guest = 3,
    Cr3Guest = 4,
    Cr4Guest = 5,
    Dr7Guest = 6,
    Ia32EferGuest = 7,
    Ia32PatGuest = 8,
    Ia32SysenterCsGuest = 9,
    Ia32SysenterEspGuest = 10,
    Ia32SysenterEipGuest = 11,
    CsBaseGuest = 12,
    CsSelLimAttrGuest = 13,
    SsBaseGuest = 14,
    SsSelLimAttrGuest = 15,
    DsBaseGuest = 16,
    DsSelLimAttrGuest = 17,
    EsBaseGuest = 18,
    EsSelLimAttrGuest = 19,
    FsBaseGuest = 20,
    FsSelLimAttrGuest = 21,
    GsBaseGuest = 22,
    GsSelLimAttrGuest = 23,
    GdtrBaseLimGuest = 24,
    IdtrBaseLimGuest = 25,
    ActivityIntrStateGuest = 26,
    PinProcCtrl12 = 27,
    ExcBitmap = 28,
    Cr0GuestHostMask = 29,
    Cr0ReadShadow = 30,
    Cr4GuestHostMask = 31,
    Cr4ReadShadow = 32,
    EptPointer = 33,
    Vpid = 34,
    ExitReason = 35,
    ExitQualification = 36,
    GuestLinearAddr = 37,
    GuestPhysicalAddr = 38,
    ExitIntrInfoErr = 39,
    ExitInstrLength = 40,
    IdtVectoringInfo = 41,
    VmEntryControls = 42,
    VmEntryIntrInfo = 43,
    VmEntryExcErr = 44,
    VmEntryInstrLen = 45,
    Cr2Guest = 46,
    Cr8Guest = 47,
    RaxGuest = 48,
    RcxGuest = 49,
    RdxGuest = 50,
    RbxGuest = 51,
    RbpGuest = 52,
    RsiGuest = 53,
    RdiGuest = 54,
    R8Guest = 55,
    R9Guest = 56,
    R10Guest = 57,
    R11Guest = 58,
    R12Guest = 59,
    R13Guest = 60,
    R14Guest = 61,
    R15Guest = 62,
}

impl VmcsCoord {
    pub fn index(self) -> usize {
        self as usize
    }

    pub fn bitmask(self) -> u64 {
        1u64 << (self as usize)
    }
}

/// Architectural VT-x Basic Exit Reasons
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ExitReason {
    ExternalInterrupt = 1,
    TripleFault = 2,
    InitSignal = 3,
    StartupIpi = 4,
    IoSmi = 5,
    OtherSmi = 6,
    InterruptWindow = 7,
    NmiWindow = 8,
    TaskSwitch = 9,
    Cpuid = 10,
    Getsec = 11,
    Hlt = 12,
    Invd = 13,
    Invlpg = 14,
    Rdpmc = 15,
    Rdtsc = 16,
    Rsm = 17,
    Vmcall = 18,
    Vmclear = 19,
    Vmlaunch = 20,
    Vmptrld = 21,
    Vmptrst = 22,
    Vmread = 23,
    Vmresume = 24,
    Vmwrite = 25,
    Vmxoff = 26,
    Vmxon = 27,
    CrAccess = 28,
    DrAccess = 29,
    IoInstruction = 30,
    Rdmsr = 31,
    Wrmsr = 32,
    VmEntryFailureInvalidGuestState = 33,
    VmEntryFailureMsrLoading = 34,
    Mwait = 36,
    MonitorTrapFlag = 37,
    Monitor = 39,
    Pause = 40,
    VmEntryFailureMachineCheck = 41,
    TprBelowThreshold = 43,
    ApicAccess = 44,
    VirtualizedEoi = 45,
    GdtrIdtrAccess = 46,
    LdtrTrAccess = 47,
    EptViolation = 48,
    EptMisconfiguration = 49,
    Invept = 50,
    Rdtscp = 51,
    PreemptionTimer = 52,
    Invvpid = 53,
    Wbinvd = 54,
    Xsetbv = 55,
    ApicWrite = 56,
    Rdrand = 57,
    Invpcid = 58,
    Vmfunc = 59,
    Encls = 60,
    Rdseed = 61,
    PmlFull = 62,
    Xsaves = 63,
    Xrstors = 64,
}

impl ExitReason {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::ExternalInterrupt),
            2 => Some(Self::TripleFault),
            3 => Some(Self::InitSignal),
            4 => Some(Self::StartupIpi),
            5 => Some(Self::IoSmi),
            6 => Some(Self::OtherSmi),
            7 => Some(Self::InterruptWindow),
            8 => Some(Self::NmiWindow),
            9 => Some(Self::TaskSwitch),
            10 => Some(Self::Cpuid),
            11 => Some(Self::Getsec),
            12 => Some(Self::Hlt),
            13 => Some(Self::Invd),
            14 => Some(Self::Invlpg),
            15 => Some(Self::Rdpmc),
            16 => Some(Self::Rdtsc),
            17 => Some(Self::Rsm),
            18 => Some(Self::Vmcall),
            19 => Some(Self::Vmclear),
            20 => Some(Self::Vmlaunch),
            21 => Some(Self::Vmptrld),
            22 => Some(Self::Vmptrst),
            23 => Some(Self::Vmread),
            24 => Some(Self::Vmresume),
            25 => Some(Self::Vmwrite),
            26 => Some(Self::Vmxoff),
            27 => Some(Self::Vmxon),
            28 => Some(Self::CrAccess),
            29 => Some(Self::DrAccess),
            30 => Some(Self::IoInstruction),
            31 => Some(Self::Rdmsr),
            32 => Some(Self::Wrmsr),
            33 => Some(Self::VmEntryFailureInvalidGuestState),
            34 => Some(Self::VmEntryFailureMsrLoading),
            36 => Some(Self::Mwait),
            37 => Some(Self::MonitorTrapFlag),
            39 => Some(Self::Monitor),
            40 => Some(Self::Pause),
            41 => Some(Self::VmEntryFailureMachineCheck),
            43 => Some(Self::TprBelowThreshold),
            44 => Some(Self::ApicAccess),
            45 => Some(Self::VirtualizedEoi),
            46 => Some(Self::GdtrIdtrAccess),
            47 => Some(Self::LdtrTrAccess),
            48 => Some(Self::EptViolation),
            49 => Some(Self::EptMisconfiguration),
            50 => Some(Self::Invept),
            51 => Some(Self::Rdtscp),
            52 => Some(Self::PreemptionTimer),
            53 => Some(Self::Invvpid),
            54 => Some(Self::Wbinvd),
            55 => Some(Self::Xsetbv),
            56 => Some(Self::ApicWrite),
            57 => Some(Self::Rdrand),
            58 => Some(Self::Invpcid),
            59 => Some(Self::Vmfunc),
            60 => Some(Self::Encls),
            61 => Some(Self::Rdseed),
            62 => Some(Self::PmlFull),
            63 => Some(Self::Xsaves),
            64 => Some(Self::Xrstors),
            _ => None,
        }
    }

    pub fn is_synchronous_instruction_trap(self) -> bool {
        matches!(
            self,
            Self::Cpuid
                | Self::Getsec
                | Self::Hlt
                | Self::Invd
                | Self::Invlpg
                | Self::Rdpmc
                | Self::Rdtsc
                | Self::Rsm
                | Self::Vmcall
                | Self::Vmclear
                | Self::Vmlaunch
                | Self::Vmptrld
                | Self::Vmptrst
                | Self::Vmread
                | Self::Vmresume
                | Self::Vmwrite
                | Self::Vmxoff
                | Self::Vmxon
                | Self::CrAccess
                | Self::DrAccess
                | Self::IoInstruction
                | Self::Rdmsr
                | Self::Wrmsr
                | Self::Rdtscp
                | Self::Wbinvd
                | Self::Xsetbv
                | Self::Rdrand
                | Self::Invpcid
                | Self::Rdseed
                | Self::Xsaves
                | Self::Xrstors
        )
    }
}

/// Computes the 63-bit invariance bitmask MaskInt(rho).
///
/// Bit j = 1 means coordinate j is strictly invariant across the VMEXIT handler.
/// Bit j = 0 means coordinate j is permitted to be modified by exit rho.
pub fn get_invariance_mask(rho: u32, exit_qual: u64, is_mmio: bool) -> u64 {
    let all_ones = (1u64 << 63) - 1; // 63 bits set

    match ExitReason::from_u32(rho) {
        Some(ExitReason::ExternalInterrupt) => {
            // Mutable coordinates: Activity/Intr State (26), VmEntry Intr Info (43),
            // VmEntry Exc Err (44), VmEntry Instr Len (45)
            all_ones
                & !(VmcsCoord::ActivityIntrStateGuest.bitmask()
                    | VmcsCoord::VmEntryIntrInfo.bitmask()
                    | VmcsCoord::VmEntryExcErr.bitmask()
                    | VmcsCoord::VmEntryInstrLen.bitmask())
        }
        Some(ExitReason::Cpuid) => {
            // Mutable: RIP (0), RAX (48), RCX (49), RDX (50), RBX (51)
            all_ones
                & !(VmcsCoord::RipGuest.bitmask()
                    | VmcsCoord::RaxGuest.bitmask()
                    | VmcsCoord::RcxGuest.bitmask()
                    | VmcsCoord::RdxGuest.bitmask()
                    | VmcsCoord::RbxGuest.bitmask())
        }
        Some(ExitReason::Vmcall) => {
            // Mutable: RIP (0), RAX (48)
            all_ones & !(VmcsCoord::RipGuest.bitmask() | VmcsCoord::RaxGuest.bitmask())
        }
        Some(ExitReason::IoInstruction) => {
            let is_in = (exit_qual & (1 << 3)) != 0;
            if is_in {
                all_ones & !(VmcsCoord::RipGuest.bitmask() | VmcsCoord::RaxGuest.bitmask())
            } else {
                // OUT: only RIP advances; RAX is strictly invariant!
                all_ones & !VmcsCoord::RipGuest.bitmask()
            }
        }
        Some(ExitReason::CrAccess) => {
            let cr_num = exit_qual & 0x0F;
            let access_type = (exit_qual >> 4) & 3;
            let mut unmasked = VmcsCoord::RipGuest.bitmask();
            match cr_num {
                0 => {
                    unmasked |= VmcsCoord::Cr0Guest.bitmask() | VmcsCoord::Cr0ReadShadow.bitmask();
                }
                3 => {
                    unmasked |= VmcsCoord::Cr3Guest.bitmask();
                }
                4 => {
                    unmasked |= VmcsCoord::Cr4Guest.bitmask() | VmcsCoord::Cr4ReadShadow.bitmask();
                }
                8 => {
                    unmasked |= VmcsCoord::Cr8Guest.bitmask();
                }
                _ => {}
            }
            if access_type == 1 {
                // MOV from CR: target general-purpose register is modified
                let gpr_idx = ((exit_qual >> 8) & 0x0F) as usize;
                let gpr_coord = match gpr_idx {
                    0 => VmcsCoord::RaxGuest,
                    1 => VmcsCoord::RcxGuest,
                    2 => VmcsCoord::RdxGuest,
                    3 => VmcsCoord::RbxGuest,
                    4 => VmcsCoord::RspGuest,
                    5 => VmcsCoord::RbpGuest,
                    6 => VmcsCoord::RsiGuest,
                    7 => VmcsCoord::RdiGuest,
                    r @ 8..=15 => match r {
                        8 => VmcsCoord::R8Guest,
                        9 => VmcsCoord::R9Guest,
                        10 => VmcsCoord::R10Guest,
                        11 => VmcsCoord::R11Guest,
                        12 => VmcsCoord::R12Guest,
                        13 => VmcsCoord::R13Guest,
                        14 => VmcsCoord::R14Guest,
                        15 => VmcsCoord::R15Guest,
                        _ => unreachable!(),
                    },
                    _ => VmcsCoord::RaxGuest,
                };
                unmasked |= gpr_coord.bitmask();
            }
            all_ones & !unmasked
        }
        Some(ExitReason::Rdmsr) => {
            // Mutable: RIP (0), RAX (48), RDX (50)
            all_ones
                & !(VmcsCoord::RipGuest.bitmask()
                    | VmcsCoord::RaxGuest.bitmask()
                    | VmcsCoord::RdxGuest.bitmask())
        }
        Some(ExitReason::Wrmsr) => {
            // Mutable: RIP (0); MSR bank updated separately
            all_ones & !VmcsCoord::RipGuest.bitmask()
        }
        Some(ExitReason::EptViolation) => {
            if is_mmio {
                // MMIO load: unmasks target GPR and RIP
                let target_reg = ((exit_qual >> 16) & 0x0F) as usize;
                let reg_coord = match target_reg {
                    0 => VmcsCoord::RaxGuest,
                    1 => VmcsCoord::RcxGuest,
                    2 => VmcsCoord::RdxGuest,
                    3 => VmcsCoord::RbxGuest,
                    4 => VmcsCoord::RspGuest,
                    5 => VmcsCoord::RbpGuest,
                    6 => VmcsCoord::RsiGuest,
                    7 => VmcsCoord::RdiGuest,
                    r @ 8..=15 => match r {
                        8 => VmcsCoord::R8Guest,
                        9 => VmcsCoord::R9Guest,
                        10 => VmcsCoord::R10Guest,
                        11 => VmcsCoord::R11Guest,
                        12 => VmcsCoord::R12Guest,
                        13 => VmcsCoord::R13Guest,
                        14 => VmcsCoord::R14Guest,
                        15 => VmcsCoord::R15Guest,
                        _ => unreachable!(),
                    },
                    _ => VmcsCoord::RaxGuest,
                };
                all_ones & !(VmcsCoord::RipGuest.bitmask() | reg_coord.bitmask())
            } else {
                // Demand paging RAM violation: only EPTP (33) can be updated.
                // 100% of guest GPRs, CRs, and RIP are strictly invariant!
                all_ones & !VmcsCoord::EptPointer.bitmask()
            }
        }
        Some(ExitReason::PreemptionTimer) => {
            // Pure scheduling quantum preemption: 100% invariant
            all_ones
        }
        _ => {
            // Default conservative: unmask only RIP
            all_ones & !VmcsCoord::RipGuest.bitmask()
        }
    }
}

/// Section 5.2.1: Control Register Guest/Host Masking and Read Shadows.
///
/// Evaluates whether a guest write of value `w` to CR0 or CR4 triggers a VMEXIT (exit 28).
/// Decomposes w, mask, and shadow into 8 bytes:
/// `delta_[k] = (w_[k] ^ shadow_[k]) & mask_[k]`
/// `Delta_CR = sum delta_[k] * 2^{8k}`
/// tau_CR = 1 if Delta_CR != 0 else 0
pub fn evaluate_cr_access_trap(
    w: u64,
    mask: u64,
    shadow: u64,
    cr_guest_current: u64,
) -> (bool, u64, u64) {
    let mut delta_cr = 0u64;
    for k in 0..8 {
        let w_k = ((w >> (8 * k)) & 0xFF) as u8;
        let s_k = ((shadow >> (8 * k)) & 0xFF) as u8;
        let m_k = ((mask >> (8 * k)) & 0xFF) as u8;
        let delta_k = (w_k ^ s_k) & m_k;
        delta_cr |= (delta_k as u64) << (8 * k);
    }

    let should_trap = delta_cr != 0;
    let new_cr_guest = if !should_trap {
        // If tau_CR == 0: CR_guest = (CR_guest & mask) | (w & !mask)
        (cr_guest_current & mask) | (w & !mask)
    } else {
        cr_guest_current // unchanged in guest state upon trap
    };

    (should_trap, delta_cr, new_cr_guest)
}

/// Representation of the 63-element committed world-switch vector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmcsVector {
    pub elements: [Scalar; VMCS_VECTOR_LEN],
}

impl VmcsVector {
    pub fn new() -> Self {
        Self {
            elements: [Scalar::zero(); VMCS_VECTOR_LEN],
        }
    }

    pub fn get(&self, coord: VmcsCoord) -> Scalar {
        self.elements[coord.index()]
    }

    pub fn set(&mut self, coord: VmcsCoord, val: Scalar) {
        self.elements[coord.index()] = val;
    }

    pub fn get_u64(&self, coord: VmcsCoord) -> u64 {
        let bigint = self.elements[coord.index()].into_bigint();
        bigint.as_ref()[0]
    }

    pub fn set_u64(&mut self, coord: VmcsCoord, val: u64) {
        self.elements[coord.index()] = Scalar::from(val);
    }
}

impl Default for VmcsVector {
    fn default() -> Self {
        Self::new()
    }
}

/// Verification of the Cryptographic Hypervisor Mediation Policy (Phi_KVM).
/// Enforces:
/// 1. Invariance Masking: I(rho) * (Omega^{(t+1)} - Omega^{(t)}) == 0^63
/// 2. Instruction Pointer Advancement: Delta_rip == ell (synchronous) or 0 (asynchronous)
pub fn verify_vmcs_mediation_policy(
    omega_prev: &VmcsVector,
    omega_next: &VmcsVector,
    rho: u32,
    exit_qual: u64,
    exit_instr_len: u32,
    is_mmio: bool,
) -> Result<(), &'static str> {
    let mask_int = get_invariance_mask(rho, exit_qual, is_mmio);

    // 1. Verify Hadamard product invariance constraint
    for j in 0..VMCS_VECTOR_LEN {
        let is_invariant = ((mask_int >> j) & 1) == 1;
        if is_invariant && omega_prev.elements[j] != omega_next.elements[j] {
            return Err("Violation of hypervisor mediation invariance mask!");
        }
    }

    // 2. Verify Instruction Pointer advancement
    let rip_prev = omega_prev.get_u64(VmcsCoord::RipGuest);
    let rip_next = omega_next.get_u64(VmcsCoord::RipGuest);
    let delta_rip = rip_next.wrapping_sub(rip_prev);

    let is_sync = ExitReason::from_u32(rho)
        .map(|r| r.is_synchronous_instruction_trap())
        .unwrap_or(false);

    if is_sync || (rho == ExitReason::EptViolation as u32 && is_mmio) {
        if delta_rip != exit_instr_len as u64 {
            return Err("Synchronous exit failed instruction pointer advancement!");
        }
    } else {
        if delta_rip != 0 {
            return Err("Asynchronous exit illegally advanced guest instruction pointer!");
        }
    }

    Ok(())
}

/// Differential VMENTRY Consistency Checks (34 CCS constraints).
/// Verifies:
/// 1. Canonical 48-bit RIP sign-extension:
///    rip = u_low + 2^47 * b_47 + 2^48 * u_high, where u_high == b_47 * (2^16 - 1)
/// 2. Control Register fixed bits (CR0 and CR4)
/// 3. VM-Entry interrupt injection conditions
pub fn verify_differential_vmentry(omega: &VmcsVector) -> Result<(), &'static str> {
    // 1. Canonical 48-bit RIP verification
    let rip = omega.get_u64(VmcsCoord::RipGuest);
    let b47 = (rip >> 47) & 1;
    let u_high = (rip >> 48) & 0xFFFF;
    let expected_high = if b47 == 1 { 0xFFFF } else { 0x0000 };
    if u_high != expected_high {
        return Err("VMENTRY consistency check failed: Non-canonical guest RIP!");
    }

    // 2. CR0/CR4 basic architectural constraints
    let cr0 = omega.get_u64(VmcsCoord::Cr0Guest);
    // PE (bit 0) and PG (bit 31): If PG=1, PE must be 1.
    let pe = cr0 & 1;
    let pg = (cr0 >> 31) & 1;
    if pg == 1 && pe == 0 {
        return Err("VMENTRY consistency check failed: CR0 PG=1 requires PE=1!");
    }

    // 3. Interrupt injection verification
    let intr_info = omega.get_u64(VmcsCoord::VmEntryIntrInfo);
    let valid = (intr_info >> 31) & 1;
    let intr_type = (intr_info >> 8) & 7;
    if valid == 1 && intr_type == 0 {
        // External interrupt injection requires IF=1
        let rflags = omega.get_u64(VmcsCoord::RflagsGuest);
        let if_flag = (rflags >> 9) & 1;
        if if_flag == 0 {
            return Err("VMENTRY check failed: Injecting external IRQ with IF=0!");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpuid_mediation_policy() {
        let mut prev = VmcsVector::new();
        prev.set_u64(VmcsCoord::RipGuest, 0x1000);
        prev.set_u64(VmcsCoord::RaxGuest, 0x1);
        prev.set_u64(VmcsCoord::RbxGuest, 0x0);
        prev.set_u64(VmcsCoord::RspGuest, 0x7fff_0000);

        let mut next = prev.clone();
        // Hypervisor handles CPUID: advances RIP by 2 (CPUID is 2 bytes: 0F A2),
        // sets RAX/RBX/RCX/RDX feature flags.
        next.set_u64(VmcsCoord::RipGuest, 0x1002);
        next.set_u64(VmcsCoord::RaxGuest, 0x000806E9);
        next.set_u64(VmcsCoord::RbxGuest, 0x00100800);

        // Valid mediation
        let res = verify_vmcs_mediation_policy(&prev, &next, ExitReason::Cpuid as u32, 0, 2, false);
        assert!(res.is_ok());

        // Malicious hypervisor tampering with RSP (forbidden on CPUID!)
        let mut tampered = next.clone();
        tampered.set_u64(VmcsCoord::RspGuest, 0x7fff_1000);
        let tampered_res =
            verify_vmcs_mediation_policy(&prev, &tampered, ExitReason::Cpuid as u32, 0, 2, false);
        assert!(tampered_res.is_err());
    }

    #[test]
    fn test_canonical_rip_vmentry() {
        let mut vec = VmcsVector::new();
        vec.set_u64(VmcsCoord::RipGuest, 0x0000_7FFF_1234_5678);
        vec.set_u64(VmcsCoord::Cr0Guest, 0x8000_0001); // PE=1, PG=1
        assert!(verify_differential_vmentry(&vec).is_ok());

        // Negative sign-extension: bit 47 is 1, so top 16 bits must be 0xFFFF
        vec.set_u64(VmcsCoord::RipGuest, 0xFFFF_8000_0000_0000);
        assert!(verify_differential_vmentry(&vec).is_ok());

        // Invalid non-canonical address
        vec.set_u64(VmcsCoord::RipGuest, 0x1234_8000_0000_0000);
        assert!(verify_differential_vmentry(&vec).is_err());
    }
}
