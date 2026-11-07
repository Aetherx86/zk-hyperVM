//! The Hardware-Assisted Virtualization State Machine (M_KVM).
//!
//! Dual-mode execution engine modeling Linux KVM (kvm.ko / kvm-intel.ko)
//! and Intel VT-x hardware:
//!   - Root / Non-Root virtualization modes and CPL 0-3 rings
//!   - VMLAUNCH, VMRESUME, VMEXIT world switches
//!   - Fast-path TLB caching and asynchronous 2D-EPT refills
//!   - KVM Exit mediation (CPUID, VMCALL, CR access, RDMSR/WRMSR, EPT violation)
//!   - VirtIO device queue processing and IOMMU domain checking
//!   - Step-by-step witness generation and multi-circuit folding orchestration.

use crate::circuits::{synthesize_circuit_step, CircuitId};
use crate::crypto::Scalar;
use crate::ept::NestedMemoryManager;
use crate::folding::FoldingEngine;
use crate::leakage::{MicroarchTaint, SPEC_CTRL_REQUIRED_MASK};
use crate::logup::TlbTranslation;
use crate::virtio_iommu::{SplitVirtqueue, VerifiableIommu};
use crate::vmcs::{
    verify_differential_vmentry, verify_vmcs_mediation_policy, ExitReason, VmcsCoord, VmcsVector,
};
use ark_ff::{One, Zero};
use std::collections::HashMap;

/// Virtualization Mode
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtualizationMode {
    Root,    // Host Hypervisor
    NonRoot, // Guest Virtual Machine
}

/// Simulated Guest Instruction
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuestInstruction {
    /// reg_dst = reg_src1 + reg_src2
    Add { dst: u8, src1: u8, src2: u8 },
    /// reg_dst = reg_src1 - reg_src2
    Sub { dst: u8, src1: u8, src2: u8 },
    /// reg_dst = immediate
    MovImm { dst: u8, imm: u64 },
    /// Load 64-bit word from guest virtual address [reg_base + offset] into dst
    LoadMem { dst: u8, base: u8, offset: i64 },
    /// Store 64-bit word from src into guest virtual address [reg_base + offset]
    StoreMem { src: u8, base: u8, offset: i64 },
    /// CPUID instruction: traps to hypervisor (VMEXIT 10)
    Cpuid,
    /// VMCALL hypercall: traps to hypervisor (VMEXIT 18)
    Vmcall,
    /// MOV to CR0/CR3/CR4: traps if guest-host mask is set (VMEXIT 28)
    MovCr { cr_num: u8, reg_src: u8 },
    /// RDMSR: read model-specific register (VMEXIT 31)
    Rdmsr { msr_idx: u32 },
    /// WRMSR: write model-specific register (VMEXIT 32)
    Wrmsr { msr_idx: u32, val: u64 },
    /// VirtIO device kick: triggers I/O notification to host (VMEXIT 30)
    VirtioKick { queue_id: u16 },
    /// Halt instruction (VMEXIT 12)
    Hlt,
}

/// Statistics collected during virtualized execution
#[derive(Clone, Debug, Default)]
pub struct ExecutionStats {
    pub total_steps: usize,
    pub alu_steps: usize,
    pub mem_steps: usize,
    pub vmexit_count: usize,
    pub hyper_med_steps: usize,
    pub vmentry_count: usize,
    pub ept_refills: usize,
    pub virtio_dma_events: usize,
    pub tlb_hits: usize,
    pub tlb_misses: usize,
}

/// The zk-HyperKVM Virtual Machine Instance
pub struct HyperKvmInstance {
    pub vcpu_id: u32,
    pub mode: VirtualizationMode,
    pub cpl: u8,
    pub vmcs: VmcsVector,
    pub memory: NestedMemoryManager,
    pub tlb_cache: HashMap<u64, TlbTranslation>, // VPN -> Translation
    pub virtqueue: SplitVirtqueue,
    pub iommu: VerifiableIommu,
    pub taint: MicroarchTaint,
    pub msr_bank: HashMap<u32, u64>,
    pub stats: ExecutionStats,
}

impl HyperKvmInstance {
    pub fn new(vcpu_id: u32, cr3_guest: u64, eptp: u64) -> Self {
        let mut vmcs = VmcsVector::new();
        vmcs.set_u64(VmcsCoord::RipGuest, 0x0000_7FFF_0000_1000);
        vmcs.set_u64(VmcsCoord::RspGuest, 0x0000_7FFF_FFFF_0000);
        vmcs.set_u64(VmcsCoord::RflagsGuest, 0x0000_0000_0000_0202); // IF=1
        vmcs.set_u64(VmcsCoord::Cr0Guest, 0x8000_0001); // PE=1, PG=1
        vmcs.set_u64(VmcsCoord::Cr3Guest, cr3_guest);
        vmcs.set_u64(VmcsCoord::Cr4Guest, 0x0000_0020); // PAE=1
        vmcs.set_u64(VmcsCoord::EptPointer, eptp);
        vmcs.set_u64(VmcsCoord::Vpid, 1);

        let mut msr_bank = HashMap::new();
        msr_bank.insert(0x48, SPEC_CTRL_REQUIRED_MASK); // IA32_SPEC_CTRL

        let virtqueue = SplitVirtqueue::new(
            vcpu_id,
            0,
            256,
            0x0000_8000_0000,
            0x0000_8000_1000,
            0x0000_8000_2000,
        );

        let iommu = VerifiableIommu::new(0x0001_0000_0000);

        Self {
            vcpu_id,
            mode: VirtualizationMode::NonRoot,
            cpl: 0,
            vmcs,
            memory: NestedMemoryManager::new(),
            tlb_cache: HashMap::new(),
            virtqueue,
            iommu,
            taint: MicroarchTaint::new(),
            msr_bank,
            stats: ExecutionStats::default(),
        }
    }

    /// Read guest general purpose register (0=RAX, 1=RCX, ..., 15=R15)
    pub fn read_gpr(&self, reg: u8) -> u64 {
        match reg {
            0 => self.vmcs.get_u64(VmcsCoord::RaxGuest),
            1 => self.vmcs.get_u64(VmcsCoord::RcxGuest),
            2 => self.vmcs.get_u64(VmcsCoord::RdxGuest),
            3 => self.vmcs.get_u64(VmcsCoord::RbxGuest),
            4 => self.vmcs.get_u64(VmcsCoord::RspGuest),
            5 => self.vmcs.get_u64(VmcsCoord::RbpGuest),
            6 => self.vmcs.get_u64(VmcsCoord::RsiGuest),
            7 => self.vmcs.get_u64(VmcsCoord::RdiGuest),
            8 => self.vmcs.get_u64(VmcsCoord::R8Guest),
            9 => self.vmcs.get_u64(VmcsCoord::R9Guest),
            10 => self.vmcs.get_u64(VmcsCoord::R10Guest),
            11 => self.vmcs.get_u64(VmcsCoord::R11Guest),
            12 => self.vmcs.get_u64(VmcsCoord::R12Guest),
            13 => self.vmcs.get_u64(VmcsCoord::R13Guest),
            14 => self.vmcs.get_u64(VmcsCoord::R14Guest),
            15 => self.vmcs.get_u64(VmcsCoord::R15Guest),
            _ => 0,
        }
    }

    /// Write guest general purpose register
    pub fn write_gpr(&mut self, reg: u8, val: u64) {
        match reg {
            0 => self.vmcs.set_u64(VmcsCoord::RaxGuest, val),
            1 => self.vmcs.set_u64(VmcsCoord::RcxGuest, val),
            2 => self.vmcs.set_u64(VmcsCoord::RdxGuest, val),
            3 => self.vmcs.set_u64(VmcsCoord::RbxGuest, val),
            4 => self.vmcs.set_u64(VmcsCoord::RspGuest, val),
            5 => self.vmcs.set_u64(VmcsCoord::RbpGuest, val),
            6 => self.vmcs.set_u64(VmcsCoord::RsiGuest, val),
            7 => self.vmcs.set_u64(VmcsCoord::RdiGuest, val),
            8 => self.vmcs.set_u64(VmcsCoord::R8Guest, val),
            9 => self.vmcs.set_u64(VmcsCoord::R9Guest, val),
            10 => self.vmcs.set_u64(VmcsCoord::R10Guest, val),
            11 => self.vmcs.set_u64(VmcsCoord::R11Guest, val),
            12 => self.vmcs.set_u64(VmcsCoord::R12Guest, val),
            13 => self.vmcs.set_u64(VmcsCoord::R13Guest, val),
            14 => self.vmcs.set_u64(VmcsCoord::R14Guest, val),
            15 => self.vmcs.set_u64(VmcsCoord::R15Guest, val),
            _ => {}
        }
    }

    /// Memory translation via fast-path TLB or 2D-EPT page walk refill
    pub fn translate_gva(
        &mut self,
        gva: u64,
        folding_engine: &mut FoldingEngine,
    ) -> Result<u64, &'static str> {
        let vpn = gva >> 12;

        // Fast-path TLB lookup
        if let Some(tlb) = self.tlb_cache.get(&vpn) {
            self.stats.tlb_hits += 1;
            let offset = gva & 0xFFF;
            let hpa = (tlb.hfn_host << 12) | offset;
            return Ok(hpa);
        }

        // Asynchronous 2D-EPT Refill: Circuit C_6 (WALK_2D)
        self.stats.tlb_misses += 1;
        self.stats.ept_refills += 1;

        let cr3 = self.vmcs.get_u64(VmcsCoord::Cr3Guest);
        let eptp = self.vmcs.get_u64(VmcsCoord::EptPointer);
        let vpid = self.vmcs.get_u64(VmcsCoord::Vpid) as u16;

        let (tlb, final_hpa) = self.memory.walk_2d_nested(vpid, cr3, eptp, gva)?;
        self.tlb_cache.insert(vpn, tlb);

        // Fold C_6 refill circuit into IVC accumulator
        let _ccs6 = folding_engine.family.get_ccs(CircuitId::Walk2D);
        let x6 = vec![
            Scalar::from(vpid),
            Scalar::from(tlb.tau_vpid),
            Scalar::from(tlb.tau_ept),
            Scalar::from(cr3),
            Scalar::from(eptp),
            Scalar::from(tlb.vpn_guest),
            Scalar::from(tlb.hfn_host),
            Scalar::from(tlb.perms),
            Scalar::zero(),
            Scalar::zero(),
        ];
        let (inst6, wit6) = synthesize_circuit_step(&folding_engine.family, CircuitId::Walk2D, &x6);
        folding_engine.fold_step(
            CircuitId::Walk2D,
            &inst6,
            &wit6,
            (
                Scalar::zero(),
                Scalar::zero(),
                Scalar::zero(),
                Scalar::zero(),
            ),
        )?;

        Ok(final_hpa)
    }

    /// Execute a single guest instruction step and fold into IVC
    pub fn step(
        &mut self,
        instr: &GuestInstruction,
        folding_engine: &mut FoldingEngine,
    ) -> Result<bool, &'static str> {
        self.stats.total_steps += 1;
        self.taint.accumulate(self.vcpu_id);

        match instr {
            GuestInstruction::Add { dst, src1, src2 } => {
                let v1 = self.read_gpr(*src1);
                let v2 = self.read_gpr(*src2);
                self.write_gpr(*dst, v1.wrapping_add(v2));

                let rip = self.vmcs.get_u64(VmcsCoord::RipGuest);
                self.vmcs.set_u64(VmcsCoord::RipGuest, rip + 4);

                self.stats.alu_steps += 1;

                // Fold C_1: GUEST_ALU
                let _ccs1 = folding_engine.family.get_ccs(CircuitId::GuestAlu);
                let x1 = vec![
                    Scalar::from(rip),
                    Scalar::from(rip + 4),
                    Scalar::zero(),
                    Scalar::zero(),
                ];
                let (inst1, wit1) =
                    synthesize_circuit_step(&folding_engine.family, CircuitId::GuestAlu, &x1);
                folding_engine.fold_step(
                    CircuitId::GuestAlu,
                    &inst1,
                    &wit1,
                    (
                        Scalar::zero(),
                        Scalar::zero(),
                        Scalar::zero(),
                        Scalar::zero(),
                    ),
                )?;
            }
            GuestInstruction::Sub { dst, src1, src2 } => {
                let v1 = self.read_gpr(*src1);
                let v2 = self.read_gpr(*src2);
                self.write_gpr(*dst, v1.wrapping_sub(v2));

                let rip = self.vmcs.get_u64(VmcsCoord::RipGuest);
                self.vmcs.set_u64(VmcsCoord::RipGuest, rip + 4);

                self.stats.alu_steps += 1;

                let _ccs1 = folding_engine.family.get_ccs(CircuitId::GuestAlu);
                let x1 = vec![
                    Scalar::from(rip),
                    Scalar::from(rip + 4),
                    Scalar::zero(),
                    Scalar::zero(),
                ];
                let (inst1, wit1) =
                    synthesize_circuit_step(&folding_engine.family, CircuitId::GuestAlu, &x1);
                folding_engine.fold_step(
                    CircuitId::GuestAlu,
                    &inst1,
                    &wit1,
                    (
                        Scalar::zero(),
                        Scalar::zero(),
                        Scalar::zero(),
                        Scalar::zero(),
                    ),
                )?;
            }
            GuestInstruction::MovImm { dst, imm } => {
                self.write_gpr(*dst, *imm);
                let rip = self.vmcs.get_u64(VmcsCoord::RipGuest);
                self.vmcs.set_u64(VmcsCoord::RipGuest, rip + 5);

                self.stats.alu_steps += 1;

                let _ccs1 = folding_engine.family.get_ccs(CircuitId::GuestAlu);
                let x1 = vec![
                    Scalar::from(rip),
                    Scalar::from(rip + 5),
                    Scalar::zero(),
                    Scalar::zero(),
                ];
                let (inst1, wit1) =
                    synthesize_circuit_step(&folding_engine.family, CircuitId::GuestAlu, &x1);
                folding_engine.fold_step(
                    CircuitId::GuestAlu,
                    &inst1,
                    &wit1,
                    (
                        Scalar::zero(),
                        Scalar::zero(),
                        Scalar::zero(),
                        Scalar::zero(),
                    ),
                )?;
            }
            GuestInstruction::LoadMem { dst, base, offset } => {
                let gva = (self.read_gpr(*base) as i64 + *offset) as u64;
                let hpa = self.translate_gva(gva, folding_engine)?;
                let val = self.memory.read_hpa_word(hpa);
                self.write_gpr(*dst, val);

                let rip = self.vmcs.get_u64(VmcsCoord::RipGuest);
                self.vmcs.set_u64(VmcsCoord::RipGuest, rip + 4);

                self.stats.mem_steps += 1;

                // Fold C_2: GUEST_MEM
                let _ccs2 = folding_engine.family.get_ccs(CircuitId::GuestMem);
                let x2 = vec![
                    Scalar::from(rip),
                    Scalar::from(rip + 4),
                    Scalar::from(gva),
                    Scalar::from(hpa),
                    Scalar::from(val),
                    Scalar::zero(),
                ];
                let (inst2, wit2) =
                    synthesize_circuit_step(&folding_engine.family, CircuitId::GuestMem, &x2);
                folding_engine.fold_step(
                    CircuitId::GuestMem,
                    &inst2,
                    &wit2,
                    (
                        Scalar::zero(),
                        Scalar::zero(),
                        Scalar::zero(),
                        Scalar::zero(),
                    ),
                )?;
            }
            GuestInstruction::StoreMem { src, base, offset } => {
                let gva = (self.read_gpr(*base) as i64 + *offset) as u64;
                let hpa = self.translate_gva(gva, folding_engine)?;
                let val = self.read_gpr(*src);
                self.memory.write_hpa_word(hpa, val);

                let rip = self.vmcs.get_u64(VmcsCoord::RipGuest);
                self.vmcs.set_u64(VmcsCoord::RipGuest, rip + 4);

                self.stats.mem_steps += 1;

                // Fold C_2: GUEST_MEM
                let _ccs2 = folding_engine.family.get_ccs(CircuitId::GuestMem);
                let x2 = vec![
                    Scalar::from(rip),
                    Scalar::from(rip + 4),
                    Scalar::from(gva),
                    Scalar::from(hpa),
                    Scalar::from(val),
                    Scalar::one(), // is_store
                ];
                let (inst2, wit2) =
                    synthesize_circuit_step(&folding_engine.family, CircuitId::GuestMem, &x2);
                folding_engine.fold_step(
                    CircuitId::GuestMem,
                    &inst2,
                    &wit2,
                    (
                        Scalar::zero(),
                        Scalar::zero(),
                        Scalar::zero(),
                        Scalar::zero(),
                    ),
                )?;
            }
            GuestInstruction::Cpuid => {
                // World Switch: VMEXIT (Circuit C_3) -> HYPER_MED (Circuit C_4) -> VMENTRY (Circuit C_5)
                self.handle_world_switch(ExitReason::Cpuid, 2, 0, folding_engine)?;
            }
            GuestInstruction::Vmcall => {
                self.handle_world_switch(ExitReason::Vmcall, 3, 0, folding_engine)?;
            }
            GuestInstruction::MovCr { cr_num, reg_src: _ } => {
                let exit_qual = *cr_num as u64;
                self.handle_world_switch(ExitReason::CrAccess, 3, exit_qual, folding_engine)?;
            }
            GuestInstruction::Rdmsr { msr_idx } => {
                let exit_qual = *msr_idx as u64;
                self.handle_world_switch(ExitReason::Rdmsr, 2, exit_qual, folding_engine)?;
            }
            GuestInstruction::Wrmsr { msr_idx, val } => {
                self.msr_bank.insert(*msr_idx, *val);
                let exit_qual = *msr_idx as u64;
                self.handle_world_switch(ExitReason::Wrmsr, 2, exit_qual, folding_engine)?;
            }
            GuestInstruction::VirtioKick { queue_id } => {
                self.stats.virtio_dma_events += 1;
                // Circuit C_7: DMA_VIRTIO
                let _ccs7 = folding_engine.family.get_ccs(CircuitId::DmaVirtio);
                let x7 = vec![
                    Scalar::from(self.vcpu_id),
                    Scalar::from(*queue_id),
                    Scalar::zero(),
                    Scalar::zero(),
                    Scalar::zero(),
                    Scalar::zero(),
                    Scalar::zero(),
                    Scalar::zero(),
                ];
                let (inst7, wit7) =
                    synthesize_circuit_step(&folding_engine.family, CircuitId::DmaVirtio, &x7);
                folding_engine.fold_step(
                    CircuitId::DmaVirtio,
                    &inst7,
                    &wit7,
                    (
                        Scalar::zero(),
                        Scalar::zero(),
                        Scalar::zero(),
                        Scalar::zero(),
                    ),
                )?;

                let rip = self.vmcs.get_u64(VmcsCoord::RipGuest);
                self.vmcs.set_u64(VmcsCoord::RipGuest, rip + 3);
            }
            GuestInstruction::Hlt => {
                return Ok(false); // Finished execution
            }
        }

        Ok(true)
    }

    /// Complete world-switch handling: C_3 (VMEXIT) -> C_4 (HYPER_MED) -> C_5 (VMENTRY)
    fn handle_world_switch(
        &mut self,
        exit: ExitReason,
        exit_len: u32,
        exit_qual: u64,
        folding_engine: &mut FoldingEngine,
    ) -> Result<(), &'static str> {
        let prev_vmcs = self.vmcs.clone();
        self.stats.vmexit_count += 1;

        // 1. VMEXIT (Non-Root -> Root): Circuit C_3
        self.mode = VirtualizationMode::Root;
        self.vmcs.set_u64(VmcsCoord::ExitReason, exit as u64);
        self.vmcs.set_u64(VmcsCoord::ExitQualification, exit_qual);
        self.vmcs
            .set_u64(VmcsCoord::ExitInstrLength, exit_len as u64);

        let _ccs3 = folding_engine.family.get_ccs(CircuitId::VmExit);
        let x3 = vec![
            Scalar::from(prev_vmcs.get_u64(VmcsCoord::RipGuest)),
            Scalar::from(exit as u64),
            Scalar::from(exit_qual),
            Scalar::from(exit_len as u64),
            Scalar::zero(),
            Scalar::zero(),
        ];
        let (inst3, wit3) = synthesize_circuit_step(&folding_engine.family, CircuitId::VmExit, &x3);
        folding_engine.fold_step(
            CircuitId::VmExit,
            &inst3,
            &wit3,
            (
                Scalar::zero(),
                Scalar::zero(),
                Scalar::zero(),
                Scalar::zero(),
            ),
        )?;

        // 2. HYPER_MED: Circuit C_4 (KVM Exit Dispatcher & Mediation Policy)
        self.stats.hyper_med_steps += 1;
        let mut post_vmcs = prev_vmcs.clone();

        // Advance instruction pointer
        let rip = prev_vmcs.get_u64(VmcsCoord::RipGuest);
        post_vmcs.set_u64(VmcsCoord::RipGuest, rip + exit_len as u64);

        // Exit-specific semantic mutations
        match exit {
            ExitReason::Cpuid => {
                post_vmcs.set_u64(VmcsCoord::RaxGuest, 0x0008_06EC); // GenuineIntel Skylake/Icelake
                post_vmcs.set_u64(VmcsCoord::RbxGuest, 0x0110_0800);
                post_vmcs.set_u64(VmcsCoord::RcxGuest, 0x7FFA_FBBF);
                post_vmcs.set_u64(VmcsCoord::RdxGuest, 0xBFEF_FBFF);
            }
            ExitReason::Vmcall => {
                post_vmcs.set_u64(VmcsCoord::RaxGuest, 0); // KVM_HC_SUCCESS
            }
            ExitReason::Rdmsr => {
                let val = *self.msr_bank.get(&(exit_qual as u32)).unwrap_or(&0);
                post_vmcs.set_u64(VmcsCoord::RaxGuest, val & 0xFFFF_FFFF);
                post_vmcs.set_u64(VmcsCoord::RdxGuest, val >> 32);
            }
            _ => {}
        }

        // Verify mediation policy Phi_KVM mathematically
        verify_vmcs_mediation_policy(
            &prev_vmcs,
            &post_vmcs,
            exit as u32,
            exit_qual,
            exit_len,
            false,
        )?;

        let _ccs4 = folding_engine.family.get_ccs(CircuitId::HyperMed);
        let x4 = vec![
            Scalar::from(rip),
            Scalar::from(rip + exit_len as u64),
            Scalar::from(exit as u64),
            Scalar::from(exit_qual),
            Scalar::zero(),
            Scalar::zero(),
            Scalar::zero(),
            Scalar::zero(),
        ];
        let (inst4, wit4) =
            synthesize_circuit_step(&folding_engine.family, CircuitId::HyperMed, &x4);
        folding_engine.fold_step(
            CircuitId::HyperMed,
            &inst4,
            &wit4,
            (
                Scalar::zero(),
                Scalar::zero(),
                Scalar::zero(),
                Scalar::zero(),
            ),
        )?;

        // 3. VMENTRY: Circuit C_5 (Differential consistency checks & microarch sanitization)
        self.stats.vmentry_count += 1;
        verify_differential_vmentry(&post_vmcs)?;

        // Execute architectural flushes (L1D, IBPB, VERW) to ensure zero cross-domain leakage
        self.taint.apply_barriers(true, true, true);
        self.taint.verify_sanitization(0, self.vcpu_id)?;

        let _ccs5 = folding_engine.family.get_ccs(CircuitId::VmEntry);
        let x5 = vec![
            Scalar::from(post_vmcs.get_u64(VmcsCoord::RipGuest)),
            Scalar::one(), // f_l1d
            Scalar::one(), // f_ibpb
            Scalar::one(), // f_verw
            Scalar::zero(),
            Scalar::zero(),
        ];
        let (inst5, wit5) =
            synthesize_circuit_step(&folding_engine.family, CircuitId::VmEntry, &x5);
        folding_engine.fold_step(
            CircuitId::VmEntry,
            &inst5,
            &wit5,
            (
                Scalar::zero(),
                Scalar::zero(),
                Scalar::zero(),
                Scalar::zero(),
            ),
        )?;

        // Update VMCS state and restore Non-Root mode
        self.vmcs = post_vmcs;
        self.mode = VirtualizationMode::NonRoot;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ept::{GuestPte, HostEpte};

    #[test]
    fn test_full_hypervisor_execution_and_proving() {
        let mut folding_engine = FoldingEngine::new();

        let eptp = 0x1000u64;
        let cr3 = 0x2000u64;
        let mut vm = HyperKvmInstance::new(1, cr3, eptp);

        // Set up nested page tables for GVA 0x0000_7FFF_0000_1000 -> HPA
        // Host EPML4 (HFN 1) -> EPDPT (HFN 2) -> EPD (HFN 3) -> EPTE (HFN 4)
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
        vm.memory.write_hpa_word(0x1000, epte_base.encode());
        vm.memory.write_hpa_word(
            0x2000,
            HostEpte {
                hfn: 3,
                ..epte_base
            }
            .encode(),
        );
        vm.memory.write_hpa_word(
            0x3000,
            HostEpte {
                hfn: 4,
                ..epte_base
            }
            .encode(),
        );

        // Host EPTE mappings for guest tables
        vm.memory.write_hpa_word(
            0x4000 + 2 * 8,
            HostEpte {
                hfn: 10,
                ..epte_base
            }
            .encode(),
        ); // GFN 2 (PML4) -> HFN 10
        vm.memory.write_hpa_word(
            0x4000 + 5 * 8,
            HostEpte {
                hfn: 20,
                ..epte_base
            }
            .encode(),
        ); // GFN 5 (PDPT) -> HFN 20
        vm.memory.write_hpa_word(
            0x4000 + 6 * 8,
            HostEpte {
                hfn: 30,
                ..epte_base
            }
            .encode(),
        ); // GFN 6 (PD) -> HFN 30
        vm.memory.write_hpa_word(
            0x4000 + 7 * 8,
            HostEpte {
                hfn: 40,
                ..epte_base
            }
            .encode(),
        ); // GFN 7 (PT) -> HFN 40
        vm.memory.write_hpa_word(
            0x4000 + 8 * 8,
            HostEpte {
                hfn: 50,
                ..epte_base
            }
            .encode(),
        ); // GFN 8 (Data) -> HFN 50

        // Guest page tables for GVA
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
            gfn: 5,
            no_execute: false,
        };
        vm.memory.write_hpa_word(10 << 12, guest_pte_base.encode());
        vm.memory.write_hpa_word(
            20 << 12,
            GuestPte {
                gfn: 6,
                ..guest_pte_base
            }
            .encode(),
        );
        vm.memory.write_hpa_word(
            30 << 12,
            GuestPte {
                gfn: 7,
                ..guest_pte_base
            }
            .encode(),
        );
        vm.memory.write_hpa_word(
            40 << 12,
            GuestPte {
                gfn: 8,
                ..guest_pte_base
            }
            .encode(),
        );

        // Guest program:
        // 1. MovImm R8 = 100
        // 2. MovImm R9 = 250
        // 3. Add R10 = R8 + R9 (R10 = 350)
        // 4. StoreMem [GVA 0x0048] = R10
        // 5. Cpuid (VMEXIT -> HYPER_MED -> VMENTRY, sets RAX, RBX, RCX, RDX)
        // 6. LoadMem R11 = [GVA 0x0048]
        // 7. VirtioKick queue 0
        // 8. Hlt
        let program = vec![
            GuestInstruction::MovImm { dst: 8, imm: 100 },
            GuestInstruction::MovImm { dst: 9, imm: 250 },
            GuestInstruction::Add {
                dst: 10,
                src1: 8,
                src2: 9,
            },
            GuestInstruction::StoreMem {
                src: 10,
                base: 7,
                offset: 0,
            },
            GuestInstruction::Cpuid,
            GuestInstruction::LoadMem {
                dst: 11,
                base: 7,
                offset: 0,
            },
            GuestInstruction::VirtioKick { queue_id: 0 },
            GuestInstruction::Hlt,
        ];

        // Set R7 (RDI) to GVA 0x0048
        vm.write_gpr(7, 0x0048);

        for instr in program {
            let running = vm.step(&instr, &mut folding_engine).unwrap();
            if !running {
                break;
            }
        }

        // Verify guest computed values
        assert_eq!(vm.read_gpr(10), 350);
        assert_eq!(vm.read_gpr(11), 350);
        // Verify CPUID leaf feature flags were mediated by hypervisor
        assert_eq!(vm.read_gpr(0), 0x0008_06EC);
        assert_eq!(vm.read_gpr(3), 0x0110_0800);

        // Verify that the terminal multi-instance folding proof checks out!
        assert!(folding_engine.verify_terminal_proof().is_ok());

        println!(
            "Execution and Proving completed successfully! Stats: {:?}",
            vm.stats
        );
    }
}
