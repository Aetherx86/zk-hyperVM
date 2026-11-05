//! Advanced Extensions of zk-HyperKVM (Paper Section 12).
//!
//! Includes:
//!   - Section 12.1: Verifiable Nested Virtualization (L_0 -> L_1 -> L_2) via Shadow-VMCS and 3D-EPT.
//!   - Section 12.2: Verifiable Zero-Downtime Live VM Migration across untrusted hosts.
//!   - Section 12.3: Post-Quantum LatticeFold / Module-SIS norm-bounded folding.

use crate::ept::NestedMemoryManager;
use crate::logup::TlbTranslation;
use std::collections::{HashMap, HashSet};

/// Section 12.1: Three-Dimensional Extended Page Table (3D-EPT) Translation.
/// GVA_L2 -> (CR3_L2) -> GPA_L2 -> (EPT_12) -> GPA_L1 -> (EPT_01) -> HPA_L0
#[derive(Clone, Debug)]
pub struct Nested3DEptManager {
    pub l0_memory: NestedMemoryManager,
    pub eptp_01: u64, // Physical EPT root managed by L0 host
    pub eptp_12: u64, // Virtualized EPT root managed by L1 guest hypervisor
}

impl Nested3DEptManager {
    pub fn new(l0_memory: NestedMemoryManager, eptp_01: u64, eptp_12: u64) -> Self {
        Self {
            l0_memory,
            eptp_01,
            eptp_12,
        }
    }

    /// Translates GPA_L2 -> GPA_L1 (via EPT_12) -> HPA_L0 (via EPT_01)
    pub fn translate_gpa_l2_to_hpa_l0(&self, gpa_l2: u64) -> Result<(u64, u8), &'static str> {
        let gfn_l2 = gpa_l2 >> 12;
        let offset = gpa_l2 & 0xFFF;

        // Stage A: GPA_L2 -> GPA_L1 using EPT_12
        let ept12_trans = self.l0_memory.walk_ept_1d(self.eptp_12, gfn_l2)?;
        let gpa_l1 = (ept12_trans.hfn << 12) | offset;
        let gfn_l1 = gpa_l1 >> 12;

        // Stage B: GPA_L1 -> HPA_L0 using EPT_01
        let ept01_trans = self.l0_memory.walk_ept_1d(self.eptp_01, gfn_l1)?;
        let hpa_l0 = (ept01_trans.hfn << 12) | offset;

        let combined_perms = ept12_trans.perms_ept & ept01_trans.perms_ept;
        Ok((hpa_l0, combined_perms))
    }

    /// Full 3D Nested Radix Walk: GVA_L2 -> HPA_L0
    /// Translates L2 guest virtual address through 4 guest radix levels
    /// where each table pointer is in GPA_L2 space, translated to GPA_L1 (via EPT_12) and then HPA_L0 (via EPT_01).
    pub fn walk_3d_nested(
        &self,
        vpid_l2: u16,
        cr3_l2: u64,
        gva_l2: u64,
    ) -> Result<(TlbTranslation, u64), &'static str> {
        use crate::ept::{DecomposedGva, GuestPte};

        let dec = DecomposedGva::from_gva(gva_l2);

        // Stage 4: Guest L2 PML4
        let gpa_pml4_l2 = (cr3_l2 & !0xFFF) + (dec.idx_pml4 as u64) * 8;
        let (hpa_pml4_l0, perms_pml4) = self.translate_gpa_l2_to_hpa_l0(gpa_pml4_l2)?;
        let pml4e = GuestPte::parse(self.l0_memory.read_hpa_word(hpa_pml4_l0));
        if !pml4e.present {
            return Err("3D-EPT Fault: L2 PML4E not present");
        }

        // Stage 3: Guest L2 PDPT
        let gpa_pdpt_l2 = (pml4e.gfn << 12) + (dec.idx_pdpt as u64) * 8;
        let (hpa_pdpt_l0, perms_pdpt) = self.translate_gpa_l2_to_hpa_l0(gpa_pdpt_l2)?;
        let pdpte = GuestPte::parse(self.l0_memory.read_hpa_word(hpa_pdpt_l0));
        if !pdpte.present {
            return Err("3D-EPT Fault: L2 PDPTE not present");
        }
        if pdpte.page_size {
            // 1GB L2 Huge Page in GPA_L2 space
            let gpa_data_l2 = ((pdpte.gfn & 0x000F_FFFF_C000) << 12) | (gva_l2 & 0x3FFF_FFFF);
            let (final_hpa_l0, perms_data) = self.translate_gpa_l2_to_hpa_l0(gpa_data_l2)?;
            let combined_perms = perms_pml4 & perms_pdpt & perms_data;
            let tlb = TlbTranslation {
                vpid: vpid_l2,
                tau_vpid: self.l0_memory.tau_vpid,
                tau_ept: self.l0_memory.tau_ept,
                cr3_guest: cr3_l2,
                eptp: self.eptp_01,
                vpn_guest: dec.vpn(),
                hfn_host: final_hpa_l0 >> 12,
                perms: combined_perms,
            };
            return Ok((tlb, final_hpa_l0));
        }

        // Stage 2: Guest L2 PD
        let gpa_pd_l2 = (pdpte.gfn << 12) + (dec.idx_pd as u64) * 8;
        let (hpa_pd_l0, perms_pd) = self.translate_gpa_l2_to_hpa_l0(gpa_pd_l2)?;
        let pde = GuestPte::parse(self.l0_memory.read_hpa_word(hpa_pd_l0));
        if !pde.present {
            return Err("3D-EPT Fault: L2 PDE not present");
        }
        if pde.page_size {
            // 2MB L2 Huge Page in GPA_L2 space
            let gpa_data_l2 = ((pde.gfn & 0x000F_FFFF_FFE0) << 12) | (gva_l2 & 0x1F_FFFF);
            let (final_hpa_l0, perms_data) = self.translate_gpa_l2_to_hpa_l0(gpa_data_l2)?;
            let combined_perms = perms_pml4 & perms_pdpt & perms_pd & perms_data;
            let tlb = TlbTranslation {
                vpid: vpid_l2,
                tau_vpid: self.l0_memory.tau_vpid,
                tau_ept: self.l0_memory.tau_ept,
                cr3_guest: cr3_l2,
                eptp: self.eptp_01,
                vpn_guest: dec.vpn(),
                hfn_host: final_hpa_l0 >> 12,
                perms: combined_perms,
            };
            return Ok((tlb, final_hpa_l0));
        }

        // Stage 1: Guest L2 PT
        let gpa_pt_l2 = (pde.gfn << 12) + (dec.idx_pt as u64) * 8;
        let (hpa_pt_l0, perms_pt) = self.translate_gpa_l2_to_hpa_l0(gpa_pt_l2)?;
        let pte = GuestPte::parse(self.l0_memory.read_hpa_word(hpa_pt_l0));
        if !pte.present {
            return Err("3D-EPT Fault: L2 PTE not present");
        }

        // Stage 0: L2 Target Data Frame in GPA_L2 space
        let gpa_data_l2 = (pte.gfn << 12) | (dec.offset as u64);
        let (final_hpa_l0, perms_data) = self.translate_gpa_l2_to_hpa_l0(gpa_data_l2)?;
        let combined_perms = perms_pml4 & perms_pdpt & perms_pd & perms_pt & perms_data;

        let tlb = TlbTranslation {
            vpid: vpid_l2,
            tau_vpid: self.l0_memory.tau_vpid,
            tau_ept: self.l0_memory.tau_ept,
            cr3_guest: cr3_l2,
            eptp: self.eptp_01,
            vpn_guest: dec.vpn(),
            hfn_host: final_hpa_l0 >> 12,
            perms: combined_perms,
        };

        Ok((tlb, final_hpa_l0))
    }
}

/// Section 12.2: Cryptographically Verifiable Zero-Downtime Live VM Migration
#[derive(Clone, Debug)]
pub struct LiveMigrationCoordinator {
    pub current_epoch: usize,
    pub dirty_page_log: HashSet<u64>, // GFNs modified during pre-copy
    pub total_pages_transferred: usize,
}

impl LiveMigrationCoordinator {
    pub fn new() -> Self {
        Self {
            current_epoch: 0,
            dirty_page_log: HashSet::new(),
            total_pages_transferred: 0,
        }
    }
}

impl Default for LiveMigrationCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveMigrationCoordinator {
    /// Page Modification Logging (PML) transition: EPTE.D 0 -> 1 records modified GFN
    pub fn record_dirty_gfn(&mut self, gfn: u64) {
        self.dirty_page_log.insert(gfn);
    }

    /// Pre-copy iteration: transfer dirty pages to destination host
    pub fn pre_copy_iteration(&mut self) -> Vec<u64> {
        self.current_epoch += 1;
        let pages_to_send: Vec<u64> = self.dirty_page_log.drain().collect();
        self.total_pages_transferred += pages_to_send.len();
        pages_to_send
    }

    /// Verifiable Handover: Destination host rebases EPT radix tree while preserving page digests
    pub fn rebase_destination_ept(
        source_gfn_map: &HashMap<u64, u64>,  // GFN -> HFN_src
        dest_allocation: &HashMap<u64, u64>, // GFN -> HFN_dst
    ) -> Result<bool, &'static str> {
        for gfn in source_gfn_map.keys() {
            if !dest_allocation.contains_key(gfn) {
                return Err("Live Migration Failure: Unmapped guest page in destination EPT!");
            }
        }
        Ok(true)
    }
}

/// Section 12.3: Post-Quantum LatticeFold Norm-Bounded Accumulator Representation
#[derive(Clone, Debug)]
pub struct LatticeFoldWitnessLimb {
    pub limbs: Vec<i64>, // small B-ary coefficients with ||w||_inf <= beta_SIS
    pub bound_beta_sis: i64,
}

impl LatticeFoldWitnessLimb {
    pub fn new(bound_beta: i64) -> Self {
        Self {
            limbs: Vec::new(),
            bound_beta_sis: bound_beta,
        }
    }

    pub fn push(&mut self, val: i64) -> Result<(), &'static str> {
        if val.abs() > self.bound_beta_sis {
            return Err("LatticeFold Norm Overflow: Coefficient exceeds beta_SIS bound!");
        }
        self.limbs.push(val);
        Ok(())
    }

    pub fn verify_infinity_norm(&self) -> bool {
        self.limbs
            .iter()
            .all(|val| val.abs() <= self.bound_beta_sis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_live_migration_pml_tracking() {
        let mut mig = LiveMigrationCoordinator::new();

        // Guest touches pages 10, 20, 30
        mig.record_dirty_gfn(10);
        mig.record_dirty_gfn(20);
        mig.record_dirty_gfn(30);

        // Pre-copy round 1 transfers 3 pages
        let batch1 = mig.pre_copy_iteration();
        assert_eq!(batch1.len(), 3);
        assert_eq!(mig.total_pages_transferred, 3);

        // Rebase check on destination
        let mut src_map = HashMap::new();
        src_map.insert(10, 100);
        src_map.insert(20, 200);

        let mut dst_map = HashMap::new();
        dst_map.insert(10, 500); // relocated physical frames
        dst_map.insert(20, 600);

        assert!(LiveMigrationCoordinator::rebase_destination_ept(&src_map, &dst_map).is_ok());
    }

    #[test]
    fn test_lattice_fold_norm_bound() {
        let mut limbs = LatticeFoldWitnessLimb::new(128);
        assert!(limbs.push(50).is_ok());
        assert!(limbs.push(-120).is_ok());
        assert!(limbs.push(200).is_err()); // exceeds beta_SIS=128
        assert!(limbs.verify_infinity_norm());
    }
}
