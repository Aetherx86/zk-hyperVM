//! Two-Dimensional Extended Page Tables (2D-EPT) and 2D-EPT-LogUp.
//!
//! Models the nested 4-level guest radix walk nested inside 4-level host EPT walk
//! (up to 24 physical memory lookups per uncached guest access),
//! 64-bit PTE/EPTE bitfield decoders, huge pages (2MB, 1GB),
//! and the degree-3 combined permission lattice.

use crate::logup::{EptTranslation, TlbTranslation};
use std::collections::HashMap;

/// Page Frame ownership tag in physical memory
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryOwner {
    HostPrivileged,
    EptTree(u32),        // EPT structures for vCPU v
    GuestExclusive(u32), // Guest confidential physical memory for vCPU v
    VirtioShared(u32),   // Paravirtualized DMA buffer for vCPU v
}

/// 64-bit x86-64 Guest Page Table Entry (PTE_G)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestPte {
    pub raw: u64,
    pub present: bool,
    pub read_write: bool,
    pub user_supervisor: bool,
    pub page_write_through: bool,
    pub page_cache_disable: bool,
    pub accessed: bool,
    pub dirty: bool,
    pub page_size: bool, // 1 = 2MB or 1GB huge page
    pub global: bool,
    pub gfn: u64, // 40-bit guest frame number (bits 51:12)
    pub no_execute: bool,
}

impl GuestPte {
    pub fn parse(raw: u64) -> Self {
        Self {
            raw,
            present: (raw & 1) != 0,
            read_write: ((raw >> 1) & 1) != 0,
            user_supervisor: ((raw >> 2) & 1) != 0,
            page_write_through: ((raw >> 3) & 1) != 0,
            page_cache_disable: ((raw >> 4) & 1) != 0,
            accessed: ((raw >> 5) & 1) != 0,
            dirty: ((raw >> 6) & 1) != 0,
            page_size: ((raw >> 7) & 1) != 0,
            global: ((raw >> 8) & 1) != 0,
            gfn: (raw >> 12) & 0x000F_FFFF_FFFF, // 40 bits
            no_execute: ((raw >> 63) & 1) != 0,
        }
    }

    pub fn encode(&self) -> u64 {
        let mut raw = 0u64;
        if self.present { raw |= 1; }
        if self.read_write { raw |= 1 << 1; }
        if self.user_supervisor { raw |= 1 << 2; }
        if self.page_write_through { raw |= 1 << 3; }
        if self.page_cache_disable { raw |= 1 << 4; }
        if self.accessed { raw |= 1 << 5; }
        if self.dirty { raw |= 1 << 6; }
        if self.page_size { raw |= 1 << 7; }
        if self.global { raw |= 1 << 8; }
        raw |= (self.gfn & 0x000F_FFFF_FFFF) << 12;
        if self.no_execute { raw |= 1 << 63; }
        raw
    }
}

/// 64-bit Intel VT-x Extended Page Table Entry (EPTE)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostEpte {
    pub raw: u64,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub mem_type: u8,
    pub ignore_pat: bool,
    pub page_size: bool,
    pub accessed: bool,
    pub dirty: bool,
    pub execute_user: bool,
    pub hfn: u64, // 40-bit host frame number (bits 51:12)
    pub suppress_ve: bool,
}

impl HostEpte {
    pub fn parse(raw: u64) -> Self {
        Self {
            raw,
            read: (raw & 1) != 0,
            write: ((raw >> 1) & 1) != 0,
            execute: ((raw >> 2) & 1) != 0,
            mem_type: ((raw >> 3) & 7) as u8,
            ignore_pat: ((raw >> 6) & 1) != 0,
            page_size: ((raw >> 7) & 1) != 0,
            accessed: ((raw >> 8) & 1) != 0,
            dirty: ((raw >> 9) & 1) != 0,
            execute_user: ((raw >> 10) & 1) != 0,
            hfn: (raw >> 12) & 0x000F_FFFF_FFFF,
            suppress_ve: ((raw >> 63) & 1) != 0,
        }
    }

    pub fn encode(&self) -> u64 {
        let mut raw = 0u64;
        if self.read { raw |= 1; }
        if self.write { raw |= 1 << 1; }
        if self.execute { raw |= 1 << 2; }
        raw |= ((self.mem_type & 7) as u64) << 3;
        if self.ignore_pat { raw |= 1 << 6; }
        if self.page_size { raw |= 1 << 7; }
        if self.accessed { raw |= 1 << 8; }
        if self.dirty { raw |= 1 << 9; }
        if self.execute_user { raw |= 1 << 10; }
        raw |= (self.hfn & 0x000F_FFFF_FFFF) << 12;
        if self.suppress_ve { raw |= 1 << 63; }
        raw
    }

    pub fn perms_byte(&self) -> u8 {
        (self.read as u8) | ((self.write as u8) << 1) | ((self.execute as u8) << 2)
    }
}

/// Decomposed 48-bit Guest Virtual Address (GVA)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecomposedGva {
    pub idx_pml4: usize, // bits 47:39
    pub idx_pdpt: usize, // bits 38:30
    pub idx_pd: usize,   // bits 29:21
    pub idx_pt: usize,   // bits 20:12
    pub offset: usize,   // bits 11:0
}

impl DecomposedGva {
    pub fn from_gva(gva: u64) -> Self {
        Self {
            idx_pml4: ((gva >> 39) & 0x1FF) as usize,
            idx_pdpt: ((gva >> 30) & 0x1FF) as usize,
            idx_pd: ((gva >> 21) & 0x1FF) as usize,
            idx_pt: ((gva >> 12) & 0x1FF) as usize,
            offset: (gva & 0xFFF) as usize,
        }
    }

    pub fn vpn(&self) -> u64 {
        ((self.idx_pml4 as u64) << 27)
            | ((self.idx_pdpt as u64) << 18)
            | ((self.idx_pd as u64) << 9)
            | (self.idx_pt as u64)
    }
}

/// Decomposed 48-bit Guest Physical Address (GPA) for host EPT
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecomposedGpa {
    pub idx_epml4: usize,
    pub idx_epdpt: usize,
    pub idx_epd: usize,
    pub idx_ept: usize,
    pub offset: usize,
}

impl DecomposedGpa {
    pub fn from_gpa(gpa: u64) -> Self {
        Self {
            idx_epml4: ((gpa >> 39) & 0x1FF) as usize,
            idx_epdpt: ((gpa >> 30) & 0x1FF) as usize,
            idx_epd: ((gpa >> 21) & 0x1FF) as usize,
            idx_ept: ((gpa >> 12) & 0x1FF) as usize,
            offset: (gpa & 0xFFF) as usize,
        }
    }
}

/// Physical memory manager supporting 2D nested radix tree translation
#[derive(Clone, Debug)]
pub struct NestedMemoryManager {
    // Sparse physical memory words: HPA -> 64-bit value
    pub memory: HashMap<u64, u64>,
    // Page frame ownership tags: HFN -> MemoryOwner
    pub ownership: HashMap<u64, MemoryOwner>,
    pub tau_vpid: u64,
    pub tau_ept: u64,
}

impl NestedMemoryManager {
    pub fn new() -> Self {
        Self {
            memory: HashMap::new(),
            ownership: HashMap::new(),
            tau_vpid: 1,
            tau_ept: 1,
        }
    }

    pub fn read_hpa_word(&self, hpa: u64) -> u64 {
        assert_eq!(hpa % 8, 0, "Unaligned HPA read");
        *self.memory.get(&hpa).unwrap_or(&0)
    }

    pub fn write_hpa_word(&mut self, hpa: u64, val: u64) {
        assert_eq!(hpa % 8, 0, "Unaligned HPA write");
        let hfn = hpa >> 12;
        let owner = self.ownership.get(&hfn).copied().unwrap_or(MemoryOwner::HostPrivileged);
        if let MemoryOwner::EptTree(_) = owner {
            self.tau_ept += 1;
        }
        self.memory.insert(hpa, val);
    }

    /// Single 1D Host EPT Radix Walk (GPA -> HPA frame)
    pub fn walk_ept_1d(&self, eptp: u64, gfn: u64) -> Result<EptTranslation, &'static str> {
        let gpa = gfn << 12;
        let dec = DecomposedGpa::from_gpa(gpa);

        // Level 4: EPML4
        let epml4_base_hfn = eptp >> 12;
        let epml4e_hpa = (epml4_base_hfn << 12) + (dec.idx_epml4 as u64) * 8;
        let epml4e = HostEpte::parse(self.read_hpa_word(epml4e_hpa));
        if !epml4e.read && !epml4e.write && !epml4e.execute {
            return Err("EPT Violation at EPML4 (Non-Present)");
        }

        // Level 3: EPDPT
        let epdpt_hpa = (epml4e.hfn << 12) + (dec.idx_epdpt as u64) * 8;
        let epdpte = HostEpte::parse(self.read_hpa_word(epdpt_hpa));
        if !epdpte.read && !epdpte.write && !epdpte.execute {
            return Err("EPT Violation at EPDPT (Non-Present)");
        }
        if epdpte.page_size {
            // 1GB Host Huge Page
            let final_hfn = (epdpte.hfn & 0x000F_FFFF_C000)
                | ((dec.idx_epd as u64) << 9)
                | (dec.idx_ept as u64);
            let perms = epml4e.perms_byte() & epdpte.perms_byte();
            return Ok(EptTranslation {
                tau_ept: self.tau_ept,
                eptp,
                gfn,
                hfn: final_hfn,
                perms_ept: perms,
            });
        }

        // Level 2: EPD
        let epd_hpa = (epdpte.hfn << 12) + (dec.idx_epd as u64) * 8;
        let epde = HostEpte::parse(self.read_hpa_word(epd_hpa));
        if !epde.read && !epde.write && !epde.execute {
            return Err("EPT Violation at EPD (Non-Present)");
        }
        if epde.page_size {
            // 2MB Host Huge Page
            let final_hfn = (epde.hfn & 0x000F_FFFF_FFE0) | (dec.idx_ept as u64);
            let perms = epml4e.perms_byte() & epdpte.perms_byte() & epde.perms_byte();
            return Ok(EptTranslation {
                tau_ept: self.tau_ept,
                eptp,
                gfn,
                hfn: final_hfn,
                perms_ept: perms,
            });
        }

        // Level 1: EPTE
        let epte_hpa = (epde.hfn << 12) + (dec.idx_ept as u64) * 8;
        let epte = HostEpte::parse(self.read_hpa_word(epte_hpa));
        if !epte.read && !epte.write && !epte.execute {
            return Err("EPT Violation at EPTE (Non-Present)");
        }

        let perms = epml4e.perms_byte() & epdpte.perms_byte() & epde.perms_byte() & epte.perms_byte();
        Ok(EptTranslation {
            tau_ept: self.tau_ept,
            eptp,
            gfn,
            hfn: epte.hfn,
            perms_ept: perms,
        })
    }

    /// Complete 2D Nested Translation Walk: GVA -> HPA
    /// Performs 4 guest radix levels, where each guest table pointer is a GPA translated via EPT!
    pub fn walk_2d_nested(
        &self,
        vpid: u16,
        cr3_guest: u64,
        eptp: u64,
        gva: u64,
    ) -> Result<(TlbTranslation, u64), &'static str> {
        let dec = DecomposedGva::from_gva(gva);

        // Stage 4: Guest PML4
        let gfn_pml4 = cr3_guest >> 12;
        let ept_pml4 = self.walk_ept_1d(eptp, gfn_pml4)?;
        let pml4e_hpa = (ept_pml4.hfn << 12) + (dec.idx_pml4 as u64) * 8;
        let pml4e = GuestPte::parse(self.read_hpa_word(pml4e_hpa));
        if !pml4e.present {
            return Err("Guest Page Fault: PML4E not present");
        }

        // Stage 3: Guest PDPT
        let ept_pdpt = self.walk_ept_1d(eptp, pml4e.gfn)?;
        let pdpte_hpa = (ept_pdpt.hfn << 12) + (dec.idx_pdpt as u64) * 8;
        let pdpte = GuestPte::parse(self.read_hpa_word(pdpte_hpa));
        if !pdpte.present {
            return Err("Guest Page Fault: PDPTE not present");
        }
        if pdpte.page_size {
            // 1GB Huge Page in Guest
            let guest_target_gfn = (pdpte.gfn & 0x000F_FFFF_C000)
                | ((dec.idx_pd as u64) << 9)
                | (dec.idx_pt as u64);
            let ept_data = self.walk_ept_1d(eptp, guest_target_gfn)?;
            let final_hpa = (ept_data.hfn << 12) + (dec.offset as u64);

            let perms = Self::compute_combined_perms(&[pml4e, pdpte], &[ept_pml4, ept_pdpt, ept_data]);
            let tlb = TlbTranslation {
                vpid,
                tau_vpid: self.tau_vpid,
                tau_ept: self.tau_ept,
                cr3_guest,
                eptp,
                vpn_guest: dec.vpn(),
                hfn_host: ept_data.hfn,
                perms,
            };
            return Ok((tlb, final_hpa));
        }

        // Stage 2: Guest PD
        let ept_pd = self.walk_ept_1d(eptp, pdpte.gfn)?;
        let pde_hpa = (ept_pd.hfn << 12) + (dec.idx_pd as u64) * 8;
        let pde = GuestPte::parse(self.read_hpa_word(pde_hpa));
        if !pde.present {
            return Err("Guest Page Fault: PDE not present");
        }
        if pde.page_size {
            // 2MB Huge Page in Guest
            let guest_target_gfn = (pde.gfn & 0x000F_FFFF_FFE0) | (dec.idx_pt as u64);
            let ept_data = self.walk_ept_1d(eptp, guest_target_gfn)?;
            let final_hpa = (ept_data.hfn << 12) + (dec.offset as u64);

            let perms = Self::compute_combined_perms(&[pml4e, pdpte, pde], &[ept_pml4, ept_pdpt, ept_pd, ept_data]);
            let tlb = TlbTranslation {
                vpid,
                tau_vpid: self.tau_vpid,
                tau_ept: self.tau_ept,
                cr3_guest,
                eptp,
                vpn_guest: dec.vpn(),
                hfn_host: ept_data.hfn,
                perms,
            };
            return Ok((tlb, final_hpa));
        }

        // Stage 1: Guest PT
        let ept_pt = self.walk_ept_1d(eptp, pde.gfn)?;
        let pte_hpa = (ept_pt.hfn << 12) + (dec.idx_pt as u64) * 8;
        let pte = GuestPte::parse(self.read_hpa_word(pte_hpa));
        if !pte.present {
            return Err("Guest Page Fault: PTE not present");
        }

        // Stage 0: Guest Target Data Frame
        let ept_data = self.walk_ept_1d(eptp, pte.gfn)?;
        let final_hpa = (ept_data.hfn << 12) + (dec.offset as u64);

        let perms = Self::compute_combined_perms(
            &[pml4e, pdpte, pde, pte],
            &[ept_pml4, ept_pdpt, ept_pd, ept_pt, ept_data],
        );

        let tlb = TlbTranslation {
            vpid,
            tau_vpid: self.tau_vpid,
            tau_ept: self.tau_ept,
            cr3_guest,
            eptp,
            vpn_guest: dec.vpn(),
            hfn_host: ept_data.hfn,
            perms,
        };

        Ok((tlb, final_hpa))
    }

    /// Degree-3 Combined Permission Lattice:
    /// Read, Write, Execute, User permissions
    fn compute_combined_perms(guest_ptes: &[GuestPte], ept_steps: &[EptTranslation]) -> u8 {
        let mut guest_r = true;
        let mut guest_w = true;
        let mut guest_u = true;
        let mut guest_x = true;

        for pte in guest_ptes {
            guest_r &= pte.present;
            guest_w &= pte.read_write;
            guest_u &= pte.user_supervisor;
            guest_x &= !pte.no_execute;
        }

        let mut ept_r = true;
        let mut ept_w = true;
        let mut ept_x = true;

        for step in ept_steps {
            ept_r &= (step.perms_ept & 1) != 0;
            ept_w &= (step.perms_ept & 2) != 0;
            ept_x &= (step.perms_ept & 4) != 0;
        }

        let combined_r = guest_r && ept_r;
        let combined_w = combined_r && guest_w && ept_w;
        let combined_x = combined_r && guest_x && ept_x;

        (combined_r as u8)
            | ((combined_w as u8) << 1)
            | ((combined_x as u8) << 2)
            | ((guest_u as u8) << 3)
    }
}

impl Default for NestedMemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_2d_nested_page_walk() {
        let mut mm = NestedMemoryManager::new();

        let eptp = 0x0000_1000u64; // HFN = 1
        let cr3_guest = 0x0000_2000u64; // GFN = 2

        // Set up host EPT mapping for GFN 2 (Guest PML4 base) -> HFN 10
        // Host EPML4 at HFN 1: entry 0 points to EPDPT at HFN 2
        let epml4e = HostEpte {
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
        mm.write_hpa_word(0x1000, epml4e.encode());

        // Host EPDPT at HFN 2: entry 0 points to EPD at HFN 3
        let epdpte = HostEpte { hfn: 3, ..epml4e };
        mm.write_hpa_word(0x2000, epdpte.encode());

        // Host EPD at HFN 3: entry 0 points to EPTE table at HFN 4
        let epde = HostEpte { hfn: 4, ..epml4e };
        mm.write_hpa_word(0x3000, epde.encode());

        // Host EPTE table at HFN 4: entry for GFN 2 (index 2) -> HFN 10
        let epte_gfn2 = HostEpte { hfn: 10, ..epml4e };
        mm.write_hpa_word(0x4000 + 2 * 8, epte_gfn2.encode());

        // Entry for GFN 5 (Guest PDPT) -> HFN 20
        let epte_gfn5 = HostEpte { hfn: 20, ..epml4e };
        mm.write_hpa_word(0x4000 + 5 * 8, epte_gfn5.encode());

        // Entry for GFN 6 (Guest PD) -> HFN 30
        let epte_gfn6 = HostEpte { hfn: 30, ..epml4e };
        mm.write_hpa_word(0x4000 + 6 * 8, epte_gfn6.encode());

        // Entry for GFN 7 (Guest PT) -> HFN 40
        let epte_gfn7 = HostEpte { hfn: 40, ..epml4e };
        mm.write_hpa_word(0x4000 + 7 * 8, epte_gfn7.encode());

        // Entry for GFN 8 (Guest Data Page) -> HFN 50
        let epte_gfn8 = HostEpte { hfn: 50, ..epml4e };
        mm.write_hpa_word(0x4000 + 8 * 8, epte_gfn8.encode());

        // Guest PML4 (HFN 10): index 0 -> GFN 5
        let pml4e = GuestPte {
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
        mm.write_hpa_word(10 << 12, pml4e.encode());

        // Guest PDPT (HFN 20): index 0 -> GFN 6
        let pdpte = GuestPte { gfn: 6, ..pml4e };
        mm.write_hpa_word(20 << 12, pdpte.encode());

        // Guest PD (HFN 30): index 0 -> GFN 7
        let pde = GuestPte { gfn: 7, ..pml4e };
        mm.write_hpa_word(30 << 12, pde.encode());

        // Guest PT (HFN 40): index 0 -> GFN 8
        let pte = GuestPte { gfn: 8, ..pml4e };
        mm.write_hpa_word(40 << 12, pte.encode());

        // Put test data in Data Page (HFN 50) at offset 0x48: value 0xDEADBEEFCAFE
        mm.write_hpa_word((50 << 12) + 0x48, 0xDEADBEEFCAFE);

        // Now translate GVA 0x0048 through 2D nested radix walk
        let gva = 0x0048u64;
        let (tlb, final_hpa) = mm.walk_2d_nested(1, cr3_guest, eptp, gva).unwrap();

        assert_eq!(final_hpa, (50 << 12) + 0x48);
        assert_eq!(tlb.hfn_host, 50);
        assert_eq!(mm.read_hpa_word(final_hpa), 0xDEADBEEFCAFE);
        // permissions: bit 0 (R), bit 1 (W), bit 2 (X), bit 3 (U)
        assert_eq!(tlb.perms & 0b1111, 0b1111);
    }
}
