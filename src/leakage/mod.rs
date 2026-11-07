//! Microarchitectural and Speculative Execution Leakage Resilience.
//!
//! Formalizes hardware-software leakage contracts, cross-VM taint tracking,
//! architectural barrier enforcement (L1D_FLUSH, IBPB, VERW),
//! and Foreshadow (L1TF) non-present page frame masking.

use crate::ept::HostEpte;

/// Bitmask representation of domain taint over V+1 security domains.
/// Bit 0: Host Hypervisor (H)
/// Bit v (1..=V): Guest VM v
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MicroarchTaint {
    pub l1d: u32,
    pub btb: u32,
    pub lfb_mds: u32,
    pub stl: u32,
}

impl MicroarchTaint {
    pub fn new() -> Self {
        Self {
            l1d: 0,
            btb: 0,
            lfb_mds: 0,
            stl: 0,
        }
    }

    /// Taint accumulation during instruction execution in active domain `d`
    pub fn accumulate(&mut self, active_domain: u32) {
        let mask = 1u32 << active_domain;
        self.l1d |= mask;
        self.btb |= mask;
        self.lfb_mds |= mask;
        self.stl |= mask;
    }

    /// Apply architectural barriers:
    /// - f_l1d: IA32_FLUSH_CMD (0x10B) flushes L1 Data Cache
    /// - f_ibpb: IA32_PRED_CMD (0x49) flushes Branch Target Buffer
    /// - f_verw: VERW flushes Line Fill Buffers / MDS structures
    pub fn apply_barriers(&mut self, f_l1d: bool, f_ibpb: bool, f_verw: bool) {
        if f_l1d {
            self.l1d = 0;
        }
        if f_ibpb {
            self.btb = 0;
        }
        if f_verw {
            self.lfb_mds = 0;
            self.stl = 0;
        }
    }

    /// Verify Definition 5: World-Switch Microarchitectural Sanitization Invariant
    /// When switching from domain d1 to d2 (where d2 != d1), domain d1 must have zero residual taint!
    pub fn verify_sanitization(
        &self,
        from_domain: u32,
        to_domain: u32,
    ) -> Result<(), &'static str> {
        if from_domain == to_domain {
            return Ok(());
        }

        let from_mask = 1u32 << from_domain;
        if (self.l1d & from_mask) != 0 {
            return Err("Microarchitectural Leakage: L1D cache contains residual taint from previous domain!");
        }
        if (self.btb & from_mask) != 0 {
            return Err(
                "Microarchitectural Leakage: BTB contains residual branch prediction taint!",
            );
        }
        if (self.lfb_mds & from_mask) != 0 {
            return Err(
                "Microarchitectural Leakage: Line fill buffers contain residual MDS taint!",
            );
        }

        Ok(())
    }

    /// Appendix C: ForeignTaint homogeneous linear constraint:
    /// ForeignTaint(mu^{(t+1)}, d_next) = sum_{comp} sum_{d != d_next} tau_{comp, d} == 0
    pub fn foreign_taint(&self, d_next: u32, num_domains: u32) -> u32 {
        let mut foreign_sum = 0u32;
        for d in 0..num_domains {
            if d != d_next {
                let mask = 1u32 << d;
                if (self.l1d & mask) != 0 {
                    foreign_sum += 1;
                }
                if (self.btb & mask) != 0 {
                    foreign_sum += 1;
                }
                if (self.lfb_mds & mask) != 0 {
                    foreign_sum += 1;
                }
                if (self.stl & mask) != 0 {
                    foreign_sum += 1;
                }
            }
        }
        foreign_sum
    }

    /// Check if ForeignTaint == 0 prior to entering domain d_next
    pub fn verify_cross_domain_entry_gate(
        &self,
        d_next: u32,
        num_domains: u32,
    ) -> Result<(), &'static str> {
        if self.foreign_taint(d_next, num_domains) != 0 {
            return Err("Cross-Domain Entry Gate Rejected: Non-zero foreign microarchitectural taint detected!");
        }
        Ok(())
    }
}

impl Default for MicroarchTaint {
    fn default() -> Self {
        Self::new()
    }
}

/// Mitigation 2: Foreshadow (L1TF) Non-Present EPT Physical Frame Masking.
///
/// In Intel VT-x, non-present PTEs (P=0) can still leak physical frames through L1TF.
/// zk-HyperKVM enforces that every non-present EPT entry MUST have its physical frame number
/// explicitly zeroed: (1 - p_present) * pfn == 0.
pub fn verify_l1tf_immunity(epte: &HostEpte) -> Result<(), &'static str> {
    let is_present = epte.read || epte.write || epte.execute;
    if !is_present && epte.hfn != 0 {
        return Err("L1TF (Foreshadow) Vulnerability: Non-present EPT entry contains non-zero physical frame number!");
    }
    Ok(())
}

/// Mitigation 3: IA32_SPEC_CTRL (0x48) MSR Verification.
///
/// Verifies hardware speculative isolation flags:
/// - IBRS (bit 0): Indirect Branch Restricted Speculation
/// - STIBP (bit 1): Single Thread Indirect Branch Predictors
/// - SSBD (bit 2): Speculative Store Bypass Disable
/// - BHI_DIS_S (bit 10): Branch History Injection Disable
pub const SPEC_CTRL_REQUIRED_MASK: u64 = 0b0100_0000_0111; // IBRS | STIBP | SSBD | BHI_DIS_S

pub fn verify_spec_ctrl(val: u64) -> Result<(), &'static str> {
    if (val & SPEC_CTRL_REQUIRED_MASK) != SPEC_CTRL_REQUIRED_MASK {
        return Err(
            "Speculative Isolation Violation: Required SPEC_CTRL mitigation bits were stripped!",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_microarch_sanitization_lifecycle() {
        let mut taint = MicroarchTaint::new();

        // Guest VM 1 executes code
        taint.accumulate(1);
        assert_eq!(taint.l1d & (1 << 1), 1 << 1);

        // World-switch from VM 1 to VM 2 without barriers must be rejected
        assert!(taint.verify_sanitization(1, 2).is_err());

        // Apply mandatory architectural barriers (L1D_FLUSH, IBPB, VERW)
        taint.apply_barriers(true, true, true);

        // Now world-switch is clean and accepted
        assert!(taint.verify_sanitization(1, 2).is_ok());
    }

    #[test]
    fn test_l1tf_immunity() {
        // Vulnerable entry: Read/Write/Exec are false, but HFN = 0x1234
        let vuln_epte = HostEpte {
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
            hfn: 0x1234,
            suppress_ve: false,
        };
        assert!(verify_l1tf_immunity(&vuln_epte).is_err());

        // Safe entry: Non-present, but HFN = 0
        let safe_epte = HostEpte {
            hfn: 0,
            ..vuln_epte
        };
        assert!(verify_l1tf_immunity(&safe_epte).is_ok());
    }
}
