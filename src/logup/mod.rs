//! Logarithmic Derivative Lookup Arguments (LogUp) for zk-HyperKVM.
//!
//! Formalizes the 3 coupled hardware buses (TLB, EPT, HPA) and the VirtIO Capability Bus:
//!   - B_TLB: Combined Guest Virtual to Host Physical fast-path translations.
//!   - B_EPT: Second-Level Address Translation (SLAT) GPA -> HPA translations.
//!   - B_HPA: Host Physical Memory word reads/writes with epoch tracking.
//!   - B_VIRTIO: Dynamic descriptor capability minting, usage, and revocation.

use crate::crypto::Scalar;
use ark_ff::{Field, Zero};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BusId {
    TLB = 1,
    EPT = 2,
    HPA = 3,
    VirtIO = 4,
}

impl BusId {
    pub fn to_scalar(self) -> Scalar {
        Scalar::from(self as u64)
    }
}

/// A structured entry or query on a LogUp bus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusTuple {
    pub bus_id: BusId,
    pub fields: Vec<Scalar>,
}

impl BusTuple {
    pub fn new(bus_id: BusId, fields: Vec<Scalar>) -> Self {
        Self { bus_id, fields }
    }

    /// Compresses a tuple into a single field element:
    /// Comp_beta(fields) = bus_id + sum_{r=0}^{k-1} fields[r] * beta^{r+1}
    pub fn compress(&self, beta: Scalar) -> Scalar {
        let mut sum = self.bus_id.to_scalar();
        let mut beta_pow = beta;
        for field in &self.fields {
            sum += *field * beta_pow;
            beta_pow *= beta;
        }
        sum
    }
}

/// Fast-path TLB translation entry for B_TLB
#[derive(Clone, Copy, Debug)]
pub struct TlbTranslation {
    pub vpid: u16,
    pub tau_vpid: u64,
    pub tau_ept: u64,
    pub cr3_guest: u64,
    pub eptp: u64,
    pub vpn_guest: u64,
    pub hfn_host: u64,
    pub perms: u8, // bit 0: Read, 1: Write, 2: Exec, 3: User
}

impl TlbTranslation {
    pub fn to_bus_tuple(&self) -> BusTuple {
        BusTuple::new(
            BusId::TLB,
            vec![
                Scalar::from(self.vpid),
                Scalar::from(self.tau_vpid),
                Scalar::from(self.tau_ept),
                Scalar::from(self.cr3_guest),
                Scalar::from(self.eptp),
                Scalar::from(self.vpn_guest),
                Scalar::from(self.hfn_host),
                Scalar::from(self.perms),
            ],
        )
    }
}

/// 1D Host EPT translation entry for B_EPT
#[derive(Clone, Copy, Debug)]
pub struct EptTranslation {
    pub tau_ept: u64,
    pub eptp: u64,
    pub gfn: u64,
    pub hfn: u64,
    pub perms_ept: u8, // bit 0: Read, 1: Write, 2: Exec
}

impl EptTranslation {
    pub fn to_bus_tuple(&self) -> BusTuple {
        BusTuple::new(
            BusId::EPT,
            vec![
                Scalar::from(self.tau_ept),
                Scalar::from(self.eptp),
                Scalar::from(self.gfn),
                Scalar::from(self.hfn),
                Scalar::from(self.perms_ept),
            ],
        )
    }
}

/// Host Physical Memory (HPA) access entry for B_HPA
#[derive(Clone, Debug)]
pub struct HpaAccess {
    pub hpa: u64,
    pub val: u64,
    pub epoch: u64,
    pub is_write: bool,
}

impl HpaAccess {
    pub fn to_bus_tuple(&self) -> BusTuple {
        BusTuple::new(
            BusId::HPA,
            vec![
                Scalar::from(self.hpa),
                Scalar::from(self.val),
                Scalar::from(self.epoch),
                Scalar::from(self.is_write as u64),
            ],
        )
    }
}

/// VirtIO Capability Token for B_VIRTIO
#[derive(Clone, Debug)]
pub struct VirtioCapability {
    pub vcpu_id: u32,
    pub queue_id: u16,
    pub chain_head: u16,
    pub gpa_start: u64,
    pub gpa_end: u64,
    pub write_perm: bool,
}

impl VirtioCapability {
    pub fn to_bus_tuple(&self) -> BusTuple {
        BusTuple::new(
            BusId::VirtIO,
            vec![
                Scalar::from(self.vcpu_id),
                Scalar::from(self.queue_id),
                Scalar::from(self.chain_head),
                Scalar::from(self.gpa_start),
                Scalar::from(self.gpa_end),
                Scalar::from(self.write_perm as u64),
            ],
        )
    }
}

/// LogUp bus state accumulator over an execution trace.
#[derive(Clone, Debug)]
pub struct LogUpBusAccumulator {
    pub acc_tlb: Scalar,
    pub acc_ept: Scalar,
    pub acc_hpa: Scalar,
    pub acc_virtio: Scalar,
}

impl LogUpBusAccumulator {
    pub fn new() -> Self {
        Self {
            acc_tlb: Scalar::zero(),
            acc_ept: Scalar::zero(),
            acc_hpa: Scalar::zero(),
            acc_virtio: Scalar::zero(),
        }
    }

    /// Add a step contribution (delta_tlb, delta_ept, delta_hpa, delta_virtio)
    pub fn update(&mut self, deltas: (Scalar, Scalar, Scalar, Scalar)) {
        self.acc_tlb += deltas.0;
        self.acc_ept += deltas.1;
        self.acc_hpa += deltas.2;
        self.acc_virtio += deltas.3;
    }

    /// Check the terminal boundary condition:
    /// All bus accumulators must strictly cancel to 0 at the final step T.
    pub fn is_balanced(&self) -> bool {
        self.acc_tlb.is_zero()
            && self.acc_ept.is_zero()
            && self.acc_hpa.is_zero()
            && self.acc_virtio.is_zero()
    }
}

impl Default for LogUpBusAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to compute fractional step contribution:
/// delta = sum_{demands} 1 / (gamma - q_i) - sum_{supplies} m_j / (gamma - t_j)
pub fn compute_logup_delta(
    demands: &[Scalar],
    supplies: &[(Scalar, Scalar)], // (entry, multiplicity)
    gamma: Scalar,
) -> (Scalar, Vec<Scalar>, Vec<Scalar>) {
    let mut delta = Scalar::zero();
    let mut h_demands = Vec::with_capacity(demands.len());
    let mut g_supplies = Vec::with_capacity(supplies.len());

    for &q in demands {
        let denom = gamma - q;
        assert!(!denom.is_zero(), "LogUp collision: gamma == query");
        let inv = denom.inverse().expect("Inverse exists in prime field");
        delta += inv;
        h_demands.push(inv);
    }

    for &(t, m) in supplies {
        let denom = gamma - t;
        assert!(!denom.is_zero(), "LogUp collision: gamma == table entry");
        let inv = denom.inverse().expect("Inverse exists in prime field");
        delta -= m * inv;
        g_supplies.push(inv);
    }

    (delta, h_demands, g_supplies)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bus_tuple_compression() {
        let tlb = TlbTranslation {
            vpid: 1,
            tau_vpid: 10,
            tau_ept: 20,
            cr3_guest: 0x1000,
            eptp: 0x2000,
            vpn_guest: 0x7fff_ffff,
            hfn_host: 0x8888,
            perms: 0b0111,
        };

        let tuple = tlb.to_bus_tuple();
        let beta = Scalar::from(42u32);
        let comp1 = tuple.compress(beta);
        let comp2 = tuple.compress(beta);
        assert_eq!(comp1, comp2);

        let mut altered = tlb.clone();
        altered.vpn_guest += 1;
        assert_ne!(tuple.compress(beta), altered.to_bus_tuple().compress(beta));
    }

    #[test]
    fn test_logup_delta_zero_balance() {
        let beta = Scalar::from(1337u32);
        let gamma = Scalar::from(999999u32);

        let tlb = TlbTranslation {
            vpid: 1,
            tau_vpid: 0,
            tau_ept: 0,
            cr3_guest: 0x1000,
            eptp: 0x2000,
            vpn_guest: 0x10,
            hfn_host: 0x20,
            perms: 7,
        };
        let q = tlb.to_bus_tuple().compress(beta);

        // 3 demands of q, and 1 supply of q with multiplicity 3
        let demands = vec![q, q, q];
        let supplies = vec![(q, Scalar::from(3u32))];

        let (delta, _, _) = compute_logup_delta(&demands, &supplies, gamma);
        assert!(delta.is_zero());

        let mut acc = LogUpBusAccumulator::new();
        acc.update((delta, Scalar::zero(), Scalar::zero(), Scalar::zero()));
        assert!(acc.is_balanced());
    }
}
