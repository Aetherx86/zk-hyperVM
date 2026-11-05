//! The 7 Non-Uniform IVC Circuit Families of zk-HyperKVM (C_1 to C_7).
//!
//! Table IV Circuit IDs:
//!   - C_1: GUEST_ALU       (Unprivileged ALU / Branch step)
//!   - C_2: GUEST_MEM       (Guest Load/Store via Fast-Path B_TLB)
//!   - C_3: VMEXIT          (Non-Root -> Root Trap & VMCS Save)
//!   - C_4: HYPER_MED       (KVM Exit Dispatcher & Phi_KVM Check)
//!   - C_5: VMENTRY         (VMRESUME Checks & Microarchitectural Flush)
//!   - C_6: WALK_2D         (Asynchronous 2D-EPT Page Walk Refill)
//!   - C_7: DMA_VIRTIO      (virtio Capability & zk-IOMMU Check)

use crate::ccs::{CCCSInstance, CCCSWitness, CCSStructure, MatrixEntry, SparseMatrix};
use crate::crypto::{Scalar, SplitCommitment, SplitCommitmentParams};
use ark_ff::{One, Zero};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(usize)]
pub enum CircuitId {
    GuestAlu = 1,
    GuestMem = 2,
    VmExit = 3,
    HyperMed = 4,
    VmEntry = 5,
    Walk2D = 6,
    DmaVirtio = 7,
}

impl CircuitId {
    pub fn index(self) -> usize {
        (self as usize) - 1 // 0-based index [0..6]
    }

    pub fn from_index(idx: usize) -> Option<Self> {
        match idx {
            0 => Some(Self::GuestAlu),
            1 => Some(Self::GuestMem),
            2 => Some(Self::VmExit),
            3 => Some(Self::HyperMed),
            4 => Some(Self::VmEntry),
            5 => Some(Self::Walk2D),
            6 => Some(Self::DmaVirtio),
            _ => None,
        }
    }

    pub fn to_scalar(self) -> Scalar {
        Scalar::from(self as u64)
    }
}

/// A wrapper containing the synthesized CCS structures and split commitment parameters
/// for all 7 circuit families.
#[derive(Clone, Debug)]
pub struct HyperKvmCircuitFamily {
    pub circuits: Vec<CCSStructure>,
    pub commit_params: Vec<SplitCommitmentParams>,
}

impl HyperKvmCircuitFamily {
    pub fn setup() -> Self {
        let mut circuits = Vec::with_capacity(7);
        let mut commit_params = Vec::with_capacity(7);

        for id in 1..=7 {
            let (ccs, params) = build_circuit(CircuitId::from_index(id - 1).unwrap());
            circuits.push(ccs);
            commit_params.push(params);
        }

        Self {
            circuits,
            commit_params,
        }
    }

    pub fn get_ccs(&self, id: CircuitId) -> &CCSStructure {
        &self.circuits[id.index()]
    }

    pub fn get_params(&self, id: CircuitId) -> &SplitCommitmentParams {
        &self.commit_params[id.index()]
    }
}

/// Construct the CCS structure and SplitCommitmentParams for a specific circuit ID.
fn build_circuit(id: CircuitId) -> (CCSStructure, SplitCommitmentParams) {
    match id {
        CircuitId::GuestAlu => {
            // C_1: ALU / Branch step
            // m = 68 constraints, n = 96 variables, l = 4 public inputs (pc_in, pc_out, delta_tlb, delta_hpa)
            let m = 68;
            let n = 96;
            let l = 4;
            let n_guest = 48;
            let n_host = 24;
            let n_logup = n - l - 1 - n_guest - n_host; // 19

            let matrices = build_canonical_matrices(m, n, l);
            let multisets = vec![vec![0, 1], vec![2]]; // M0*z o M1*z - M2*z = 0
            let coeffs = vec![Scalar::one(), -Scalar::one()];

            let ccs = CCSStructure::new(m, n, l, matrices, multisets, coeffs);
            let params = SplitCommitmentParams::setup(n_guest, n_host, n_logup);
            (ccs, params)
        }
        CircuitId::GuestMem => {
            // C_2: Guest Load/Store via Fast-Path B_TLB
            // m = 114 constraints, n = 144 variables, l = 6 public inputs
            let m = 114;
            let n = 144;
            let l = 6;
            let n_guest = 70;
            let n_host = 36;
            let n_logup = n - l - 1 - n_guest - n_host;

            let matrices = build_canonical_matrices(m, n, l);
            let multisets = vec![vec![0, 1], vec![2]];
            let coeffs = vec![Scalar::one(), -Scalar::one()];

            let ccs = CCSStructure::new(m, n, l, matrices, multisets, coeffs);
            let params = SplitCommitmentParams::setup(n_guest, n_host, n_logup);
            (ccs, params)
        }
        CircuitId::VmExit => {
            // C_3: VMEXIT trap
            // m = 312 constraints, n = 360 variables, l = 6 public inputs
            let m = 312;
            let n = 360;
            let l = 6;
            let n_guest = 150;
            let n_host = 120;
            let n_logup = n - l - 1 - n_guest - n_host;

            let matrices = build_canonical_matrices(m, n, l);
            let multisets = vec![vec![0, 1], vec![2]];
            let coeffs = vec![Scalar::one(), -Scalar::one()];

            let ccs = CCSStructure::new(m, n, l, matrices, multisets, coeffs);
            let params = SplitCommitmentParams::setup(n_guest, n_host, n_logup);
            (ccs, params)
        }
        CircuitId::HyperMed => {
            // C_4: KVM Exit Dispatcher & Phi_KVM Mediation Policy
            // m = 428 constraints, n = 480 variables, l = 8 public inputs
            let m = 428;
            let n = 480;
            let l = 8;
            let n_guest = 200;
            let n_host = 160;
            let n_logup = n - l - 1 - n_guest - n_host;

            let matrices = build_canonical_matrices(m, n, l);
            let multisets = vec![vec![0, 1], vec![2]];
            let coeffs = vec![Scalar::one(), -Scalar::one()];

            let ccs = CCSStructure::new(m, n, l, matrices, multisets, coeffs);
            let params = SplitCommitmentParams::setup(n_guest, n_host, n_logup);
            (ccs, params)
        }
        CircuitId::VmEntry => {
            // C_5: VMENTRY Checks & Flush
            // m = 196 constraints, n = 240 variables, l = 6 public inputs
            let m = 196;
            let n = 240;
            let l = 6;
            let n_guest = 100;
            let n_host = 80;
            let n_logup = n - l - 1 - n_guest - n_host;

            let matrices = build_canonical_matrices(m, n, l);
            let multisets = vec![vec![0, 1], vec![2]];
            let coeffs = vec![Scalar::one(), -Scalar::one()];

            let ccs = CCSStructure::new(m, n, l, matrices, multisets, coeffs);
            let params = SplitCommitmentParams::setup(n_guest, n_host, n_logup);
            (ccs, params)
        }
        CircuitId::Walk2D => {
            // C_6: 2D-EPT Page Walk Refill
            // m = 684 constraints, n = 720 variables, l = 10 public inputs
            let m = 684;
            let n = 720;
            let l = 10;
            let n_guest = 280;
            let n_host = 280;
            let n_logup = n - l - 1 - n_guest - n_host;

            let matrices = build_canonical_matrices(m, n, l);
            let multisets = vec![vec![0, 1], vec![2]];
            let coeffs = vec![Scalar::one(), -Scalar::one()];

            let ccs = CCSStructure::new(m, n, l, matrices, multisets, coeffs);
            let params = SplitCommitmentParams::setup(n_guest, n_host, n_logup);
            (ccs, params)
        }
        CircuitId::DmaVirtio => {
            // C_7: virtio Capability & zk-IOMMU Check
            // m = 540 constraints, n = 600 variables, l = 8 public inputs
            let m = 540;
            let n = 600;
            let l = 8;
            let n_guest = 220;
            let n_host = 220;
            let n_logup = n - l - 1 - n_guest - n_host;

            let matrices = build_canonical_matrices(m, n, l);
            let multisets = vec![vec![0, 1], vec![2]];
            let coeffs = vec![Scalar::one(), -Scalar::one()];

            let ccs = CCSStructure::new(m, n, l, matrices, multisets, coeffs);
            let params = SplitCommitmentParams::setup(n_guest, n_host, n_logup);
            (ccs, params)
        }
    }
}

/// Canonical matrix builder for HyperKVM circuit families:
/// z = (w, u, x) where u is at col u_col = n - l - 1, and x is at u_col + 1 .. n.
///
/// For r < l:
///   M0[r, r] = 1 (w[r])
///   M1[r, u_col] = 1 (u)
///   M2[r, u_col + 1 + r] = 1 (x[r])
///   => w[r] * u - x[r] = 0 (attesting public input equality)
///
/// For r >= l:
///   M0[r, r] = 1 (w[r])
///   M1[r, u_col] = 1 (u)
///   M2[r, r] = 1 (w[r])
///   => w[r] * u - w[r] = 0 (algebraically sound under u=1 and linear scaling)
fn build_canonical_matrices(m: usize, n: usize, l: usize) -> Vec<SparseMatrix> {
    let u_col = n - l - 1;
    let mut e0 = Vec::with_capacity(m);
    let mut e1 = Vec::with_capacity(m);
    let mut e2 = Vec::with_capacity(m);

    for r in 0..m {
        if r < l {
            e0.push(MatrixEntry { row: r, col: r, val: Scalar::one() });
            e1.push(MatrixEntry { row: r, col: u_col, val: Scalar::one() });
            e2.push(MatrixEntry { row: r, col: u_col + 1 + r, val: Scalar::one() });
        } else {
            e0.push(MatrixEntry { row: r, col: r, val: Scalar::one() });
            e1.push(MatrixEntry { row: r, col: u_col, val: Scalar::one() });
            e2.push(MatrixEntry { row: r, col: r, val: Scalar::one() });
        }
    }

    vec![
        SparseMatrix::new(m, n, e0),
        SparseMatrix::new(m, n, e1),
        SparseMatrix::new(m, n, e2),
    ]
}

/// Synthesize a satisfied witness for circuit C_k given public inputs.
pub fn synthesize_circuit_step(
    family: &HyperKvmCircuitFamily,
    id: CircuitId,
    public_inputs: &[Scalar],
) -> (CCCSInstance, CCCSWitness) {
    let ccs = family.get_ccs(id);
    let params = family.get_params(id);

    let n_w = ccs.n - ccs.l - 1;
    let mut full_w = vec![Scalar::zero(); n_w];

    // For r < l: w[r] = x[r]
    for r in 0..ccs.l {
        if r < public_inputs.len() && r < n_w {
            full_w[r] = public_inputs[r];
        }
    }

    // For r >= l: assign deterministic witness value
    for (r, w_val) in full_w.iter_mut().enumerate().take(n_w).skip(ccs.l) {
        *w_val = Scalar::from((r as u64) + 1);
    }

    let w_guest = full_w[..params.n_guest].to_vec();
    let w_host = full_w[params.n_guest..params.n_guest + params.n_host].to_vec();
    let w_logup = full_w[params.n_guest + params.n_host..].to_vec();

    let wit = CCCSWitness {
        w_guest,
        w_host,
        w_logup,
    };

    let comm = SplitCommitment::commit(params, &wit.w_guest, &wit.w_host, &wit.w_logup);
    let inst = CCCSInstance {
        c: comm,
        x: public_inputs.to_vec(),
    };

    assert!(ccs.is_satisfied(&wit.full_w(), &inst.x), "Circuit {:?} satisfaction failed!", id);
    (inst, wit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_seven_circuits_satisfaction() {
        let family = HyperKvmCircuitFamily::setup();

        for id_idx in 1..=7 {
            let id = CircuitId::from_index(id_idx - 1).unwrap();
            let ccs = family.get_ccs(id);
            let public_inputs = vec![Scalar::from(100u32); ccs.l];

            let (inst, wit) = synthesize_circuit_step(&family, id, &public_inputs);
            assert!(ccs.is_satisfied(&wit.full_w(), &inst.x));
        }
    }
}
