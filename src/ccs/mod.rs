//! Customizable Constraint Systems (CCS), Linearized Committed CCS (LCCS),
//! and Committed CCS (CCCS) implementations.
//!
//! Based on Setty et al. (CCS, 2023) and Kothapalli & Setty (HyperNova, 2023).

use crate::crypto::{Scalar, SplitCommitment};
use ark_ff::{One, Zero};

/// A sparse matrix entry (row, col, value).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatrixEntry {
    pub row: usize,
    pub col: usize,
    pub val: Scalar,
}

/// Sparse matrix representation over `Scalar`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseMatrix {
    pub rows: usize,
    pub cols: usize,
    pub entries: Vec<MatrixEntry>,
}

impl SparseMatrix {
    pub fn new(rows: usize, cols: usize, entries: Vec<MatrixEntry>) -> Self {
        Self {
            rows,
            cols,
            entries,
        }
    }

    /// Multiply sparse matrix by a dense vector: out = M * z
    pub fn multiply_vec(&self, z: &[Scalar]) -> Vec<Scalar> {
        assert_eq!(
            z.len(),
            self.cols,
            "Vector length must match matrix columns"
        );
        let mut out = vec![Scalar::zero(); self.rows];
        for entry in &self.entries {
            out[entry.row] += entry.val * z[entry.col];
        }
        out
    }

    /// Multiply a row evaluation vector (from eq(r_x, .)) by sparse matrix: out = r_vec * M
    pub fn vec_multiply(&self, r_vec: &[Scalar]) -> Vec<Scalar> {
        assert_eq!(
            r_vec.len(),
            self.rows,
            "Row weights length must match matrix rows"
        );
        let mut out = vec![Scalar::zero(); self.cols];
        for entry in &self.entries {
            out[entry.col] += r_vec[entry.row] * entry.val;
        }
        out
    }
}

/// Customizable Constraint System (CCS) structure.
///
/// Encodes constraints of the form:
///   sum_{i=1}^q c_i * ( Hadamard_{j in S_i} M_j * z ) = 0^m
#[derive(Clone, Debug)]
pub struct CCSStructure {
    pub m: usize,                    // number of constraints (rows)
    pub n: usize,                    // total variables (cols)
    pub l: usize,                    // public input length
    pub s: usize,                    // log2(m)
    pub s_prime: usize,              // log2(n)
    pub matrices: Vec<SparseMatrix>, // M_1, ..., M_t
    pub multisets: Vec<Vec<usize>>,  // S_1, ..., S_q (indices into matrices)
    pub coeffs: Vec<Scalar>,         // c_1, ..., c_q
}

impl CCSStructure {
    pub fn new(
        m: usize,
        n: usize,
        l: usize,
        matrices: Vec<SparseMatrix>,
        multisets: Vec<Vec<usize>>,
        coeffs: Vec<Scalar>,
    ) -> Self {
        assert_eq!(multisets.len(), coeffs.len());
        for mat in &matrices {
            assert_eq!(mat.rows, m);
            assert_eq!(mat.cols, n);
        }
        let s = (m as f64).log2().ceil() as usize;
        let s_prime = (n as f64).log2().ceil() as usize;
        Self {
            m,
            n,
            l,
            s: s.max(1),
            s_prime: s_prime.max(1),
            matrices,
            multisets,
            coeffs,
        }
    }

    /// Format full vector z = (w, u, x)
    pub fn format_z(&self, w: &[Scalar], u: Scalar, x: &[Scalar]) -> Vec<Scalar> {
        assert_eq!(x.len(), self.l);
        assert_eq!(w.len(), self.n - self.l - 1);
        let mut z = Vec::with_capacity(self.n);
        z.extend_from_slice(w);
        z.push(u);
        z.extend_from_slice(x);
        z
    }

    /// Check if (w, 1, x) satisfies the CCS relation.
    pub fn is_satisfied(&self, w: &[Scalar], x: &[Scalar]) -> bool {
        let z = self.format_z(w, Scalar::one(), x);
        let m_z: Vec<Vec<Scalar>> = self
            .matrices
            .iter()
            .map(|mat| mat.multiply_vec(&z))
            .collect();

        let mut sum = vec![Scalar::zero(); self.m];
        for (term_idx, s_i) in self.multisets.iter().enumerate() {
            let coeff = self.coeffs[term_idx];
            let mut prod = vec![Scalar::one(); self.m];
            for &j in s_i {
                for r in 0..self.m {
                    prod[r] *= m_z[j][r];
                }
            }
            for r in 0..self.m {
                sum[r] += coeff * prod[r];
            }
        }

        sum.iter().all(|val| val.is_zero())
    }
}

/// Equality polynomial evaluated across the boolean hypercube:
/// eq(r, y) = prod_{i=0}^{s-1} (r_i * y_i + (1 - r_i) * (1 - y_i))
pub fn compute_eq_table(r: &[Scalar], num_points: usize) -> Vec<Scalar> {
    let s = r.len();
    assert!(num_points <= (1 << s));
    let mut table = vec![Scalar::one()];
    for &r_i in r {
        let mut next = Vec::with_capacity(table.len() * 2);
        for &val in &table {
            next.push(val * (Scalar::one() - r_i)); // y_k = 0
            next.push(val * r_i); // y_k = 1
        }
        table = next;
    }
    table.truncate(num_points);
    table
}

/// Evaluates eq(r1, r2) directly: prod (r1_i * r2_i + (1 - r1_i) * (1 - r2_i))
pub fn eval_eq(r1: &[Scalar], r2: &[Scalar]) -> Scalar {
    assert_eq!(r1.len(), r2.len());
    let mut prod = Scalar::one();
    for (a, b) in r1.iter().zip(r2.iter()) {
        prod *= *a * *b + (Scalar::one() - *a) * (Scalar::one() - *b);
    }
    prod
}

/// Committed CCS instance (CCCS): u = (C, 1, x)
#[derive(Clone, Debug)]
pub struct CCCSInstance {
    pub c: SplitCommitment,
    pub x: Vec<Scalar>,
}

/// Committed CCS witness
#[derive(Clone, Debug)]
pub struct CCCSWitness {
    pub w_guest: Vec<Scalar>,
    pub w_host: Vec<Scalar>,
    pub w_logup: Vec<Scalar>,
}

impl CCCSWitness {
    pub fn full_w(&self) -> Vec<Scalar> {
        let mut w = Vec::with_capacity(self.w_guest.len() + self.w_host.len() + self.w_logup.len());
        w.extend_from_slice(&self.w_guest);
        w.extend_from_slice(&self.w_host);
        w.extend_from_slice(&self.w_logup);
        w
    }
}

/// Linearized Committed CCS instance (LCCS): U = (C, u, x, r_x, v_1, ..., v_t)
#[derive(Clone, Debug)]
pub struct LCCSInstance {
    pub c: SplitCommitment,
    pub u: Scalar,
    pub x: Vec<Scalar>,
    pub r_x: Vec<Scalar>,
    pub v: Vec<Scalar>, // claimed multilinear evaluations v_1, ..., v_t
}

impl LCCSInstance {
    /// Initialize a dummy/empty LCCS instance for circuit k
    pub fn empty(ccs: &CCSStructure) -> Self {
        Self {
            c: SplitCommitment::zero(),
            u: Scalar::zero(),
            x: vec![Scalar::zero(); ccs.l],
            r_x: vec![Scalar::zero(); ccs.s],
            v: vec![Scalar::zero(); ccs.matrices.len()],
        }
    }

    /// Convert a satisfied CCCS instance and witness into a fresh LCCS instance
    /// evaluated at hypercube point r_x.
    pub fn from_cccs(
        ccs: &CCSStructure,
        cccs_inst: &CCCSInstance,
        cccs_wit: &CCCSWitness,
        r_x: &[Scalar],
    ) -> Self {
        assert_eq!(r_x.len(), ccs.s);
        let z = ccs.format_z(&cccs_wit.full_w(), Scalar::one(), &cccs_inst.x);
        let eq_table = compute_eq_table(r_x, ccs.m);

        let mut v = Vec::with_capacity(ccs.matrices.len());
        for mat in &ccs.matrices {
            let m_z = mat.multiply_vec(&z);
            let mut eval = Scalar::zero();
            for (val, eq) in m_z.iter().zip(eq_table.iter()) {
                eval += *val * *eq;
            }
            v.push(eval);
        }

        Self {
            c: cccs_inst.c,
            u: Scalar::one(),
            x: cccs_inst.x.clone(),
            r_x: r_x.to_vec(),
            v,
        }
    }

    /// Verify multilinear evaluation claim:
    /// v_j == sum_x eq(r_x, x) * (M_j * z)_x
    pub fn is_satisfied(&self, ccs: &CCSStructure, wit: &CCCSWitness) -> bool {
        let z = ccs.format_z(&wit.full_w(), self.u, &self.x);
        let eq_table = compute_eq_table(&self.r_x, ccs.m);

        for (j, mat) in ccs.matrices.iter().enumerate() {
            let m_z = mat.multiply_vec(&z);
            let mut eval = Scalar::zero();
            for (val, eq) in m_z.iter().zip(eq_table.iter()) {
                eval += *val * *eq;
            }
            if eval != self.v[j] {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ccs_and_lccs_satisfaction() {
        // Create simple constraint: w0 * w1 - x0 = 0
        // z = [w0, w1, u, x0] -> n = 4, l = 1, m = 1
        let m0 = SparseMatrix::new(
            1,
            4,
            vec![MatrixEntry {
                row: 0,
                col: 0,
                val: Scalar::one(),
            }], // w0
        );
        let m1 = SparseMatrix::new(
            1,
            4,
            vec![MatrixEntry {
                row: 0,
                col: 1,
                val: Scalar::one(),
            }], // w1
        );
        let m2 = SparseMatrix::new(
            1,
            4,
            vec![MatrixEntry {
                row: 0,
                col: 3,
                val: Scalar::one(),
            }], // x0
        );

        let matrices = vec![m0, m1, m2];
        let multisets = vec![vec![0, 1], vec![2]];
        let coeffs = vec![Scalar::one(), -Scalar::one()];

        let ccs = CCSStructure::new(1, 4, 1, matrices, multisets, coeffs);

        let w = vec![Scalar::from(3u32), Scalar::from(4u32)];
        let x = vec![Scalar::from(12u32)];
        assert!(ccs.is_satisfied(&w, &x));

        let invalid_x = vec![Scalar::from(13u32)];
        assert!(!ccs.is_satisfied(&w, &invalid_x));

        let cccs_wit = CCCSWitness {
            w_guest: vec![Scalar::from(3u32)],
            w_host: vec![Scalar::from(4u32)],
            w_logup: vec![],
        };
        let cccs_inst = CCCSInstance {
            c: SplitCommitment::zero(),
            x: x.clone(),
        };

        let r_x = vec![Scalar::from(5u32)];
        let lccs = LCCSInstance::from_cccs(&ccs, &cccs_inst, &cccs_wit, &r_x);
        assert!(lccs.is_satisfied(&ccs, &cccs_wit));
    }
}
