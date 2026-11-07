//! Cryptographic primitives for zk-HyperKVM.
//!
//! Provides scalar field aliases, group definitions (BN254 / Pasta),
//! Fiat-Shamir sponge transcripts, and split-domain homomorphic Pedersen commitments.

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_std::Zero;
use sha3::{Digest, Keccak256};
use std::ops::{Add, Mul};

pub type Scalar = Fr;
pub type Point = G1Projective;
pub type AffinePoint = G1Affine;

/// Cryptographic Fiat-Shamir transcript based on Keccak256 sponge.
#[derive(Clone, Debug)]
pub struct Transcript {
    state: [u8; 32],
    counter: u64,
}

impl Transcript {
    pub fn new(label: &'static str) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(b"zk-HyperKVM-v1-Transcript-Domain-Separator");
        hasher.update(label.as_bytes());
        let mut state = [0u8; 32];
        state.copy_from_slice(&hasher.finalize());
        Self { state, counter: 0 }
    }

    pub fn absorb_bytes(&mut self, label: &'static str, data: &[u8]) {
        let mut hasher = Keccak256::new();
        hasher.update(self.state);
        hasher.update(label.as_bytes());
        hasher.update(self.counter.to_le_bytes());
        hasher.update(data);
        self.state.copy_from_slice(&hasher.finalize());
        self.counter += 1;
    }

    pub fn absorb_scalar(&mut self, label: &'static str, scalar: &Scalar) {
        let bytes = scalar.into_bigint().to_bytes_le();
        self.absorb_bytes(label, &bytes);
    }

    pub fn absorb_point(&mut self, label: &'static str, point: &Point) {
        let affine = point.into_affine();
        let mut bytes = Vec::new();
        use ark_serialize::CanonicalSerialize;
        let _ = affine.serialize_compressed(&mut bytes);
        self.absorb_bytes(label, &bytes);
    }

    pub fn squeeze_scalar(&mut self, label: &'static str) -> Scalar {
        let mut hasher = Keccak256::new();
        hasher.update(self.state);
        hasher.update(label.as_bytes());
        hasher.update(self.counter.to_le_bytes());
        let digest = hasher.finalize();
        self.state.copy_from_slice(&digest);
        self.counter += 1;
        Scalar::from_le_bytes_mod_order(&digest)
    }

    pub fn squeeze_scalars(&mut self, label: &'static str, n: usize) -> Vec<Scalar> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.squeeze_scalar(label));
        }
        out
    }
}

/// Public parameters for Split-Domain Pedersen commitments.
/// Partitions generators into guest, host, and logup domains:
/// pp = (pp_guest, pp_host, pp_logup)
#[derive(Clone, Debug)]
pub struct SplitCommitmentParams {
    pub n_guest: usize,
    pub n_host: usize,
    pub n_logup: usize,
    pub gens_guest: Vec<Point>,
    pub gens_host: Vec<Point>,
    pub gens_logup: Vec<Point>,
    pub gen_blind: Point,
}

impl SplitCommitmentParams {
    pub fn setup(n_guest: usize, n_host: usize, n_logup: usize) -> Self {
        let gen_blind = Point::generator();
        let total = n_guest + n_host + n_logup;
        let mut gens = Vec::with_capacity(total);

        // Deterministic generator derivation via hash-to-curve / scalar multiplication
        for i in 0..total {
            let mut hasher = Keccak256::new();
            hasher.update(b"zk-HyperKVM-Commitment-Generator");
            hasher.update((i as u64).to_le_bytes());
            let scalar = Scalar::from_le_bytes_mod_order(&hasher.finalize());
            gens.push(gen_blind.mul(scalar));
        }

        let gens_guest = gens[..n_guest].to_vec();
        let gens_host = gens[n_guest..n_guest + n_host].to_vec();
        let gens_logup = gens[n_guest + n_host..].to_vec();

        Self {
            n_guest,
            n_host,
            n_logup,
            gens_guest,
            gens_host,
            gens_logup,
            gen_blind,
        }
    }
}

/// A split homomorphic commitment: (C_guest, C_host, C_logup) in G_1^3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplitCommitment {
    pub c_guest: Point,
    pub c_host: Point,
    pub c_logup: Point,
}

impl SplitCommitment {
    pub fn zero() -> Self {
        Self {
            c_guest: Point::zero(),
            c_host: Point::zero(),
            c_logup: Point::zero(),
        }
    }

    pub fn commit(
        params: &SplitCommitmentParams,
        w_guest: &[Scalar],
        w_host: &[Scalar],
        w_logup: &[Scalar],
    ) -> Self {
        assert_eq!(w_guest.len(), params.n_guest);
        assert_eq!(w_host.len(), params.n_host);
        assert_eq!(w_logup.len(), params.n_logup);

        let mut c_guest = Point::zero();
        for (w, g) in w_guest.iter().zip(params.gens_guest.iter()) {
            c_guest += g.mul(*w);
        }

        let mut c_host = Point::zero();
        for (w, g) in w_host.iter().zip(params.gens_host.iter()) {
            c_host += g.mul(*w);
        }

        let mut c_logup = Point::zero();
        for (w, g) in w_logup.iter().zip(params.gens_logup.iter()) {
            c_logup += g.mul(*w);
        }

        Self {
            c_guest,
            c_host,
            c_logup,
        }
    }

    /// Combined total group element: C_total = C_guest + C_host + C_logup
    pub fn total(&self) -> Point {
        self.c_guest + self.c_host + self.c_logup
    }

    /// Homomorphic folding along challenge rho: C_folded = C_1 + rho * C_2
    pub fn fold(&self, other: &Self, rho: Scalar) -> Self {
        Self {
            c_guest: self.c_guest + other.c_guest.mul(rho),
            c_host: self.c_host + other.c_host.mul(rho),
            c_logup: self.c_logup + other.c_logup.mul(rho),
        }
    }
}

impl Add for SplitCommitment {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self {
            c_guest: self.c_guest + rhs.c_guest,
            c_host: self.c_host + rhs.c_host,
            c_logup: self.c_logup + rhs.c_logup,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_commitment_homomorphism() {
        let params = SplitCommitmentParams::setup(4, 4, 4);
        let w_g1 = vec![
            Scalar::from(1u32),
            Scalar::from(2u32),
            Scalar::from(3u32),
            Scalar::from(4u32),
        ];
        let w_h1 = vec![
            Scalar::from(5u32),
            Scalar::from(6u32),
            Scalar::from(7u32),
            Scalar::from(8u32),
        ];
        let w_l1 = vec![
            Scalar::from(9u32),
            Scalar::from(10u32),
            Scalar::from(11u32),
            Scalar::from(12u32),
        ];

        let w_g2 = vec![
            Scalar::from(2u32),
            Scalar::from(3u32),
            Scalar::from(4u32),
            Scalar::from(5u32),
        ];
        let w_h2 = vec![
            Scalar::from(6u32),
            Scalar::from(7u32),
            Scalar::from(8u32),
            Scalar::from(9u32),
        ];
        let w_l2 = vec![
            Scalar::from(10u32),
            Scalar::from(11u32),
            Scalar::from(12u32),
            Scalar::from(13u32),
        ];

        let c1 = SplitCommitment::commit(&params, &w_g1, &w_h1, &w_l1);
        let c2 = SplitCommitment::commit(&params, &w_g2, &w_h2, &w_l2);

        let rho = Scalar::from(7u32);
        let c_folded = c1.fold(&c2, rho);

        let w_g_folded: Vec<Scalar> = w_g1
            .iter()
            .zip(w_g2.iter())
            .map(|(a, b)| *a + rho * *b)
            .collect();
        let w_h_folded: Vec<Scalar> = w_h1
            .iter()
            .zip(w_h2.iter())
            .map(|(a, b)| *a + rho * *b)
            .collect();
        let w_l_folded: Vec<Scalar> = w_l1
            .iter()
            .zip(w_l2.iter())
            .map(|(a, b)| *a + rho * *b)
            .collect();

        let c_direct = SplitCommitment::commit(&params, &w_g_folded, &w_h_folded, &w_l_folded);
        assert_eq!(c_folded.c_guest, c_direct.c_guest);
        assert_eq!(c_folded.c_host, c_direct.c_host);
        assert_eq!(c_folded.c_logup, c_direct.c_logup);
        assert_eq!(c_folded.total(), c_direct.total());
    }
}
