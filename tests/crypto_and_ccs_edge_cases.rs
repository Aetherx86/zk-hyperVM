use ark_ec::CurveGroup;
use ark_ff::{One, Zero};
use zkhypervm::ccs::{
    compute_eq_table, eval_eq, CCCSInstance, CCCSWitness, CCSStructure, LCCSInstance, MatrixEntry,
    SparseMatrix,
};
use zkhypervm::crypto::{Point, Scalar, SplitCommitment, SplitCommitmentParams, Transcript};

#[test]
fn test_zero_witness_commitment() {
    let params = SplitCommitmentParams::setup(3, 3, 3);
    let zero_w = vec![Scalar::zero(); 3];
    let comm = SplitCommitment::commit(&params, &zero_w, &zero_w, &zero_w);

    assert_eq!(comm.c_guest.into_affine(), Point::zero().into_affine());
    assert_eq!(comm.c_host.into_affine(), Point::zero().into_affine());
    assert_eq!(comm.c_logup.into_affine(), Point::zero().into_affine());
    assert_eq!(comm.total().into_affine(), Point::zero().into_affine());
}

#[test]
fn test_commitment_homomorphic_scaling_and_addition() {
    let params = SplitCommitmentParams::setup(2, 2, 2);
    let w1_g = vec![Scalar::from(5u64), Scalar::from(10u64)];
    let w1_h = vec![Scalar::from(15u64), Scalar::from(20u64)];
    let w1_l = vec![Scalar::from(25u64), Scalar::from(30u64)];

    let w2_g = vec![Scalar::from(2u64), Scalar::from(4u64)];
    let w2_h = vec![Scalar::from(6u64), Scalar::from(8u64)];
    let w2_l = vec![Scalar::from(10u64), Scalar::from(12u64)];

    let c1 = SplitCommitment::commit(&params, &w1_g, &w1_h, &w1_l);
    let c2 = SplitCommitment::commit(&params, &w2_g, &w2_h, &w2_l);

    // Test addition operator
    let c_sum = c1 + c2;
    let w_sum_g = vec![Scalar::from(7u64), Scalar::from(14u64)];
    let w_sum_h = vec![Scalar::from(21u64), Scalar::from(28u64)];
    let w_sum_l = vec![Scalar::from(35u64), Scalar::from(42u64)];
    let c_sum_expected = SplitCommitment::commit(&params, &w_sum_g, &w_sum_h, &w_sum_l);
    assert_eq!(
        c_sum.total().into_affine(),
        c_sum_expected.total().into_affine()
    );

    // Test folding by scalar factor alpha
    let alpha = Scalar::from(11u64);
    let c_folded = c1.fold(&c2, alpha);
    let w_folded_g: Vec<Scalar> = w1_g
        .iter()
        .zip(&w2_g)
        .map(|(a, b)| *a + alpha * b)
        .collect();
    let w_folded_h: Vec<Scalar> = w1_h
        .iter()
        .zip(&w2_h)
        .map(|(a, b)| *a + alpha * b)
        .collect();
    let w_folded_l: Vec<Scalar> = w1_l
        .iter()
        .zip(&w2_l)
        .map(|(a, b)| *a + alpha * b)
        .collect();
    let c_folded_expected = SplitCommitment::commit(&params, &w_folded_g, &w_folded_h, &w_folded_l);
    assert_eq!(
        c_folded.total().into_affine(),
        c_folded_expected.total().into_affine()
    );
}

#[test]
fn test_transcript_domain_separation_and_uniqueness() {
    let mut tr1 = Transcript::new("Domain-A");
    let mut tr2 = Transcript::new("Domain-B");

    let val = Scalar::from(0xDEADBEEFu64);
    tr1.absorb_scalar("input", &val);
    tr2.absorb_scalar("input", &val);

    let s1 = tr1.squeeze_scalar("challenge");
    let s2 = tr2.squeeze_scalar("challenge");

    // Two transcripts with distinct domain separators must yield distinct random challenges
    assert_ne!(s1, s2);

    // Multi-scalar squeeze must produce distinct non-zero values
    let mut tr3 = Transcript::new("Sequence-Domain");
    let scalars = tr3.squeeze_scalars("batch", 10);
    assert_eq!(scalars.len(), 10);
    for i in 0..scalars.len() {
        assert!(!scalars[i].is_zero());
        for j in (i + 1)..scalars.len() {
            assert_ne!(scalars[i], scalars[j]);
        }
    }
}

#[test]
fn test_ccs_high_degree_relations() {
    // Degree 3 constraint: w0 * w1 * w2 - x0 = 0
    // Variables: z = [w0, w1, w2, u, x0] (n = 5, l = 1, m = 1)
    let m0 = SparseMatrix::new(
        1,
        5,
        vec![MatrixEntry {
            row: 0,
            col: 0,
            val: Scalar::one(),
        }],
    );
    let m1 = SparseMatrix::new(
        1,
        5,
        vec![MatrixEntry {
            row: 0,
            col: 1,
            val: Scalar::one(),
        }],
    );
    let m2 = SparseMatrix::new(
        1,
        5,
        vec![MatrixEntry {
            row: 0,
            col: 2,
            val: Scalar::one(),
        }],
    );
    let m3 = SparseMatrix::new(
        1,
        5,
        vec![MatrixEntry {
            row: 0,
            col: 4,
            val: Scalar::one(),
        }],
    );

    let matrices = vec![m0, m1, m2, m3];
    let multisets = vec![vec![0, 1, 2], vec![3]];
    let coeffs = vec![Scalar::one(), -Scalar::one()];

    let ccs = CCSStructure::new(1, 5, 1, matrices, multisets, coeffs);

    // 2 * 3 * 5 = 30
    let w = vec![Scalar::from(2u64), Scalar::from(3u64), Scalar::from(5u64)];
    let x_valid = vec![Scalar::from(30u64)];
    let x_invalid = vec![Scalar::from(31u64)];

    assert!(ccs.is_satisfied(&w, &x_valid));
    assert!(!ccs.is_satisfied(&w, &x_invalid));

    // Tampered witness: changing w[0] from 2 to 7 -> 7 * 3 * 5 = 105 != 30
    let w_corrupted = vec![Scalar::from(7u64), Scalar::from(3u64), Scalar::from(5u64)];
    assert!(!ccs.is_satisfied(&w_corrupted, &x_valid));
}

#[test]
fn test_lccs_satisfaction_and_tamper_detection() {
    // Constraint: (w0 + w1) * w2 - (x0 + u) = 0
    // z = [w0, w1, w2, u, x0] (n = 5, l = 1, m = 1)
    let m0 = SparseMatrix::new(
        1,
        5,
        vec![
            MatrixEntry {
                row: 0,
                col: 0,
                val: Scalar::one(),
            },
            MatrixEntry {
                row: 0,
                col: 1,
                val: Scalar::one(),
            },
        ],
    );
    let m1 = SparseMatrix::new(
        1,
        5,
        vec![MatrixEntry {
            row: 0,
            col: 2,
            val: Scalar::one(),
        }],
    );
    let m2 = SparseMatrix::new(
        1,
        5,
        vec![
            MatrixEntry {
                row: 0,
                col: 3,
                val: Scalar::one(),
            },
            MatrixEntry {
                row: 0,
                col: 4,
                val: Scalar::one(),
            },
        ],
    );

    let ccs = CCSStructure::new(
        1,
        5,
        1,
        vec![m0, m1, m2],
        vec![vec![0, 1], vec![2]],
        vec![Scalar::one(), -Scalar::one()],
    );

    // w0 = 4, w1 = 6, w2 = 3. (4+6)*3 = 30.
    // u = 1, x0 = 29. 1 + 29 = 30.
    let w_guest = vec![Scalar::from(4u64)];
    let w_host = vec![Scalar::from(6u64)];
    let w_logup = vec![Scalar::from(3u64)];
    let cccs_wit = CCCSWitness {
        w_guest,
        w_host,
        w_logup,
    };
    let cccs_inst = CCCSInstance {
        c: SplitCommitment::zero(),
        x: vec![Scalar::from(29u64)],
    };

    let r_x = vec![Scalar::from(17u64)];
    let mut lccs = LCCSInstance::from_cccs(&ccs, &cccs_inst, &cccs_wit, &r_x);
    assert!(lccs.is_satisfied(&ccs, &cccs_wit));

    // Tamper 1: modify claimed evaluation v[0]
    let original_v0 = lccs.v[0];
    lccs.v[0] += Scalar::one();
    assert!(!lccs.is_satisfied(&ccs, &cccs_wit));
    lccs.v[0] = original_v0;

    // Tamper 2: modify evaluation challenge r_x
    let original_rx = lccs.r_x.clone();
    lccs.r_x[0] += Scalar::one();
    assert!(!lccs.is_satisfied(&ccs, &cccs_wit));
    lccs.r_x = original_rx;

    // Tamper 3: modify public multiplier u
    lccs.u += Scalar::one();
    assert!(!lccs.is_satisfied(&ccs, &cccs_wit));
}

#[test]
fn test_multilinear_equality_polynomial_properties() {
    let r = vec![Scalar::from(3u64), Scalar::from(7u64)];
    let table = compute_eq_table(&r, 4);
    assert_eq!(table.len(), 4);

    // The sum of eq(r, y) across the boolean hypercube y in {0, 1}^s must identically equal 1
    let sum: Scalar = table.iter().sum();
    assert_eq!(sum, Scalar::one());

    // Identity: eval_eq(r, r) matches formula prod(r_i^2 + (1-r_i)^2)
    let eq_rr = eval_eq(&r, &r);
    let expected =
        (Scalar::from(9u64) + Scalar::from(4u64)) * (Scalar::from(49u64) + Scalar::from(36u64));
    assert_eq!(eq_rr, expected);
}
