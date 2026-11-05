use ark_ff::{One, Zero};
use zkhypervm::ccs::{CCCSInstance, CCCSWitness};
use zkhypervm::circuits::{CircuitId, HyperKvmCircuitFamily};
use zkhypervm::crypto::{Scalar, SplitCommitment, SplitCommitmentParams};
use zkhypervm::folding::FoldingEngine;

fn make_dummy_instance_and_witness(
    family: &HyperKvmCircuitFamily,
    cid: CircuitId,
) -> (CCCSInstance, CCCSWitness) {
    let ccs = family.get_ccs(cid);
    let n_guest = ccs.n / 3;
    let n_host = ccs.n / 3;
    let n_logup = ccs.n - ccs.l - 1 - n_guest - n_host;

    let w_guest = vec![Scalar::zero(); n_guest];
    let w_host = vec![Scalar::zero(); n_host];
    let w_logup = vec![Scalar::zero(); n_logup];

    let params = SplitCommitmentParams::setup(n_guest, n_host, n_logup);
    let comm = SplitCommitment::commit(&params, &w_guest, &w_host, &w_logup);

    let inst = CCCSInstance {
        c: comm,
        x: vec![Scalar::zero(); ccs.l],
    };
    let wit = CCCSWitness {
        w_guest,
        w_host,
        w_logup,
    };
    (inst, wit)
}

#[test]
fn test_folding_across_all_seven_circuits() {
    let mut engine = FoldingEngine::new();
    let family = HyperKvmCircuitFamily::setup();

    // Round 1: Initialize accumulators for each of the 7 circuit families
    for id_idx in 0..7 {
        let cid = CircuitId::from_index(id_idx).unwrap();
        let (inst, wit) = make_dummy_instance_and_witness(&family, cid);
        assert!(engine
            .fold_step(
                cid,
                &inst,
                &wit,
                (
                    Scalar::zero(),
                    Scalar::zero(),
                    Scalar::zero(),
                    Scalar::zero()
                )
            )
            .is_ok());
    }

    assert_eq!(engine.state.step, 7);

    // Round 2: Fold a second instance into each of the 7 circuit accumulators
    for id_idx in 0..7 {
        let cid = CircuitId::from_index(id_idx).unwrap();
        let (inst, wit) = make_dummy_instance_and_witness(&family, cid);
        assert!(engine
            .fold_step(
                cid,
                &inst,
                &wit,
                (
                    Scalar::zero(),
                    Scalar::zero(),
                    Scalar::zero(),
                    Scalar::zero()
                )
            )
            .is_ok());
    }

    assert_eq!(engine.state.step, 14);

    // Terminal decider must accept proof
    assert!(engine.verify_terminal_proof().is_ok());
}

#[test]
fn test_decider_rejects_bus_imbalance() {
    let mut engine = FoldingEngine::new();
    let family = HyperKvmCircuitFamily::setup();

    let cid = CircuitId::GuestAlu;
    let (inst, wit) = make_dummy_instance_and_witness(&family, cid);

    // Step with non-cancelling bus delta (imbalance in TLB bus)
    let non_zero_delta = (
        Scalar::one(),
        Scalar::zero(),
        Scalar::zero(),
        Scalar::zero(),
    );
    assert!(engine.fold_step(cid, &inst, &wit, non_zero_delta).is_ok());

    // Terminal decider must strictly reject imbalanced bus
    let res = engine.verify_terminal_proof();
    assert!(res.is_err());
    assert_eq!(
        res.err().unwrap(),
        "Decider Verification Failed: LogUp bus accumulators do not balance to zero!"
    );
}

#[test]
fn test_decider_rejects_corrupted_witness() {
    let mut engine = FoldingEngine::new();
    let family = HyperKvmCircuitFamily::setup();

    let cid = CircuitId::GuestAlu;
    let (inst, wit) = make_dummy_instance_and_witness(&family, cid);
    assert!(engine
        .fold_step(
            cid,
            &inst,
            &wit,
            (
                Scalar::zero(),
                Scalar::zero(),
                Scalar::zero(),
                Scalar::zero()
            )
        )
        .is_ok());

    // Tamper with accumulated witness in the active circuit
    let k_idx = cid.index();
    if let Some(ref mut stored_wit) = engine.witnesses.witnesses[k_idx] {
        stored_wit.w_guest[0] += Scalar::from(42u64);
    }

    // Terminal decider must reject unsatisfied LCCS claim
    let res = engine.verify_terminal_proof();
    assert!(res.is_err());
    assert_eq!(
        res.err().unwrap(),
        "Decider Verification Failed: Folded LCCS accumulator unsatisfied!"
    );
}
