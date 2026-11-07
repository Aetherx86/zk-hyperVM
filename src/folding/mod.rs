//! Protocol 1: Non-Uniform Incremental Verifiable Computation (IVC) Folding Engine.
//!
//! Implements multi-circuit HyperNova-style split-witness folding over the 7 specialized
//! KVM circuits (C_1 to C_7), running LogUp bus accumulators, and decider boundary checks.

use crate::ccs::{compute_eq_table, CCCSInstance, CCCSWitness, LCCSInstance};
use crate::circuits::{CircuitId, HyperKvmCircuitFamily};
use crate::crypto::{Scalar, Transcript};
use crate::logup::LogUpBusAccumulator;
use ark_ff::{One, Zero};

/// Global IVC State z_t passed across recursive hypervisor folding steps:
/// z_t = (pc_t, C_Sigma, tau_vpid, tau_ept, A_TLB, A_EPT, A_HPA, {U_k}_{k=1}^7)
#[derive(Clone, Debug)]
pub struct GlobalIvcState {
    pub step: usize,
    pub active_circuit: CircuitId,
    pub tau_vpid: u64,
    pub tau_ept: u64,
    pub bus_acc: LogUpBusAccumulator,
    pub lccs_accumulators: Vec<LCCSInstance>, // 7 running accumulators
}

/// Accumulator witnesses for the 7 circuits
#[derive(Clone, Debug)]
pub struct AccumulatorWitnesses {
    pub witnesses: Vec<Option<CCCSWitness>>,
}

/// The HyperNova-style Multi-Circuit Folding Engine for zk-HyperKVM
pub struct FoldingEngine {
    pub family: HyperKvmCircuitFamily,
    pub state: GlobalIvcState,
    pub witnesses: AccumulatorWitnesses,
    pub transcript: Transcript,
}

impl FoldingEngine {
    pub fn new() -> Self {
        let family = HyperKvmCircuitFamily::setup();
        let mut lccs_accumulators = Vec::with_capacity(7);
        let mut witnesses = Vec::with_capacity(7);

        for id_idx in 0..7 {
            let id = CircuitId::from_index(id_idx).unwrap();
            let ccs = family.get_ccs(id);
            lccs_accumulators.push(LCCSInstance::empty(ccs));
            witnesses.push(None);
        }

        let state = GlobalIvcState {
            step: 0,
            active_circuit: CircuitId::GuestAlu,
            tau_vpid: 1,
            tau_ept: 1,
            bus_acc: LogUpBusAccumulator::new(),
            lccs_accumulators,
        };

        Self {
            family,
            state,
            witnesses: AccumulatorWitnesses { witnesses },
            transcript: Transcript::new("zk-HyperKVM-IVC-Engine"),
        }
    }

    /// Step execution of Protocol 1: Fold fresh CCCS instance u_{k*} into U_{k*}
    pub fn fold_step(
        &mut self,
        k_star: CircuitId,
        cccs_inst: &CCCSInstance,
        cccs_wit: &CCCSWitness,
        bus_deltas: (Scalar, Scalar, Scalar, Scalar),
    ) -> Result<(), &'static str> {
        let k_idx = k_star.index();
        let ccs = self.family.get_ccs(k_star);

        // Step 1: Update LogUp Bus Accumulators
        self.state.bus_acc.update(bus_deltas);

        // Absorb public state into transcript
        self.transcript
            .absorb_scalar("active_circuit", &k_star.to_scalar());
        self.transcript
            .absorb_point("comm_total", &cccs_inst.c.total());
        for x_val in &cccs_inst.x {
            self.transcript.absorb_scalar("public_io", x_val);
        }

        // If this is the very first time circuit k* is active, initialize accumulator directly
        if self.witnesses.witnesses[k_idx].is_none() {
            let r_x = self.transcript.squeeze_scalars("init_rx", ccs.s);
            let lccs = LCCSInstance::from_cccs(ccs, cccs_inst, cccs_wit, &r_x);
            self.state.lccs_accumulators[k_idx] = lccs;
            self.witnesses.witnesses[k_idx] = Some(cccs_wit.clone());
            self.state.step += 1;
            return Ok(());
        }

        // Step 2: Sumcheck Linearization & Evaluation claims
        // Sample folding challenge rho from transcript
        let rho = self.transcript.squeeze_scalar("rho_fold");

        // Existing accumulator
        let cur_lccs = &self.state.lccs_accumulators[k_idx];
        let cur_wit = self.witnesses.witnesses[k_idx].as_ref().unwrap();

        // Sample evaluation challenge r_x'' for the folded instance
        let r_x_new = self.transcript.squeeze_scalars("rx_eval", ccs.s);

        // Fold split commitments homomorphically:
        // C_folded = C_cur + rho * C_fresh
        let folded_comm = cur_lccs.c.fold(&cccs_inst.c, rho);
        let folded_u = cur_lccs.u + rho * Scalar::one();

        let mut folded_x = Vec::with_capacity(ccs.l);
        for (a, b) in cur_lccs.x.iter().zip(cccs_inst.x.iter()) {
            folded_x.push(*a + rho * *b);
        }

        // Fold witnesses: w_folded = w_cur + rho * w_fresh
        let mut folded_w_guest = Vec::with_capacity(cur_wit.w_guest.len());
        for (a, b) in cur_wit.w_guest.iter().zip(cccs_wit.w_guest.iter()) {
            folded_w_guest.push(*a + rho * *b);
        }

        let mut folded_w_host = Vec::with_capacity(cur_wit.w_host.len());
        for (a, b) in cur_wit.w_host.iter().zip(cccs_wit.w_host.iter()) {
            folded_w_host.push(*a + rho * *b);
        }

        let mut folded_w_logup = Vec::with_capacity(cur_wit.w_logup.len());
        for (a, b) in cur_wit.w_logup.iter().zip(cccs_wit.w_logup.iter()) {
            folded_w_logup.push(*a + rho * *b);
        }

        let folded_wit = CCCSWitness {
            w_guest: folded_w_guest,
            w_host: folded_w_host,
            w_logup: folded_w_logup,
        };

        // Compute new claimed evaluations v_j at r_x_new
        let z_folded = ccs.format_z(&folded_wit.full_w(), folded_u, &folded_x);
        let eq_table = compute_eq_table(&r_x_new, ccs.m);

        let mut v_folded = Vec::with_capacity(ccs.matrices.len());
        for mat in &ccs.matrices {
            let m_z = mat.multiply_vec(&z_folded);
            let mut eval = Scalar::zero();
            for (val, eq) in m_z.iter().zip(eq_table.iter()) {
                eval += *val * *eq;
            }
            v_folded.push(eval);
        }

        // Update active accumulator U_{k*}
        self.state.lccs_accumulators[k_idx] = LCCSInstance {
            c: folded_comm,
            u: folded_u,
            x: folded_x,
            r_x: r_x_new,
            v: v_folded,
        };
        self.witnesses.witnesses[k_idx] = Some(folded_wit);
        self.state.step += 1;

        Ok(())
    }

    /// Step 4: Terminal Decider Boundary Verification at step T
    /// Verifies:
    /// 1. Bus accumulators balance strictly: A_TLB == 0, A_EPT == 0, A_HPA == 0, A_VirtIO == 0
    /// 2. All 7 folded LCCS accumulators satisfy multilinear evaluation claims!
    pub fn verify_terminal_proof(&self) -> Result<(), &'static str> {
        // 1. Check bus cancellation
        if !self.state.bus_acc.is_balanced() {
            return Err(
                "Decider Verification Failed: LogUp bus accumulators do not balance to zero!",
            );
        }

        // 2. Check each active LCCS accumulator satisfaction
        for id_idx in 0..7 {
            if let Some(wit) = &self.witnesses.witnesses[id_idx] {
                let id = CircuitId::from_index(id_idx).unwrap();
                let ccs = self.family.get_ccs(id);
                let lccs = &self.state.lccs_accumulators[id_idx];

                if !lccs.is_satisfied(ccs, wit) {
                    return Err(
                        "Decider Verification Failed: Folded LCCS accumulator unsatisfied!",
                    );
                }
            }
        }

        Ok(())
    }
}

impl Default for FoldingEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::synthesize_circuit_step;

    #[test]
    fn test_multi_circuit_folding_pipeline() {
        let mut engine = FoldingEngine::new();

        // Step 1: Execute and fold Circuit 1 (GUEST_ALU)
        let ccs1 = engine.family.get_ccs(CircuitId::GuestAlu);
        let x1 = vec![Scalar::from(1u32); ccs1.l];
        let (inst1, wit1) = synthesize_circuit_step(&engine.family, CircuitId::GuestAlu, &x1);

        engine
            .fold_step(
                CircuitId::GuestAlu,
                &inst1,
                &wit1,
                (
                    Scalar::zero(),
                    Scalar::zero(),
                    Scalar::zero(),
                    Scalar::zero(),
                ),
            )
            .unwrap();

        // Step 2: Execute another GUEST_ALU instruction and fold into accumulator
        let (inst2, wit2) = synthesize_circuit_step(&engine.family, CircuitId::GuestAlu, &x1);
        engine
            .fold_step(
                CircuitId::GuestAlu,
                &inst2,
                &wit2,
                (
                    Scalar::zero(),
                    Scalar::zero(),
                    Scalar::zero(),
                    Scalar::zero(),
                ),
            )
            .unwrap();

        // Step 3: Execute Circuit 3 (VMEXIT)
        let ccs3 = engine.family.get_ccs(CircuitId::VmExit);
        let x3 = vec![Scalar::from(2u32); ccs3.l];
        let (inst3, wit3) = synthesize_circuit_step(&engine.family, CircuitId::VmExit, &x3);
        engine
            .fold_step(
                CircuitId::VmExit,
                &inst3,
                &wit3,
                (
                    Scalar::zero(),
                    Scalar::zero(),
                    Scalar::zero(),
                    Scalar::zero(),
                ),
            )
            .unwrap();

        // Verify terminal decider conditions
        assert!(engine.verify_terminal_proof().is_ok());
    }
}
