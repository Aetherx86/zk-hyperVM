//! Witness generation and checking that runs anywhere, including inside a browser tab.
//!
//! This crate has no platform dependencies. It uses no clock, threads or filesystem, so proofs can
//! be computed on the client, without sending any private input to a server.
//!
//! - [`program`] runs guest programs under the verifiable hypervisor and folds their execution.
//! - [`circom`] reads circuits and witnesses produced by Circom, checks them, and converts them to
//!   the CCS form that zk-HyperKVM's folding scheme uses.

pub mod circom;
pub mod program;
