//! # zk-HyperKVM: Verifiable Hardware-Assisted Virtualization
//!
//! A high-performance Rust implementation of zk-HyperKVM based on:
//! "zk-HyperKVM: Verifiable Hardware-Assisted Virtualization via
//! Lookup-Accelerated Incremental Folding over Extended Page Tables and VMCS Transitions"
//! by Jeong Hoon Kim.
//!
//! ## Core Architecture:
//! - **zk-VMCS**: Algebraic encoding of the 63-element committed world-switch vector,
//!   hardware exit-invariance bitmasks `MaskInt(rho)`, and differential VM-Entry verification.
//! - **2D-EPT-LogUp**: Two-dimensional Second-Level Address Translation (SLAT)
//!   collapsing 24-step nested radix walks to amortized O(1) constraints via fast-path TLB.
//! - **Non-Uniform IVC Folding**: HyperNova-style split-witness multi-instance folding
//!   over the 7 specialized hypervisor transition circuits (`C_1` to `C_7`).
//! - **zk-VirtIO & zk-IOMMU**: Lockless Split Virtqueue capability minting/revocation
//!   and VT-d scalable mode cryptographic DMA attestation.
//! - **Microarchitectural Leakage Resilience**: Cross-domain hardware taint tracking,
//!   mandatory world-switch barriers (L1D_FLUSH, IBPB, VERW), and L1TF immunity.

pub mod ccs;
pub mod circuits;
pub mod crypto;
pub mod demo;
pub mod emulator;
pub mod ept;
pub mod extensions;
pub mod folding;
pub mod leakage;
pub mod logup;
pub mod virtio_iommu;
pub mod vmcs;

pub use circuits::CircuitId;
pub use crypto::Scalar;
pub use emulator::{GuestInstruction, HyperKvmInstance};
pub use folding::FoldingEngine;
