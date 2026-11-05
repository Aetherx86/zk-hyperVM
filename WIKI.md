# zk-HyperKVM and AegisForge Technical Architecture Wiki

## Table of Contents

- [1. Executive Architectural Overview](#1-executive-architectural-overview)
  - [1.1 Comparative Architectural Positioning Matrix](#11-comparative-architectural-positioning-matrix)
  - [1.2 Visual Constraint Reduction Comparison](#12-visual-constraint-reduction-comparison)
- [2. Polyglot Collaboration: How TypeScript, Rust, and Go Work Together](#2-polyglot-collaboration-how-typescript-rust-and-go-work-together)
  - [2.1 Domain Partitioning by Language Strengths](#21-domain-partitioning-by-language-strengths)
  - [2.2 Cross-Boundary Data Pipeline: Zero-Copy Arrow IPC](#22-cross-boundary-data-pipeline-zero-copy-arrow-ipc)
  - [2.3 High-Throughput Network Coordination via ConnectRPC / gRPC](#23-high-throughput-network-coordination-via-connectrpc--grpc)
- [3. Deep Dive: Subsystem Synergies](#3-deep-dive-subsystem-synergies)
  - [3.1 zk-HyperKVM Hardware Virtualization Engine (Rust)](#31-zk-hyperkvm-hardware-virtualization-engine-rust)
  - [3.2 AegisForge Hermetic Build Graph and Merkle Caching (Rust)](#32-aegisforge-hermetic-build-graph-and-merkle-caching-rust)
  - [3.3 Symbolic Formal Verification Engine (Rust + Z3 SMT)](#33-symbolic-formal-verification-engine-rust--z3-smt)
  - [3.4 Distributed Prover Plane and Worker Scheduler (Go)](#34-distributed-prover-plane-and-worker-scheduler-go)
  - [3.5 Type-Safe Circuit DSL and Verification Client (TypeScript)](#35-type-safe-circuit-dsl-and-verification-client-typescript)
- [4. End-to-End Pipeline Workflow: Verification to Proving](#4-end-to-end-pipeline-workflow-verification-to-proving)
- [5. Continuous Integration, Quality Gates, and Security Audits](#5-continuous-integration-quality-gates-and-security-audits)
  - [5.1 Multi-Language Audit Matrix](#51-multi-language-audit-matrix)
  - [5.2 Dual-OS Quality and Test Matrix](#52-dual-os-quality-and-test-matrix)
- [6. Development and Operational Guidelines](#6-development-and-operational-guidelines)

---

## 1. Executive Architectural Overview

Modern verifiable systems demand two distinct engineering capabilities that rarely coexist in a single language ecosystem:
1. Low-latency, memory-safe execution of cryptographic primitives, hardware emulation, and symbolic reasoning.
2. Distributed consensus, network multiplexing, and dynamic developer tooling with static type invariants.

This repository resolves this tension by deploying a synchronized triad of modern systems engineering:
- **TypeScript**: Declarative DSLs, abstract syntax tree (AST) compilation, and type-level invariant validation.
- **Go**: Distributed control plane, elastic worker orchestration, artifact caching, and Raft consensus.
- **Rust**: Bare-metal cryptographic compute, hardware-assisted virtualization (EPT/VMCS), SIMD-accelerated MSM/NTT arithmetic, and SMT solver bindings.

### 1.1 Comparative Architectural Positioning Matrix

| Architectural Dimension | zk-HyperKVM | User-Space zkVMs (RISC Zero, SP1) | Jolt (Lasso Lookups) | Valida (STARK/AIR) |
| :--- | :--- | :--- | :--- | :--- |
| **Target Execution Domain** | Ring -1 (Hypervisor), Ring 0 (Kernel), Ring 3 (User) | Ring 3 (User Space Only) | Ring 3 (User Space Only) | Ring 3 (User Space Only) |
| **Virtualization Extension** | Intel VT-x & AMD-V Dual-Mode (Root / Non-Root) | None (Flat RISC-V ISA Emulation) | None (RISC-V 32-bit ISA) | None (LLVM IR / Custom ISA) |
| **World-Switch Verification** | zk-VMCS Invariance Masks & Differential VMENTRY (34 constraints) | Not Supported (Requires 9,100+ R1CS constraints) | Not Supported | Not Supported |
| **Two-Dimensional Nested Paging**| 2D-EPT-LogUp (Collapses 24-step walk to O(1) fast-path TLB) | 1D Flat Merkle Memory Tree (Tens of thousands of hashes) | 1D Lasso Lookups | 1D Permutation Arguments |
| **DMA & Device I/O Verification**| Cryptographic IOMMU (VT-d Scalable Mode) & zk-VirtIO Tokens | Pre-image Hash Ingestion Only | In-Memory Buffers Only | In-Memory Buffers Only |
| **Transient Execution Defenses** | Explicit Barriers (L1D, IBPB, VERW) & L1TF Non-Zero PFN Masking | Not Supported | Not Supported | Not Supported |
| **Amortized Step Complexity** | 146.5 constraints (43.8x reduction) | ~6,418+ constraints / cycle | High cycle expansion for OS loops | High cycle expansion for OS loops |

### 1.2 Visual Constraint Reduction Comparison

```
Step Type                 Baseline R1CS    zk-HyperKVM (CCS)   Reduction Ratio
-------------------------------------------------------------------------------------------------
Guest Load/Store (C_2)    [==================================================] 18,432
                          [=] 114                                            161.7x Reduction

2D-EPT Page Walk (C_6)    [=================================================] 18,100
                          [==] 684                                           26.5x Reduction

KVM Exit Handler (C_4)    [========================] 9,120
                          [=] 428                                            21.3x Reduction

VMEXIT World Trap (C_3)   [==================] 6,840
                          [=] 312                                            21.9x Reduction

VMENTRY Checks (C_5)      [===============] 5,600
                          [=] 196                                            28.6x Reduction

Unprivileged ALU (C_1)    [=] 420
                          [=] 68                                             6.2x Reduction
-------------------------------------------------------------------------------------------------
Amortized Real OS Mix     [=================] 6,418
(Paper Section XI)        [=] 146.5                                          43.8x Amortized Reduction
```

---

## 2. Polyglot Collaboration: How TypeScript, Rust, and Go Work Together

The systems architecture avoids monolithic bloat by enforcing strict boundary minimization. Each language runtime operates exclusively within its optimal computational paradigm.

### 2.1 Domain Partitioning by Language Strengths

| Runtime | Operational Domain | Computational Paradigm | Zero-Overhead Guarantee |
| :--- | :--- | :--- | :--- |
| **TypeScript** | Client CLI, Circuit DSL, Schema Validation | Structural Type Theory & AST Compilation | Type checking occurs entirely at compile time; outputs emit static protobuf/Arrow schemas without runtime reflection overhead. |
| **Go** | Scheduler, Cluster Raft, Network Multiplexing | Communicating Sequential Processes (CSP) | Manages thousands of concurrent worker threads and network channels without managing byte-level numerical loops. |
| **Rust** | Hardware Emulation, ZK-Folding, SIMD MSM/NTT | Affine Ownership Semantics & Bare-Metal SIMD | Zero garbage-collection latency; cache-aligned structures execute at native silicon throughput. |

### 2.2 Cross-Boundary Data Pipeline: Zero-Copy Arrow IPC

Standard inter-process communication (IPC) frameworks introduce heavy serialization and deserialization penalties when passing millions of constraint variables or witness values.

AegisForge and zk-HyperKVM eliminate this bottleneck through Apache Arrow memory-mapped ring buffers:

```
+---------------------------+                +---------------------------+
|    Go Control Plane       |                |     Rust Compute Plane    |
|   (Task Orchestrator)     |                |  (zk-HyperKVM / Prover)   |
+---------------------------+                +---------------------------+
              |                                            |
              | 1. Allocate anonymous shared memory        |
              |    (shm_open / ftruncate)                  |
              |                                            |
              | 2. Serialize witness columns directly      |
              |    into Arrow record batch                 |
              |                                            |
              | 3. Pass file descriptor over Unix socket   |
              |    via SCM_RIGHTS                          |
              +------------------------------------------->|
                                                           | 4. Zero-copy mmap() into
                                                           |    Rust address space
                                                           |
                                                           | 5. Rayon SIMD workers read
                                                           |    native 256-bit scalars
```

- **Serialization Overhead**: Reduced from hundreds of milliseconds (JSON/Protobuf over standard sockets) to sub-millisecond memory-pointer remapping.
- **Memory Footprint**: Exactly zero duplicate memory allocations across the Go and Rust boundary.

### 2.3 High-Throughput Network Coordination via ConnectRPC / gRPC

All network control-plane communications between the developer client (TypeScript) and the cluster daemon (Go) rely on strongly typed Protocol Buffers schemas located in `proto/aegis/v1/`:
- `build.proto`: Hermetic build graph target evaluation and Merkle hash queries.
- `verify.proto`: Bytecode submission, SMT solver timeout limits, and counterexample extraction.
- `zkp.proto`: Circuit constraint commitment, witness batch dispatch, and proof verification.

---

## 3. Deep Dive: Subsystem Synergies

### 3.1 zk-HyperKVM Hardware Virtualization Engine (Rust)

zk-HyperKVM proves the correct execution of hardware-assisted virtual machine transitions. Key capabilities include:
- **Verifiable VMCS (zk-VMCS)**: Validates non-uniform world switches (VMEXIT / VMENTRY), checking architectural registers, host/guest state areas, and KVM CPUID instruction trapping policies.
- **Two-Dimensional Extended Page Table Bus (2D-EPT-LogUp)**: Verifies GVA-to-GPA-to-HPA nested translations using logarithmic derivative multiset lookup arguments, reducing translation verification costs by 43.8x.
- **Cryptographic IOMMU (zk-IOMMU)**: Constrains asynchronous Direct Memory Access (DMA) and device interrupt delivery.
- **Microarchitectural Sanitization**: Guarantees L1TF, Meltdown, and Spectre mitigation state invariants across world-switch boundaries.

### 3.2 AegisForge Hermetic Build Graph and Merkle Caching (Rust)

- Uses parallel BLAKE3 hashing across source files and configuration artifacts.
- Guarantees deterministic, content-addressed build environments. If source inputs or constraint declarations do not change, intermediate artifacts and proofs are served directly from cache.

### 3.3 Symbolic Formal Verification Engine (Rust + Z3 SMT)

- Translates circuit invariants and hypervisor transition functions into Static Single Assignment (SSA) form.
- Dispatches assertion logic to Z3 / CVC5 over native FFI. If an invariant can be breached, the engine generates the counterexample register witness trace prior to costly zero-knowledge proof generation.

### 3.4 Distributed Prover Plane and Worker Scheduler (Go)

- Implements an elastic, topological DAG scheduler that coordinates worker nodes.
- Balances folding batch proofs, multi-scalar multiplications (MSM), and number theoretic transforms (NTT) across multi-core servers and GPU clusters.

### 3.5 Type-Safe Circuit DSL and Verification Client (TypeScript)

- Provides developer ergonomics for specifying invariants and circuit constraints.
- Utilizes TypeScript conditional and mapped types to ensure that unsatisfied constraint paths produce static type errors prior to code submission.

---

## 4. End-to-End Pipeline Workflow: Verification to Proving

The combined pipeline executes in four disciplined phases:

```
[ Phase 1: Specification ]
  TypeScript Client compiles constraint specifications into high-level AST.
  Type-level invariants are checked; schema is sent to Go control plane.
       |
       v
[ Phase 2: Dependency & Cache Evaluation ]
  Go daemon evaluates topological DAG and queries Rust BLAKE3 Merkle engine.
  Unmodified sub-graphs return cached cryptographic commitments immediately.
       |
       v
[ Phase 3: Symbolic Pre-Verification ]
  Rust Verifier translates modified bytecode into SSA form.
  Z3 SMT solver verifies absence of underconstrained variables or policy breaches.
       |
       v
[ Phase 4: Parallel Prover Execution ]
  zk-HyperKVM executes VMCS transitions and generates 2D-EPT memory traces.
  Go scheduler feeds witness batches into Rust multi-threaded Rayon MSM/NTT kernels.
  Final succinct folding proof is assembled, verified, and saved to artifact cache.
```

---

## 5. Continuous Integration, Quality Gates, and Security Audits

The repository enforces end-to-end quality and security validation across all supported languages through GitHub Actions workflows.

### 5.1 Multi-Language Audit Matrix (`.github/workflows/audit.yml`)

The security workflow audits dependencies and code hygiene on a scheduled weekly basis and on pull requests:
- **Rust Audit**: Runs `cargo audit` against the RustSec Advisory Database, verifying zero vulnerable or unmaintained crate dependencies.
- **Go Audit**: Evaluates all Go modules dynamically via official `govulncheck` to catch known vulnerabilities in Go dependencies.
- **TypeScript Audit**: Audits all Node.js and TypeScript packages via `npm audit --audit-level=high`.
- **Dynamic Module Discovery**: Jobs automatically detect module presence (`go.mod`, `package.json`, `Cargo.lock`) so audits run cleanly whether deployed as a single crate or as an extended monorepo.

### 5.2 Dual-OS Quality and Test Matrix (`.github/workflows/ci.yml`)

The CI workflow executes on every commit across `ubuntu-latest` and `macos-latest`:
- **Repository Hygiene & Secret Scanning**: Gitleaks secret scan plus automated detection of git merge conflict markers.
- **Rust Quality Suite**:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - `cargo build --release --all-targets`
  - `cargo test --release --all-targets --all-features` (43 unit, integration, and property tests)
  - CLI command smoke tests (`run`, `prove`, `bench`)
- **Go Quality Suite**:
  - `go vet ./...`
  - `go test -v -race ./...` (Data race detector enabled)
  - `go build ./...`
- **TypeScript Quality Suite**:
  - Package dependency installation
  - Static type checking (`tsc --noEmit`)
  - Test and linter execution

---

## 6. Development and Operational Guidelines

1. **Deterministic Build Reproducibility**: All dependencies must be pinned in `Cargo.lock`, `go.sum`, or `package-lock.json`.
2. **Warning-Free Compilation**: The CI pipeline treats compiler and linter warnings as fatal errors (`-D warnings`).
3. **No Unsafe Code without Cryptographic Proof**: Unsafe memory operations in Rust are restricted to memory-mapped FFI boundaries and must be accompanied by explicit safety invariants.
