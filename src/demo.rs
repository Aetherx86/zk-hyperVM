//! The guest environment used by the command line and by the browser workbench: a VM whose nested
//! page tables map a small region of guest memory, and a program that exercises all of the
//! hypervisor's transition circuits.

use crate::emulator::{GuestInstruction, HyperKvmInstance};
use crate::ept::{GuestPte, HostEpte};

/// Builds the demonstration VM and its guest program.
pub fn demo_environment() -> (HyperKvmInstance, Vec<GuestInstruction>) {
    let eptp = 0x1000u64;
    let cr3 = 0x2000u64;
    let mut vm = HyperKvmInstance::new(1, cr3, eptp);

    // Host EPT 4-level radix tree setup
    let epte_base = HostEpte {
        raw: 0,
        read: true,
        write: true,
        execute: true,
        mem_type: 6,
        ignore_pat: false,
        page_size: false,
        accessed: true,
        dirty: true,
        execute_user: true,
        hfn: 2,
        suppress_ve: false,
    };
    vm.memory.write_hpa_word(0x1000, epte_base.encode());
    vm.memory.write_hpa_word(
        0x2000,
        HostEpte {
            hfn: 3,
            ..epte_base
        }
        .encode(),
    );
    vm.memory.write_hpa_word(
        0x3000,
        HostEpte {
            hfn: 4,
            ..epte_base
        }
        .encode(),
    );

    // Host EPTE mappings
    vm.memory.write_hpa_word(
        0x4000 + 2 * 8,
        HostEpte {
            hfn: 10,
            ..epte_base
        }
        .encode(),
    );
    vm.memory.write_hpa_word(
        0x4000 + 5 * 8,
        HostEpte {
            hfn: 20,
            ..epte_base
        }
        .encode(),
    );
    vm.memory.write_hpa_word(
        0x4000 + 6 * 8,
        HostEpte {
            hfn: 30,
            ..epte_base
        }
        .encode(),
    );
    vm.memory.write_hpa_word(
        0x4000 + 7 * 8,
        HostEpte {
            hfn: 40,
            ..epte_base
        }
        .encode(),
    );
    vm.memory.write_hpa_word(
        0x4000 + 8 * 8,
        HostEpte {
            hfn: 50,
            ..epte_base
        }
        .encode(),
    );

    // Guest page tables
    let guest_pte_base = GuestPte {
        raw: 0,
        present: true,
        read_write: true,
        user_supervisor: true,
        page_write_through: false,
        page_cache_disable: false,
        accessed: true,
        dirty: true,
        page_size: false,
        global: false,
        gfn: 5,
        no_execute: false,
    };
    vm.memory.write_hpa_word(10 << 12, guest_pte_base.encode());
    vm.memory.write_hpa_word(
        20 << 12,
        GuestPte {
            gfn: 6,
            ..guest_pte_base
        }
        .encode(),
    );
    vm.memory.write_hpa_word(
        30 << 12,
        GuestPte {
            gfn: 7,
            ..guest_pte_base
        }
        .encode(),
    );
    vm.memory.write_hpa_word(
        40 << 12,
        GuestPte {
            gfn: 8,
            ..guest_pte_base
        }
        .encode(),
    );

    // Set GVA in R7 (RDI)
    vm.write_gpr(7, 0x0048);

    let program = vec![
        GuestInstruction::MovImm { dst: 1, imm: 100 },
        GuestInstruction::MovImm { dst: 2, imm: 250 },
        GuestInstruction::Add {
            dst: 3,
            src1: 1,
            src2: 2,
        },
        GuestInstruction::StoreMem {
            src: 3,
            base: 7,
            offset: 0,
        },
        GuestInstruction::Cpuid,
        GuestInstruction::LoadMem {
            dst: 4,
            base: 7,
            offset: 0,
        },
        GuestInstruction::VirtioKick { queue_id: 0 },
        GuestInstruction::Vmcall,
        GuestInstruction::Sub {
            dst: 5,
            src1: 4,
            src2: 1,
        },
    ];

    (vm, program)
}
