use zkhypervm::emulator::{GuestInstruction, HyperKvmInstance};
use zkhypervm::ept::{GuestPte, HostEpte};
use zkhypervm::folding::FoldingEngine;

fn setup_system() -> HyperKvmInstance {
    let eptp = 0x1000u64;
    let cr3 = 0x2000u64;
    let mut vm = HyperKvmInstance::new(1, cr3, eptp);

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

    // Host EPTE mappings for guest tables and data
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

    vm
}

#[test]
fn test_emulator_state_machine_and_stats() {
    let mut vm = setup_system();
    let mut engine = FoldingEngine::new();

    let program = [
        GuestInstruction::MovImm { dst: 1, imm: 42 },
        GuestInstruction::MovImm { dst: 2, imm: 58 },
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
        GuestInstruction::LoadMem {
            dst: 4,
            base: 7,
            offset: 0,
        },
        GuestInstruction::Sub {
            dst: 5,
            src1: 4,
            src2: 1,
        },
    ];

    for instr in &program {
        let step_res = vm.step(instr, &mut engine).unwrap();
        assert!(step_res);
    }

    assert_eq!(vm.read_gpr(1), 42);
    assert_eq!(vm.read_gpr(2), 58);
    assert_eq!(vm.read_gpr(3), 100);
    assert_eq!(vm.read_gpr(4), 100);
    assert_eq!(vm.read_gpr(5), 58);

    assert_eq!(vm.stats.alu_steps, 4);
    assert_eq!(vm.stats.mem_steps, 2);
    assert_eq!(vm.stats.tlb_hits, 1);
    assert_eq!(vm.stats.tlb_misses, 1);

    assert!(engine.verify_terminal_proof().is_ok());
}

#[test]
fn test_emulator_cpuid_world_switch_and_resume() {
    let mut vm = setup_system();
    let mut engine = FoldingEngine::new();

    // CPUID triggers VMEXIT -> Hypervisor Mediation -> VMENTRY
    let step_res = vm.step(&GuestInstruction::Cpuid, &mut engine).unwrap();
    assert!(step_res);

    // Verify CPUID hypervisor mediation returned standard synthetic values
    assert_eq!(vm.read_gpr(0), 0x0008_06EC); // RAX
    assert_eq!(vm.read_gpr(1), 0x7FFA_FBBF); // RCX
    assert_eq!(vm.read_gpr(2), 0xBFEF_FBFF); // RDX
    assert_eq!(vm.read_gpr(3), 0x0110_0800); // RBX

    assert_eq!(vm.stats.vmexit_count, 1);
    assert_eq!(vm.stats.hyper_med_steps, 1);
    assert_eq!(vm.stats.vmentry_count, 1);

    assert!(engine.verify_terminal_proof().is_ok());
}
