//! The inspector against hand-built binaries with known layouts, real executables, and garbage.

use zkhypervm_inspector::{inspect, Architecture, Block, EdgeKind, InspectError, Options};

fn block_at(blocks: &[Block], start: u64) -> &Block {
    blocks.iter().find(|b| b.start == start).unwrap_or_else(|| {
        panic!(
            "no block at {start:#x}: {:?}",
            blocks.iter().map(|b| b.start).collect::<Vec<_>>()
        )
    })
}

fn targets(block: &Block, kind: EdgeKind) -> Vec<u64> {
    block
        .successors
        .iter()
        .filter(|e| e.kind == kind)
        .map(|e| e.target)
        .collect()
}

fn raw(architecture: Architecture, code: &[u8]) -> zkhypervm_inspector::Report {
    let options = Options {
        force_architecture: Some(architecture),
        ..Options::default()
    };
    inspect(code, &options).unwrap()
}

/// `if (edi == 0) eax = 2; else eax = 1; return;`, a diamond with a known shape.
const X86_DIAMOND: &[u8] = &[
    0x55, // 0: push rbp
    0x85, 0xFF, // 1: test edi, edi
    0x74, 0x07, // 3: je 0xC
    0xB8, 0x01, 0x00, 0x00, 0x00, // 5: mov eax, 1
    0xEB, 0x05, // 0xA: jmp 0x11
    0xB8, 0x02, 0x00, 0x00, 0x00, // 0xC: mov eax, 2
    0x5D, // 0x11: pop rbp
    0xC3, // 0x12: ret
];

#[test]
fn x86_diamond_has_the_right_blocks_and_edges() {
    let report = raw(Architecture::X86_64, X86_DIAMOND);
    assert_eq!(report.blocks.len(), 4);
    let head = block_at(&report.blocks, 0);
    assert_eq!(targets(head, EdgeKind::Branch), [0xC]);
    assert_eq!(targets(head, EdgeKind::Fallthrough), [5]);
    let jumps = block_at(&report.blocks, 5);
    assert_eq!(targets(jumps, EdgeKind::Branch), [0x11]);
    assert_eq!(
        jumps.successors.len(),
        1,
        "an unconditional jump has no fallthrough edge"
    );
    assert_eq!(
        targets(block_at(&report.blocks, 0xC), EdgeKind::Fallthrough),
        [0x11]
    );
    let tail = block_at(&report.blocks, 0x11);
    assert!(tail.successors.is_empty());
    assert_eq!(tail.instructions.last().unwrap().text, "ret");
    assert_eq!(head.instructions[0].text, "push rbp");
    assert_eq!(head.instructions[0].bytes, "55");
}

#[test]
fn calls_are_followed_and_execution_continues_after_them() {
    let code = [
        0xE8, 0x01, 0x00, 0x00, 0x00, // 0: call 6
        0xC3, // 5: ret
        0xC3, // 6: ret
    ];
    let report = raw(Architecture::X86_64, &code);
    let first = block_at(&report.blocks, 0);
    assert_eq!(targets(first, EdgeKind::Call), [6]);
    assert!(
        report.blocks.iter().any(|b| b.start == 6),
        "the callee should be disassembled"
    );
    let reached_5 = report
        .blocks
        .iter()
        .flat_map(|b| &b.instructions)
        .any(|i| i.address == 5);
    assert!(reached_5, "code after a call should be reached");
}

#[test]
fn data_after_an_unconditional_jump_is_not_disassembled() {
    // The skipped bytes are valid instructions, so only the control flow can keep them out.
    let code = [0xEB, 0x02, 0x90, 0x90, 0xC3];
    let report = raw(Architecture::X86_64, &code);
    let addresses: Vec<u64> = report
        .blocks
        .iter()
        .flat_map(|b| &b.instructions)
        .map(|i| i.address)
        .collect();
    assert_eq!(addresses, [0, 4], "the bytes at 2 and 3 are not code");
}

#[test]
fn indirect_jumps_are_marked_unresolved() {
    let report = raw(Architecture::X86_64, &[0xFF, 0xE0]); // jmp rax
    assert_eq!(report.blocks[0].successors[0].kind, EdgeKind::Unresolved);
}

#[test]
fn loops_terminate_and_form_a_back_edge() {
    let code = [0x48, 0xFF, 0xC8, 0x75, 0xFB, 0xC3]; // dec rax; jne 0; ret
    let report = raw(Architecture::X86_64, &code);
    assert_eq!(targets(block_at(&report.blocks, 0), EdgeKind::Branch), [0]);
}

#[test]
fn x86_32_uses_the_right_bitness() {
    let report = raw(Architecture::X86, &[0x40, 0xC3]); // inc eax in 32-bit mode
    assert_eq!(report.blocks[0].instructions[0].text, "inc eax");
}

#[test]
fn riscv_control_flow_and_names_decode() {
    let code: Vec<u8> = [
        0x0015_0513u32, // 0: addi a0, a0, 1
        0x0005_0463,    // 4: beq a0, zero, 0xC
        0x00C0_00EF,    // 8: jal ra, 0x14
        0x0000_8067,    // 0xC: ret
        0x0000_8067,    // 0x10: not reached
        0x0000_8067,    // 0x14: ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let report = raw(Architecture::Riscv64, &code);
    let head = block_at(&report.blocks, 0);
    assert_eq!(head.instructions[0].text, "addi a0, a0, 1");
    assert_eq!(targets(head, EdgeKind::Branch), [0xC]);
    assert_eq!(targets(block_at(&report.blocks, 8), EdgeKind::Call), [0x14]);
    assert_eq!(block_at(&report.blocks, 0xC).instructions[0].text, "ret");
}

#[test]
fn riscv_compressed_instructions_have_the_right_length() {
    let code: Vec<u8> = [0x0505u16, 0x8082]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    let report = raw(Architecture::Riscv64, &code);
    let block = &report.blocks[0];
    assert_eq!(block.instructions.len(), 2);
    assert_eq!(block.instructions[1].address, 2);
    assert_eq!(block.instructions[1].text, "c.ret");
}

#[test]
fn aarch64_control_flow_decodes() {
    let code: Vec<u8> = [
        0xD280_0020u32, // 0: movz x0, #1
        0x5400_0060,    // 4: b.eq 0x10
        0x9400_0004,    // 8: bl 0x18
        0x1400_0002,    // 0xC: b 0x14
        0xD503_201F,    // 0x10: nop
        0xD65F_03C0,    // 0x14: ret
        0xD65F_03C0,    // 0x18: ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let report = raw(Architecture::Aarch64, &code);
    let head = block_at(&report.blocks, 0);
    assert_eq!(targets(head, EdgeKind::Branch), [0x10]);
    assert_eq!(head.instructions[1].text, "b.eq 0x10");
    assert_eq!(targets(block_at(&report.blocks, 8), EdgeKind::Call), [0x18]);
    assert_eq!(
        targets(block_at(&report.blocks, 8), EdgeKind::Branch),
        [0x14]
    );
    assert_eq!(block_at(&report.blocks, 0x14).instructions[0].text, "ret");
}

#[test]
fn aarch64_authenticated_branches_flow_like_plain_ones() {
    // blraa x8, x9; nop; braaz x16 and then a nop that must not be decoded.
    let mut code = Vec::new();
    for word in [0xD73F_0909u32, 0xD503_201F, 0xD61F_0A1F, 0xD503_201F] {
        code.extend_from_slice(&word.to_le_bytes());
    }
    let report = raw(Architecture::Aarch64, &code);
    let text: Vec<&str> = report
        .blocks
        .iter()
        .flat_map(|b| &b.instructions)
        .map(|i| i.text.as_str())
        .collect();
    assert_eq!(
        text,
        ["blraa x8", "nop", "braa x16"],
        "execution continues after the call"
    );

    // retab, whose fixed fields look nothing like the plain form.
    let report = raw(Architecture::Aarch64, &0xD65F_0FFFu32.to_le_bytes());
    assert_eq!(report.blocks[0].instructions[0].text, "retab");
    assert!(report.blocks[0].successors.is_empty());
}

#[test]
fn common_aarch64_forms_are_readable() {
    let cases: [(u32, &str); 10] = [
        (0xA9BF_7BFD, "stp x29, x30, [sp, #-16]!"),
        (0xA8C1_7BFD, "ldp x29, x30, [sp], #16"),
        (0xF940_0020, "ldr x0, [x1, #0]"),
        (0xB900_0422, "str w2, [x1, #4]"),
        (0xAA01_03E0, "mov x0, x1"),
        (0x7100_041F, "cmp w0, #0x1"),
        (0xF100_041F, "cmp x0, #0x1"),
        (0xD503_233F, "paciasp"),
        (0x1000_0040, "adr x0, 0x8"),
        (0x9000_0000, "adrp x0, 0x0"),
    ];
    for (word, expected) in cases {
        let mut code = word.to_le_bytes().to_vec();
        code.extend_from_slice(&0xD65F_03C0u32.to_le_bytes());
        let report = raw(Architecture::Aarch64, &code);
        assert_eq!(report.blocks[0].instructions[0].text, expected);
    }
}

/// Builds a minimal ELF64 whose single segment and section hold [`X86_DIAMOND`].
fn build_elf(code: &[u8], machine: u16) -> Vec<u8> {
    let base = 0x40_0000u64;
    let code_offset = 64 + 56;
    let names = b"\0.text\0.shstrtab\0";
    let names_offset = code_offset + code.len();
    let sh_offset = names_offset + names.len();

    let mut f = Vec::new();
    f.extend_from_slice(b"\x7FELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
    f.extend_from_slice(&2u16.to_le_bytes());
    f.extend_from_slice(&machine.to_le_bytes());
    f.extend_from_slice(&1u32.to_le_bytes());
    f.extend_from_slice(&(base + code_offset as u64).to_le_bytes());
    f.extend_from_slice(&64u64.to_le_bytes());
    f.extend_from_slice(&(sh_offset as u64).to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes());
    for value in [64u16, 56, 1, 64, 3, 2] {
        f.extend_from_slice(&value.to_le_bytes());
    }
    f.extend_from_slice(&1u32.to_le_bytes());
    f.extend_from_slice(&5u32.to_le_bytes());
    f.extend_from_slice(&(code_offset as u64).to_le_bytes());
    f.extend_from_slice(&(base + code_offset as u64).to_le_bytes());
    f.extend_from_slice(&(base + code_offset as u64).to_le_bytes());
    f.extend_from_slice(&(code.len() as u64).to_le_bytes());
    f.extend_from_slice(&(code.len() as u64).to_le_bytes());
    f.extend_from_slice(&0x1000u64.to_le_bytes());
    f.extend_from_slice(code);
    f.extend_from_slice(names);

    let mut section = |name: u32, kind: u32, flags: u64, addr: u64, offset: u64, size: u64| {
        f.extend_from_slice(&name.to_le_bytes());
        f.extend_from_slice(&kind.to_le_bytes());
        f.extend_from_slice(&flags.to_le_bytes());
        f.extend_from_slice(&addr.to_le_bytes());
        f.extend_from_slice(&offset.to_le_bytes());
        f.extend_from_slice(&size.to_le_bytes());
        f.extend_from_slice(&[0u8; 24]);
    };
    section(0, 0, 0, 0, 0, 0);
    section(
        1,
        1,
        6,
        base + code_offset as u64,
        code_offset as u64,
        code.len() as u64,
    );
    section(7, 3, 0, 0, names_offset as u64, names.len() as u64);
    f
}

#[test]
fn elf_files_map_code_to_its_virtual_address() {
    let file = build_elf(X86_DIAMOND, 62);
    let report = inspect(&file, &Options::default()).unwrap();
    assert_eq!(report.format, "ELF64");
    assert_eq!(report.architecture, Architecture::X86_64);
    let entry = 0x40_0000 + 120;
    assert_eq!(report.entry, Some(entry));
    assert_eq!(report.blocks.len(), 4);
    assert_eq!(report.blocks[0].start, entry);
    let text = report
        .sections
        .iter()
        .find(|s| s.name == ".text")
        .expect(".text should be named");
    assert!(text.executable);
    assert_eq!(text.size, X86_DIAMOND.len() as u64);
}

/// An ELF file with code, data, and a symbol table with a function symbol in each of them.
///
/// A helper function follows the diamond in `.text`, and nothing but its symbol reaches it. Both the
/// helper and the data decode as valid instructions, and one segment maps them both, so only the
/// section flags can tell them apart.
fn build_elf_with_symbols() -> (Vec<u8>, u64, u64) {
    const HEADERS: usize = 64 + 56;
    let base = 0x40_0000u64;
    let helper = [0x90, 0xC3];
    let data = [0x90, 0xC3];
    let mut code = X86_DIAMOND.to_vec();
    let helper_offset = HEADERS + code.len();
    code.extend_from_slice(&helper);
    let data_offset = HEADERS + code.len();
    let symtab_offset = data_offset + data.len();
    let strings = b"\0helper\0decoy\0";
    let strtab_offset = symtab_offset + 3 * 24;
    let names = b"\0.text\0.data\0.symtab\0.strtab\0.shstrtab\0";
    let names_offset = strtab_offset + strings.len();
    let sh_offset = names_offset + names.len();
    let address = |offset: usize| base + offset as u64;

    let mut f = Vec::new();
    f.extend_from_slice(b"\x7FELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
    f.extend_from_slice(&2u16.to_le_bytes());
    f.extend_from_slice(&62u16.to_le_bytes());
    f.extend_from_slice(&1u32.to_le_bytes());
    f.extend_from_slice(&address(HEADERS).to_le_bytes());
    f.extend_from_slice(&64u64.to_le_bytes());
    f.extend_from_slice(&(sh_offset as u64).to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes());
    for value in [64u16, 56, 1, 64, 6, 5] {
        f.extend_from_slice(&value.to_le_bytes());
    }
    let mapped = (symtab_offset - HEADERS) as u64;
    f.extend_from_slice(&1u32.to_le_bytes());
    f.extend_from_slice(&5u32.to_le_bytes());
    f.extend_from_slice(&(HEADERS as u64).to_le_bytes());
    f.extend_from_slice(&address(HEADERS).to_le_bytes());
    f.extend_from_slice(&address(HEADERS).to_le_bytes());
    f.extend_from_slice(&mapped.to_le_bytes());
    f.extend_from_slice(&mapped.to_le_bytes());
    f.extend_from_slice(&0x1000u64.to_le_bytes());
    f.extend_from_slice(&code);
    f.extend_from_slice(&data);

    let mut symbol = |name: u32, value: u64| {
        f.extend_from_slice(&name.to_le_bytes());
        // Global binding, and type 2 for a function.
        f.extend_from_slice(&[0x12, 0]);
        f.extend_from_slice(&1u16.to_le_bytes());
        f.extend_from_slice(&value.to_le_bytes());
        f.extend_from_slice(&2u64.to_le_bytes());
    };
    symbol(0, 0);
    symbol(1, address(helper_offset));
    symbol(8, address(data_offset));
    f.extend_from_slice(strings);
    f.extend_from_slice(names);

    let mut section =
        |name: u32, kind: u32, flags: u64, addr: u64, offset: usize, size: usize, link: u32| {
            f.extend_from_slice(&name.to_le_bytes());
            f.extend_from_slice(&kind.to_le_bytes());
            f.extend_from_slice(&flags.to_le_bytes());
            f.extend_from_slice(&addr.to_le_bytes());
            f.extend_from_slice(&(offset as u64).to_le_bytes());
            f.extend_from_slice(&(size as u64).to_le_bytes());
            f.extend_from_slice(&link.to_le_bytes());
            f.extend_from_slice(&[0u8; 20]);
        };
    section(0, 0, 0, 0, 0, 0, 0);
    section(1, 1, 6, address(HEADERS), HEADERS, code.len(), 0);
    section(7, 1, 3, address(data_offset), data_offset, data.len(), 0);
    section(13, 2, 0, 0, symtab_offset, 3 * 24, 4);
    section(21, 3, 0, 0, strtab_offset, strings.len(), 0);
    section(29, 3, 0, 0, names_offset, names.len(), 0);
    (f, address(helper_offset), address(data_offset))
}

#[test]
fn function_symbols_only_start_code_in_executable_sections() {
    let (file, helper, data) = build_elf_with_symbols();
    let report = inspect(&file, &Options::default()).unwrap();
    assert_eq!(report.symbols.len(), 2, "both symbols are still reported");
    let starts: Vec<u64> = report.blocks.iter().map(|b| b.start).collect();
    assert!(
        starts.contains(&helper),
        "a symbol in code starts a block: {starts:#x?}"
    );
    assert!(
        !starts.contains(&data),
        "a symbol in data must not be decoded: {starts:#x?}"
    );
}

#[test]
fn elf_files_for_unknown_machines_still_report_structure() {
    let report = inspect(&build_elf(&[0; 16], 8), &Options::default()).unwrap();
    assert!(matches!(report.architecture, Architecture::Unknown(_)));
    assert!(report.blocks.is_empty());
    assert!(report.sections.iter().any(|s| s.name == ".text"));
    assert!(!report.notes.is_empty());
}

fn build_pe(code: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 0x40];
    f[0] = b'M';
    f[1] = b'Z';
    f[0x3C] = 0x40;
    f.extend_from_slice(b"PE\0\0");
    f.extend_from_slice(&0x8664u16.to_le_bytes());
    f.extend_from_slice(&1u16.to_le_bytes());
    f.extend_from_slice(&[0u8; 12]);
    f.extend_from_slice(&240u16.to_le_bytes());
    f.extend_from_slice(&0x22u16.to_le_bytes());
    let mut optional = vec![0u8; 240];
    optional[0..2].copy_from_slice(&0x20Bu16.to_le_bytes());
    optional[16..20].copy_from_slice(&0x1000u32.to_le_bytes());
    optional[24..32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    f.extend_from_slice(&optional);
    f.extend_from_slice(b".text\0\0\0");
    f.extend_from_slice(&(code.len() as u32).to_le_bytes());
    f.extend_from_slice(&0x1000u32.to_le_bytes());
    f.extend_from_slice(&(code.len() as u32).to_le_bytes());
    let offset = f.len() as u32 + 20;
    f.extend_from_slice(&offset.to_le_bytes());
    f.extend_from_slice(&[0u8; 12]);
    f.extend_from_slice(&0x6000_0020u32.to_le_bytes());
    f.extend_from_slice(code);
    f
}

#[test]
fn pe_files_map_code_through_the_image_base() {
    let report = inspect(&build_pe(X86_DIAMOND), &Options::default()).unwrap();
    assert_eq!(report.format, "PE32+");
    assert_eq!(report.architecture, Architecture::X86_64);
    assert_eq!(report.entry, Some(0x1_4000_1000));
    assert_eq!(report.blocks.len(), 4);
    assert_eq!(report.sections[0].name, ".text");
    assert!(report.sections[0].executable);
}

#[test]
fn evm_jump_targets_resolve_through_push() {
    // PUSH1 4; JUMP; INVALID; JUMPDEST; STOP
    let report = inspect(b"0x600456fe5b00", &Options::default()).unwrap();
    assert_eq!(report.architecture, Architecture::Evm);
    let head = block_at(&report.blocks, 0);
    assert_eq!(targets(head, EdgeKind::Branch), [4]);
    assert_eq!(head.instructions[0].text, "PUSH1 0x04");
    assert_eq!(block_at(&report.blocks, 4).instructions[0].text, "JUMPDEST");
}

#[test]
fn evm_push_data_is_never_a_jump_destination() {
    // PUSH2 0x5B5B holds bytes that look like JUMPDESTs, and the jump to 1 lands inside them.
    let report = inspect(b"615b5b60015600", &Options::default()).unwrap();
    assert_eq!(report.blocks.len(), 2);
    assert_eq!(
        report.blocks[0].successors[0].kind,
        EdgeKind::Unresolved,
        "a jump into push data is not a valid edge"
    );
}

#[test]
fn evm_conditional_jumps_have_two_successors() {
    // PUSH1 1; PUSH1 6; JUMPI; STOP; JUMPDEST; STOP
    let report = inspect(b"6001600657005b00", &Options::default()).unwrap();
    let head = block_at(&report.blocks, 0);
    assert_eq!(targets(head, EdgeKind::Fallthrough), [5]);
    assert_eq!(targets(head, EdgeKind::Branch), [6]);
    assert_eq!(report.ir[0].statements, ["if 0x1 goto 0x6"]);
}

#[test]
fn evm_lifting_recovers_expressions() {
    // CALLVALUE; PUSH1 2; ADD; PUSH1 0; SSTORE; STOP
    let report = inspect(b"346002016000555b00", &Options::default()).unwrap();
    let statements = &report.ir[0].statements;
    assert_eq!(statements[0], "v0 = CALLVALUE()");
    assert_eq!(statements[1], "v1 = ADD(0x2, v0)");
    assert_eq!(statements[2], "SSTORE(0x0, v1)");
}

#[test]
fn evm_lifting_names_values_from_before_the_block() {
    // POP takes a value this block never pushed. DUP2 and SWAP1 reach further down.
    let report = inspect(b"508190015b00", &Options::default()).unwrap();
    let statements = &report.ir[0].statements;
    assert_eq!(statements[0], "POP(s0)");
    assert_eq!(statements[1], "v0 = ADD(s1, s2)");
}

#[test]
fn evm_truncated_push_at_the_end_of_the_code_is_tolerated() {
    let report = inspect(b"61", &Options::default()).unwrap();
    assert_eq!(report.blocks[0].instructions[0].text, "PUSH2 0x");
}

#[test]
fn evm_unknown_opcodes_are_reported_and_do_not_crash() {
    let report = inspect(b"0c0d0e0f21", &Options::default()).unwrap();
    assert!(report.blocks[0].instructions[0].text.starts_with("UNKNOWN"));
}

#[test]
fn every_evm_byte_value_disassembles() {
    let code: Vec<u8> = (0..=255u8).collect();
    let options = Options {
        force_architecture: Some(Architecture::Evm),
        ..Options::default()
    };
    let report = inspect(&code, &options).unwrap();
    assert!(!report.blocks.is_empty());
}

#[test]
fn the_instruction_limit_is_respected() {
    let code = vec![0x90u8; 10_000];
    let options = Options {
        force_architecture: Some(Architecture::X86_64),
        max_instructions: 100,
        ..Options::default()
    };
    let report = inspect(&code, &options).unwrap();
    assert!(report.truncated);
    let count: usize = report.blocks.iter().map(|b| b.instructions.len()).sum();
    assert_eq!(count, 100);
}

#[test]
fn unknown_inputs_are_rejected_clearly() {
    assert_eq!(inspect(b"", &Options::default()), Err(InspectError::Empty));
    assert_eq!(
        inspect(b"hello there", &Options::default()),
        Err(InspectError::UnknownFormat)
    );
    assert_eq!(
        inspect(b"abc", &Options::default()),
        Err(InspectError::UnknownFormat),
        "odd-length hex"
    );
}

/// A real compiled program, which is this test binary itself, in the host's native format.
#[test]
fn real_executables_parse_and_disassemble() {
    let path = std::env::current_exe().unwrap();
    let bytes = std::fs::read(path).unwrap();
    let report = inspect(&bytes, &Options::default()).unwrap();
    assert!(!report.sections.is_empty(), "a real binary has sections");
    assert!(
        report.sections.iter().any(|s| s.executable),
        "and at least one has code"
    );
    if cfg!(target_os = "linux") {
        assert_eq!(report.format, "ELF64");
    }
    if cfg!(target_os = "windows") {
        assert_eq!(report.format, "PE32+");
    }
    if cfg!(target_os = "macos") {
        assert_eq!(report.format, "Mach-O 64");
    }
    assert!(
        report.entry.is_some(),
        "a real executable has an entry point"
    );
    // Mach-O names its own header with a symbol, which must not be mistaken for code.
    let first = report.blocks[0].start;
    assert!(
        report
            .sections
            .iter()
            .any(|s| s.executable && (s.address..s.address + s.size).contains(&first)),
        "the first block at {first:#x} is outside every executable section"
    );
    let instructions: usize = report.blocks.iter().map(|b| b.instructions.len()).sum();
    assert!(
        instructions > 100,
        "only {instructions} instructions were found"
    );
}

/// A tight budget has to go to the entry point first, whatever other symbols the binary has.
#[test]
fn the_entry_point_is_decoded_even_when_the_budget_is_tight() {
    let bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let options = Options {
        max_instructions: 50,
        ..Options::default()
    };
    let report = inspect(&bytes, &options).unwrap();
    let entry = report.entry.expect("a real executable has an entry point");
    assert!(
        report.blocks.iter().any(|b| b.start == entry),
        "the entry point {entry:#x} was not disassembled"
    );
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn small_options() -> Options {
    Options {
        max_instructions: 2_000,
        ..Options::default()
    }
}

/// Damages valid files in many ways. An error is fine, and any panic fails the test.
#[test]
fn damaged_files_never_panic() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);
    let samples = [build_elf(X86_DIAMOND, 62), build_pe(X86_DIAMOND)];
    for sample in &samples {
        for _ in 0..4000 {
            let mut file = sample.clone();
            for _ in 0..(1 + rng.next() % 8) {
                let at = rng.next() as usize % file.len();
                file[at] = match rng.next() % 4 {
                    0 => 0xFF,
                    1 => 0,
                    2 => 0x7F,
                    _ => rng.next() as u8,
                };
            }
            if rng.next().is_multiple_of(4) {
                file.truncate(rng.next() as usize % file.len());
            }
            let _ = inspect(&file, &small_options());
        }
    }
}

/// The same for a real binary, where every header field is reachable.
#[test]
fn damaged_real_executables_never_panic() {
    let bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let head = &bytes[..bytes.len().min(16 * 1024)];
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    for _ in 0..1500 {
        let mut file = head.to_vec();
        for _ in 0..(1 + rng.next() % 16) {
            let at = rng.next() as usize % 4096.min(file.len());
            file[at] = rng.next() as u8;
        }
        let _ = inspect(&file, &small_options());
    }
}

#[test]
fn random_bytes_never_panic_in_any_decoder() {
    let mut rng = Rng(0xABCD_EF01_2345_6789);
    let architectures = [
        Architecture::X86,
        Architecture::X86_64,
        Architecture::Aarch64,
        Architecture::Riscv64,
        Architecture::Evm,
    ];
    for _ in 0..1000 {
        let code: Vec<u8> = (0..(rng.next() % 512)).map(|_| rng.next() as u8).collect();
        for architecture in &architectures {
            let options = Options {
                force_architecture: Some(architecture.clone()),
                max_instructions: 500,
                extra_roots: vec![rng.next() % 512, u64::MAX, u64::MAX - 3],
            };
            if !code.is_empty() {
                let _ = inspect(&code, &options);
            }
        }
    }
}

#[test]
fn magic_numbers_alone_do_not_panic() {
    let magics: [&[u8]; 6] = [
        b"\x7FELF",
        b"\x7FELF\x02\x01",
        b"MZ",
        &[0xCF, 0xFA, 0xED, 0xFE],
        &[0xCA, 0xFE, 0xBA, 0xBE],
        &[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 200],
    ];
    for magic in magics {
        assert!(inspect(magic, &Options::default()).is_err());
    }
}
