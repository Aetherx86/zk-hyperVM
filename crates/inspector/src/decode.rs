//! Instruction decoders. Each one reports the text of an instruction and how control leaves it,
//! which is all that building a control-flow graph needs.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, NasmFormatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Next,
    Jump(u64),
    Branch(u64),
    Call(u64),
    Return,
    IndirectJump,
    IndirectCall,
    Stop,
}

pub struct Decoded {
    pub length: usize,
    pub text: String,
    pub flow: Flow,
}

pub fn decode_x86(bytes: &[u8], address: u64, bitness: u32) -> Option<Decoded> {
    let window = &bytes[..bytes.len().min(15)];
    let mut decoder = Decoder::with_ip(bitness, window, address, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    if !decoder.can_decode() {
        return None;
    }
    decoder.decode_out(&mut instruction);
    if instruction.is_invalid() {
        return None;
    }
    let mut formatter = NasmFormatter::new();
    let mut text = String::new();
    formatter.format(&instruction, &mut text);
    let flow = match instruction.flow_control() {
        FlowControl::Next | FlowControl::XbeginXabortXend => Flow::Next,
        FlowControl::UnconditionalBranch => Flow::Jump(instruction.near_branch_target()),
        FlowControl::ConditionalBranch => Flow::Branch(instruction.near_branch_target()),
        FlowControl::Call => Flow::Call(instruction.near_branch_target()),
        FlowControl::Return => Flow::Return,
        FlowControl::IndirectBranch => Flow::IndirectJump,
        FlowControl::IndirectCall => Flow::IndirectCall,
        FlowControl::Interrupt | FlowControl::Exception => Flow::Stop,
    };
    Some(Decoded {
        length: instruction.len(),
        text,
        flow,
    })
}

const RV_NAMES: [&str; 32] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
    "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
    "t5", "t6",
];

fn sign_extend(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

/// RISC-V RV64I and M. Compressed instructions are recognized by length, with only their control
/// flow decoded, because that is what keeps the graph correct.
pub fn decode_riscv(bytes: &[u8], address: u64) -> Option<Decoded> {
    if bytes.len() < 2 {
        return None;
    }
    let low = u16::from_le_bytes([bytes[0], bytes[1]]);
    if low & 3 != 3 {
        return Some(decode_riscv_compressed(low, address));
    }
    let raw = bytes.get(..4)?;
    let op = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let rd = RV_NAMES[((op >> 7) & 31) as usize];
    let rs1 = RV_NAMES[((op >> 15) & 31) as usize];
    let rs2 = RV_NAMES[((op >> 20) & 31) as usize];
    let funct3 = (op >> 12) & 7;
    let funct7 = op >> 25;
    let imm_i = sign_extend(u64::from(op >> 20), 12);
    let imm_s = sign_extend(u64::from(((op >> 25) << 5) | ((op >> 7) & 31)), 12);
    let simple = |text: String| {
        Some(Decoded {
            length: 4,
            text,
            flow: Flow::Next,
        })
    };
    match op & 0x7F {
        0x37 => simple(format!("lui {rd}, {:#x}", op >> 12)),
        0x17 => simple(format!("auipc {rd}, {:#x}", op >> 12)),
        0x6F => {
            let imm = ((op >> 31) << 20)
                | (((op >> 12) & 0xFF) << 12)
                | (((op >> 20) & 1) << 11)
                | (((op >> 21) & 0x3FF) << 1);
            let target = address.wrapping_add(sign_extend(u64::from(imm), 21) as u64);
            let linking = (op >> 7) & 31 != 0;
            Some(Decoded {
                length: 4,
                text: format!("jal {rd}, {target:#x}"),
                flow: if linking {
                    Flow::Call(target)
                } else {
                    Flow::Jump(target)
                },
            })
        }
        0x67 => {
            let is_return = (op >> 7) & 31 == 0 && (op >> 15) & 31 == 1;
            let linking = (op >> 7) & 31 != 0;
            Some(Decoded {
                length: 4,
                text: if is_return {
                    "ret".into()
                } else {
                    format!("jalr {rd}, {imm_i}({rs1})")
                },
                flow: if is_return {
                    Flow::Return
                } else if linking {
                    Flow::IndirectCall
                } else {
                    Flow::IndirectJump
                },
            })
        }
        0x63 => {
            let imm = ((op >> 31) << 12)
                | (((op >> 7) & 1) << 11)
                | (((op >> 25) & 0x3F) << 5)
                | (((op >> 8) & 0xF) << 1);
            let target = address.wrapping_add(sign_extend(u64::from(imm), 13) as u64);
            let name = ["beq", "bne", "?", "?", "blt", "bge", "bltu", "bgeu"][funct3 as usize];
            if name == "?" {
                return None;
            }
            Some(Decoded {
                length: 4,
                text: format!("{name} {rs1}, {rs2}, {target:#x}"),
                flow: Flow::Branch(target),
            })
        }
        0x03 => {
            let name = ["lb", "lh", "lw", "ld", "lbu", "lhu", "lwu", "?"][funct3 as usize];
            if name == "?" {
                return None;
            }
            simple(format!("{name} {rd}, {imm_i}({rs1})"))
        }
        0x23 => {
            let name = ["sb", "sh", "sw", "sd", "?", "?", "?", "?"][funct3 as usize];
            if name == "?" {
                return None;
            }
            simple(format!("{name} {rs2}, {imm_s}({rs1})"))
        }
        0x13 | 0x1B => {
            let suffix = if op & 0x7F == 0x1B { "w" } else { "" };
            let name = match (funct3, funct7 >> 1) {
                (0, _) => "addi",
                (2, _) => "slti",
                (3, _) => "sltiu",
                (4, _) => "xori",
                (6, _) => "ori",
                (7, _) => "andi",
                (1, _) => "slli",
                (5, 0x10) => "srai",
                (5, _) => "srli",
                _ => return None,
            };
            simple(format!("{name}{suffix} {rd}, {rs1}, {imm_i}"))
        }
        0x33 | 0x3B => {
            let suffix = if op & 0x7F == 0x3B { "w" } else { "" };
            let name = match (funct7, funct3) {
                (0x00, 0) => "add",
                (0x20, 0) => "sub",
                (0x00, 1) => "sll",
                (0x00, 2) => "slt",
                (0x00, 3) => "sltu",
                (0x00, 4) => "xor",
                (0x00, 5) => "srl",
                (0x20, 5) => "sra",
                (0x00, 6) => "or",
                (0x00, 7) => "and",
                (0x01, 0) => "mul",
                (0x01, 1) => "mulh",
                (0x01, 2) => "mulhsu",
                (0x01, 3) => "mulhu",
                (0x01, 4) => "div",
                (0x01, 5) => "divu",
                (0x01, 6) => "rem",
                (0x01, 7) => "remu",
                _ => return None,
            };
            simple(format!("{name}{suffix} {rd}, {rs1}, {rs2}"))
        }
        0x0F => simple("fence".into()),
        0x73 => Some(Decoded {
            length: 4,
            text: if op == 0x73 {
                "ecall".into()
            } else {
                format!("system {op:#x}")
            },
            flow: if op == 0x0010_0073 {
                Flow::Stop
            } else {
                Flow::Next
            },
        }),
        _ => None,
    }
}

fn decode_riscv_compressed(op: u16, address: u64) -> Decoded {
    let op = u32::from(op);
    let quadrant = op & 3;
    let funct3 = (op >> 13) & 7;
    let plain = |text: String, flow: Flow| Decoded {
        length: 2,
        text,
        flow,
    };
    if quadrant == 1 && (funct3 == 5 || funct3 == 6 || funct3 == 7) {
        if funct3 == 5 {
            let imm = (((op >> 12) & 1) << 11)
                | (((op >> 8) & 1) << 10)
                | (((op >> 9) & 3) << 8)
                | (((op >> 6) & 1) << 7)
                | (((op >> 7) & 1) << 6)
                | (((op >> 2) & 1) << 5)
                | (((op >> 11) & 1) << 4)
                | (((op >> 3) & 7) << 1);
            let target = address.wrapping_add(sign_extend(u64::from(imm), 12) as u64);
            return plain(format!("c.j {target:#x}"), Flow::Jump(target));
        }
        let imm = (((op >> 12) & 1) << 8)
            | (((op >> 5) & 3) << 6)
            | (((op >> 2) & 1) << 5)
            | (((op >> 10) & 3) << 3)
            | (((op >> 3) & 3) << 1);
        let target = address.wrapping_add(sign_extend(u64::from(imm), 9) as u64);
        let name = if funct3 == 6 { "c.beqz" } else { "c.bnez" };
        return plain(format!("{name} {target:#x}"), Flow::Branch(target));
    }
    if quadrant == 2 && funct3 == 4 && (op >> 2) & 31 == 0 && (op >> 7) & 31 != 0 {
        let rs1 = (op >> 7) & 31;
        if (op >> 12) & 1 == 0 {
            if rs1 == 1 {
                return plain("c.ret".into(), Flow::Return);
            }
            return plain(
                format!("c.jr {}", RV_NAMES[rs1 as usize]),
                Flow::IndirectJump,
            );
        }
        return plain(
            format!("c.jalr {}", RV_NAMES[rs1 as usize]),
            Flow::IndirectCall,
        );
    }
    plain(format!("c.insn {op:#06x}"), Flow::Next)
}

/// AArch64. Control flow is decoded completely, since the graph depends on it. Other instructions
/// get their common forms, and the rest print as raw words.
pub fn decode_aarch64(bytes: &[u8], address: u64) -> Option<Decoded> {
    let raw = bytes.get(..4)?;
    let op = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let make = |text: String, flow: Flow| {
        Some(Decoded {
            length: 4,
            text,
            flow,
        })
    };
    let reg = |bits: u32| {
        if bits == 31 {
            "sp".to_string()
        } else {
            format!("x{bits}")
        }
    };
    // Unconditional branches, with or without link.
    if op & 0x7C00_0000 == 0x1400_0000 {
        let target =
            address.wrapping_add((sign_extend(u64::from(op & 0x03FF_FFFF), 26) << 2) as u64);
        return if op >> 31 == 1 {
            make(format!("bl {target:#x}"), Flow::Call(target))
        } else {
            make(format!("b {target:#x}"), Flow::Jump(target))
        };
    }
    // Conditional branch.
    if op & 0xFF00_0010 == 0x5400_0000 {
        let target =
            address.wrapping_add((sign_extend(u64::from((op >> 5) & 0x7FFFF), 19) << 2) as u64);
        let cond = [
            "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
            "al", "nv",
        ][(op & 15) as usize];
        return make(format!("b.{cond} {target:#x}"), Flow::Branch(target));
    }
    // Compare and branch.
    if op & 0x7E00_0000 == 0x3400_0000 {
        let target =
            address.wrapping_add((sign_extend(u64::from((op >> 5) & 0x7FFFF), 19) << 2) as u64);
        let name = if op & (1 << 24) != 0 { "cbnz" } else { "cbz" };
        return make(
            format!("{name} {}, {target:#x}", reg(op & 31)),
            Flow::Branch(target),
        );
    }
    // Test and branch.
    if op & 0x7E00_0000 == 0x3600_0000 {
        let target =
            address.wrapping_add((sign_extend(u64::from((op >> 5) & 0x3FFF), 14) << 2) as u64);
        let name = if op & (1 << 24) != 0 { "tbnz" } else { "tbz" };
        return make(
            format!("{name} {}, {target:#x}", reg(op & 31)),
            Flow::Branch(target),
        );
    }
    // Branches to a register. Bit 11 marks the pointer-authenticated forms, with bit 10 for the key
    // and bit 24 for a modifier register. They branch just like the plain forms, which matters
    // because arm64e code calls through them everywhere.
    if op & 0xFE1F_F000 == 0xD61F_0000 {
        let rn = reg((op >> 5) & 31);
        let auth = match (op >> 10) & 3 {
            0b10 => "aa",
            0b11 => "ab",
            _ => "",
        };
        return match (op >> 21) & 7 {
            0 => make(format!("br{auth} {rn}"), Flow::IndirectJump),
            1 => make(format!("blr{auth} {rn}"), Flow::IndirectCall),
            2 => make(format!("ret{auth}"), Flow::Return),
            _ => make(format!(".inst {op:#010x}"), Flow::Stop),
        };
    }
    if op & 0xFFE0_001F == 0xD420_0000 {
        return make(format!("brk #{:#x}", (op >> 5) & 0xFFFF), Flow::Stop);
    }
    if op == 0xD503_201F {
        return make("nop".to_string(), Flow::Next);
    }
    if op & 0x7F80_0000 == 0x5280_0000 {
        let shift = ((op >> 21) & 3) * 16;
        return make(
            format!(
                "movz {}, #{:#x}, lsl #{shift}",
                reg(op & 31),
                (op >> 5) & 0xFFFF
            ),
            Flow::Next,
        );
    }
    if op & 0x7F00_0000 == 0x1100_0000 || op & 0x7F00_0000 == 0x5100_0000 {
        let name = if op & 0x4000_0000 != 0 { "sub" } else { "add" };
        return make(
            format!(
                "{name} {}, {}, #{:#x}",
                reg(op & 31),
                reg((op >> 5) & 31),
                (op >> 10) & 0xFFF
            ),
            Flow::Next,
        );
    }
    if let Some(text) = aarch64_common(op, address) {
        return make(text, Flow::Next);
    }
    make(format!(".inst {op:#010x}"), Flow::Next)
}

/// The forms that make up most of real AArch64 code, so a listing is readable.
fn aarch64_common(op: u32, address: u64) -> Option<String> {
    let reg = |bits: u32| {
        if bits == 31 {
            "xzr".to_string()
        } else {
            format!("x{bits}")
        }
    };
    let base = |bits: u32| {
        if bits == 31 {
            "sp".to_string()
        } else {
            format!("x{bits}")
        }
    };
    let rd = op & 31;
    let rn = (op >> 5) & 31;
    match op {
        0xD503_233F => return Some("paciasp".into()),
        0xD503_23BF => return Some("autiasp".into()),
        0xD503_237F => return Some("pacibsp".into()),
        0xD503_23FF => return Some("autibsp".into()),
        0xD503_245F | 0xD503_249F | 0xD503_24DF | 0xD503_241F => return Some("bti".into()),
        _ => {}
    }
    // ADR and ADRP, which address data relative to the instruction.
    if op & 0x1F00_0000 == 0x1000_0000 {
        let immediate = (u64::from((op >> 5) & 0x7FFFF) << 2) | u64::from((op >> 29) & 3);
        let offset = sign_extend(immediate, 21);
        return Some(if op >> 31 == 1 {
            let target = (address & !0xFFF).wrapping_add((offset << 12) as u64);
            format!("adrp {}, {target:#x}", reg(rd))
        } else {
            format!(
                "adr {}, {:#x}",
                reg(rd),
                address.wrapping_add(offset as u64)
            )
        });
    }
    // Load and store pair, as in function prologues.
    if op & 0x7E00_0000 == 0x2800_0000 && op >> 30 == 2 {
        let name = if op & (1 << 22) != 0 { "ldp" } else { "stp" };
        let offset = sign_extend(u64::from((op >> 15) & 0x7F), 7) * 8;
        let second = (op >> 10) & 31;
        let (open, close) = match (op >> 23) & 3 {
            1 => ("[", format!("], #{offset}")),
            3 => ("[", format!(", #{offset}]!")),
            _ => ("[", format!(", #{offset}]")),
        };
        return Some(format!(
            "{name} {}, {}, {open}{}{close}",
            reg(rd),
            reg(second),
            base(rn)
        ));
    }
    // Load and store with an unsigned scaled offset.
    if op & 0xBFC0_0000 == 0xB900_0000 || op & 0xBFC0_0000 == 0xB940_0000 {
        let wide = op & (1 << 30) != 0;
        let load = op & (1 << 22) != 0;
        let scale = if wide { 8 } else { 4 };
        let offset = u64::from((op >> 10) & 0xFFF) * scale;
        let name = if load { "ldr" } else { "str" };
        let target = if wide { reg(rd) } else { format!("w{rd}") };
        return Some(format!("{name} {target}, [{}, #{offset}]", base(rn)));
    }
    // MOV between registers, which encodes as ORR with the zero register.
    if op & 0x7FE0_FFE0 == 0x2A00_03E0 {
        let width = if op >> 31 == 1 { "x" } else { "w" };
        return Some(format!("mov {width}{rd}, {width}{}", (op >> 16) & 31));
    }
    // SUBS with an immediate, written as CMP when the result is discarded.
    if op & 0x7F00_0000 == 0x7100_0000 {
        let immediate = (op >> 10) & 0xFFF;
        let width = if op >> 31 == 1 { "x" } else { "w" };
        return Some(if rd == 31 {
            format!("cmp {width}{rn}, #{immediate:#x}")
        } else {
            format!("subs {width}{rd}, {width}{rn}, #{immediate:#x}")
        });
    }
    None
}
