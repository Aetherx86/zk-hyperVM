//! EVM bytecode: disassembly, a control-flow graph, and a block-level lift to expressions.

use crate::{Block, Edge, EdgeKind, Instruction, IrBlock};
use std::collections::{BTreeMap, BTreeSet};

/// The name of an opcode, and how many values it pops and pushes.
fn opcode(op: u8) -> Option<(&'static str, u8, u8)> {
    Some(match op {
        0x00 => ("STOP", 0, 0),
        0x01 => ("ADD", 2, 1),
        0x02 => ("MUL", 2, 1),
        0x03 => ("SUB", 2, 1),
        0x04 => ("DIV", 2, 1),
        0x05 => ("SDIV", 2, 1),
        0x06 => ("MOD", 2, 1),
        0x07 => ("SMOD", 2, 1),
        0x08 => ("ADDMOD", 3, 1),
        0x09 => ("MULMOD", 3, 1),
        0x0A => ("EXP", 2, 1),
        0x0B => ("SIGNEXTEND", 2, 1),
        0x10 => ("LT", 2, 1),
        0x11 => ("GT", 2, 1),
        0x12 => ("SLT", 2, 1),
        0x13 => ("SGT", 2, 1),
        0x14 => ("EQ", 2, 1),
        0x15 => ("ISZERO", 1, 1),
        0x16 => ("AND", 2, 1),
        0x17 => ("OR", 2, 1),
        0x18 => ("XOR", 2, 1),
        0x19 => ("NOT", 1, 1),
        0x1A => ("BYTE", 2, 1),
        0x1B => ("SHL", 2, 1),
        0x1C => ("SHR", 2, 1),
        0x1D => ("SAR", 2, 1),
        0x20 => ("KECCAK256", 2, 1),
        0x30 => ("ADDRESS", 0, 1),
        0x31 => ("BALANCE", 1, 1),
        0x32 => ("ORIGIN", 0, 1),
        0x33 => ("CALLER", 0, 1),
        0x34 => ("CALLVALUE", 0, 1),
        0x35 => ("CALLDATALOAD", 1, 1),
        0x36 => ("CALLDATASIZE", 0, 1),
        0x37 => ("CALLDATACOPY", 3, 0),
        0x38 => ("CODESIZE", 0, 1),
        0x39 => ("CODECOPY", 3, 0),
        0x3A => ("GASPRICE", 0, 1),
        0x3B => ("EXTCODESIZE", 1, 1),
        0x3C => ("EXTCODECOPY", 4, 0),
        0x3D => ("RETURNDATASIZE", 0, 1),
        0x3E => ("RETURNDATACOPY", 3, 0),
        0x3F => ("EXTCODEHASH", 1, 1),
        0x40 => ("BLOCKHASH", 1, 1),
        0x41 => ("COINBASE", 0, 1),
        0x42 => ("TIMESTAMP", 0, 1),
        0x43 => ("NUMBER", 0, 1),
        0x44 => ("PREVRANDAO", 0, 1),
        0x45 => ("GASLIMIT", 0, 1),
        0x46 => ("CHAINID", 0, 1),
        0x47 => ("SELFBALANCE", 0, 1),
        0x48 => ("BASEFEE", 0, 1),
        0x49 => ("BLOBHASH", 1, 1),
        0x4A => ("BLOBBASEFEE", 0, 1),
        0x50 => ("POP", 1, 0),
        0x51 => ("MLOAD", 1, 1),
        0x52 => ("MSTORE", 2, 0),
        0x53 => ("MSTORE8", 2, 0),
        0x54 => ("SLOAD", 1, 1),
        0x55 => ("SSTORE", 2, 0),
        0x56 => ("JUMP", 1, 0),
        0x57 => ("JUMPI", 2, 0),
        0x58 => ("PC", 0, 1),
        0x59 => ("MSIZE", 0, 1),
        0x5A => ("GAS", 0, 1),
        0x5B => ("JUMPDEST", 0, 0),
        0x5C => ("TLOAD", 1, 1),
        0x5D => ("TSTORE", 2, 0),
        0x5E => ("MCOPY", 3, 0),
        0x5F => ("PUSH0", 0, 1),
        0xA0 => ("LOG0", 2, 0),
        0xA1 => ("LOG1", 3, 0),
        0xA2 => ("LOG2", 4, 0),
        0xA3 => ("LOG3", 5, 0),
        0xA4 => ("LOG4", 6, 0),
        0xF0 => ("CREATE", 3, 1),
        0xF1 => ("CALL", 7, 1),
        0xF2 => ("CALLCODE", 7, 1),
        0xF3 => ("RETURN", 2, 0),
        0xF4 => ("DELEGATECALL", 6, 1),
        0xF5 => ("CREATE2", 4, 1),
        0xFA => ("STATICCALL", 6, 1),
        0xFD => ("REVERT", 2, 0),
        0xFE => ("INVALID", 0, 0),
        0xFF => ("SELFDESTRUCT", 1, 0),
        _ => return None,
    })
}

fn ends_block(op: u8) -> bool {
    matches!(op, 0x00 | 0x56 | 0x57 | 0xF3 | 0xFD | 0xFE | 0xFF)
}

struct Raw {
    pc: u64,
    op: u8,
    immediate: Vec<u8>,
}

fn sweep(code: &[u8], limit: usize) -> (Vec<Raw>, bool) {
    let mut out = Vec::new();
    let mut pc = 0usize;
    while pc < code.len() {
        if out.len() >= limit {
            return (out, true);
        }
        let op = code[pc];
        // Push data is data, even if it happens to look like a JUMPDEST. This is exactly the rule
        // the EVM itself uses to decide which jump targets are valid.
        let width = if (0x60..=0x7F).contains(&op) {
            usize::from(op - 0x5F)
        } else {
            0
        };
        let end = (pc + 1 + width).min(code.len());
        out.push(Raw {
            pc: pc as u64,
            op,
            immediate: code[pc + 1..end].to_vec(),
        });
        pc += 1 + width;
    }
    (out, false)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn text_of(raw: &Raw) -> String {
    match raw.op {
        0x60..=0x7F => format!("PUSH{} 0x{}", raw.op - 0x5F, hex(&raw.immediate)),
        0x80..=0x8F => format!("DUP{}", raw.op - 0x7F),
        0x90..=0x9F => format!("SWAP{}", raw.op - 0x8F),
        op => match opcode(op) {
            Some((name, _, _)) => name.to_string(),
            None => format!("UNKNOWN 0x{op:02x}"),
        },
    }
}

fn constant(raw: &Raw) -> Option<u64> {
    if raw.op == 0x5F {
        return Some(0);
    }
    if !(0x60..=0x7F).contains(&raw.op) || raw.immediate.len() > 8 {
        return None;
    }
    Some(
        raw.immediate
            .iter()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b)),
    )
}

/// Lifts one block to statements by simulating its stack symbolically. Values coming from before
/// the block are named `s0`, `s1` and so on, from the top of the stack.
fn lift(block: &[&Raw]) -> (Vec<String>, Option<u64>, Option<String>) {
    let mut stack: Vec<String> = Vec::new();
    let mut from_outside = 0usize;
    let mut statements = Vec::new();
    let mut next_value = 0usize;
    let mut target = None;
    let mut condition = None;

    fn pop(stack: &mut Vec<String>, from_outside: &mut usize) -> String {
        stack.pop().unwrap_or_else(|| {
            let name = format!("s{from_outside}");
            *from_outside += 1;
            name
        })
    }

    for raw in block {
        match raw.op {
            0x5F..=0x7F => {
                let digits = hex(&raw.immediate);
                let trimmed = digits.trim_start_matches('0');
                stack.push(format!(
                    "0x{}",
                    if trimmed.is_empty() { "0" } else { trimmed }
                ));
            }
            0x80..=0x8F => {
                let depth = usize::from(raw.op - 0x80);
                while stack.len() <= depth {
                    let name = format!("s{from_outside}");
                    from_outside += 1;
                    stack.insert(0, name);
                }
                let value = stack[stack.len() - 1 - depth].clone();
                stack.push(value);
            }
            0x90..=0x9F => {
                let depth = usize::from(raw.op - 0x8F);
                while stack.len() <= depth {
                    let name = format!("s{from_outside}");
                    from_outside += 1;
                    stack.insert(0, name);
                }
                let top = stack.len() - 1;
                stack.swap(top, top - depth);
            }
            0x5B => {}
            0x56 | 0x57 => {
                let destination = pop(&mut stack, &mut from_outside);
                target = destination
                    .strip_prefix("0x")
                    .and_then(|d| u64::from_str_radix(d, 16).ok());
                if raw.op == 0x57 {
                    let test = pop(&mut stack, &mut from_outside);
                    statements.push(format!("if {test} goto {destination}"));
                    condition = Some(test);
                } else {
                    statements.push(format!("goto {destination}"));
                }
            }
            op => {
                let Some((name, pops, pushes)) = opcode(op) else {
                    statements.push(format!("unknown 0x{op:02x}"));
                    continue;
                };
                let args: Vec<String> = (0..pops)
                    .map(|_| pop(&mut stack, &mut from_outside))
                    .collect();
                let call = format!("{name}({})", args.join(", "));
                if pushes > 0 {
                    let value = format!("v{next_value}");
                    next_value += 1;
                    statements.push(format!("{value} = {call}"));
                    stack.push(value);
                } else {
                    statements.push(call);
                }
            }
        }
    }
    (statements, target, condition)
}

pub fn analyze(code: &[u8], limit: usize) -> (Vec<Block>, Vec<IrBlock>, bool) {
    let (raws, truncated) = sweep(code, limit);
    let jump_destinations: BTreeSet<u64> =
        raws.iter().filter(|r| r.op == 0x5B).map(|r| r.pc).collect();

    // A block starts at the first instruction, at every JUMPDEST, and after every terminator.
    let mut groups: Vec<Vec<&Raw>> = Vec::new();
    let mut current: Vec<&Raw> = Vec::new();
    for raw in &raws {
        if raw.op == 0x5B && !current.is_empty() {
            groups.push(std::mem::take(&mut current));
        }
        current.push(raw);
        if ends_block(raw.op) {
            groups.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        groups.push(current);
    }

    let starts: BTreeMap<u64, usize> = groups
        .iter()
        .enumerate()
        .filter_map(|(i, g)| g.first().map(|r| (r.pc, i)))
        .collect();

    let mut blocks = Vec::with_capacity(groups.len());
    let mut lifted = Vec::with_capacity(groups.len());
    for (i, group) in groups.iter().enumerate() {
        let (Some(first), Some(last)) = (group.first(), group.last()) else {
            continue;
        };
        let (statements, target, _) = lift(group);
        let mut successors = Vec::new();
        let fallthrough = groups.get(i + 1).and_then(|g| g.first()).map(|r| r.pc);
        match last.op {
            0x56 | 0x57 => {
                match target.filter(|t| jump_destinations.contains(t)) {
                    Some(t) => successors.push(Edge {
                        target: t,
                        kind: EdgeKind::Branch,
                    }),
                    None => successors.push(Edge {
                        target: u64::MAX,
                        kind: EdgeKind::Unresolved,
                    }),
                }
                if last.op == 0x57 {
                    if let Some(next) = fallthrough {
                        successors.push(Edge {
                            target: next,
                            kind: EdgeKind::Fallthrough,
                        });
                    }
                }
            }
            op if ends_block(op) => {}
            _ => {
                if let Some(next) = fallthrough {
                    successors.push(Edge {
                        target: next,
                        kind: EdgeKind::Fallthrough,
                    });
                }
            }
        }
        // A constant directly before the jump is also a useful cross-check of the lift.
        debug_assert!({
            if group.len() >= 2 && last.op == 0x56 {
                let previous = group[group.len() - 2];
                constant(previous).is_none() || constant(previous) == target
            } else {
                true
            }
        });
        let width = |r: &Raw| 1 + r.immediate.len() as u64;
        blocks.push(Block {
            start: first.pc,
            end: last.pc + width(last),
            instructions: group
                .iter()
                .map(|r| Instruction {
                    address: r.pc,
                    bytes: format!("{:02x}{}", r.op, hex(&r.immediate)),
                    text: text_of(r),
                })
                .collect(),
            successors,
        });
        lifted.push(IrBlock {
            start: first.pc,
            statements,
        });
    }
    let _ = starts;
    (blocks, lifted, truncated)
}
