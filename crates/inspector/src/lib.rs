//! A binary and bytecode inspector that runs entirely on the client.
//!
//! Point it at an ELF, PE or Mach-O file or at EVM bytecode, and it reports the sections, symbols and
//! a control-flow graph. Compiled to WebAssembly, it inspects sensitive binaries inside a browser
//! tab with nothing uploaded anywhere.
//!
//! Every input is treated as hostile. The inspector must return an error rather than panic, on any
//! bytes at all, and its work is bounded by [`Options::max_instructions`].

mod decode;
mod evm;
mod formats;

use crate::decode::{Decoded, Flow};
use crate::formats::Image;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Addresses travel as hex strings, because JSON numbers lose precision above 2^53 and kernel and
/// other high-half addresses are far above that.
fn hex_address<S: serde::Serializer>(value: &u64, out: S) -> Result<S::Ok, S::Error> {
    out.serialize_str(&format!("{value:#x}"))
}

fn hex_address_opt<S: serde::Serializer>(value: &Option<u64>, out: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(v) => out.serialize_str(&format!("{v:#x}")),
        None => out.serialize_none(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Architecture {
    X86,
    X86_64,
    Aarch64,
    Riscv64,
    Evm,
    Unknown(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum InspectError {
    Empty,
    UnknownFormat,
    Malformed(&'static str),
    Unsupported(String),
}

impl fmt::Display for InspectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InspectError::Empty => write!(f, "the file is empty"),
            InspectError::UnknownFormat => write!(
                f,
                "not a recognized format. ELF, PE, Mach-O and EVM bytecode are supported, and \
                 raw code can be inspected by choosing an architecture"
            ),
            InspectError::Malformed(why) => write!(f, "malformed file: {why}"),
            InspectError::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

impl std::error::Error for InspectError {}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    #[serde(serialize_with = "hex_address")]
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub executable: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    #[serde(serialize_with = "hex_address")]
    pub address: u64,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Instruction {
    #[serde(serialize_with = "hex_address")]
    pub address: u64,
    pub bytes: String,
    pub text: String,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum EdgeKind {
    Fallthrough,
    Branch,
    Call,
    /// An indirect jump, whose target is not known from the code alone.
    Unresolved,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Edge {
    #[serde(serialize_with = "hex_address")]
    pub target: u64,
    pub kind: EdgeKind,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Block {
    #[serde(serialize_with = "hex_address")]
    pub start: u64,
    #[serde(serialize_with = "hex_address")]
    pub end: u64,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<Edge>,
}

/// Statements recovered for a block of stack-machine code.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct IrBlock {
    #[serde(serialize_with = "hex_address")]
    pub start: u64,
    pub statements: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Report {
    pub format: String,
    pub architecture: Architecture,
    #[serde(serialize_with = "hex_address_opt")]
    pub entry: Option<u64>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub blocks: Vec<Block>,
    pub ir: Vec<IrBlock>,
    pub notes: Vec<String>,
    pub truncated: bool,
}

#[derive(Clone, Debug)]
pub struct Options {
    /// Stops decoding after this many instructions, and marks the report as truncated.
    pub max_instructions: usize,
    /// Treats the input as raw code for this architecture, loaded at address zero.
    pub force_architecture: Option<Architecture>,
    /// Addresses to start from, in addition to the entry point and function symbols.
    pub extra_roots: Vec<u64>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            max_instructions: 50_000,
            force_architecture: None,
            extra_roots: Vec::new(),
        }
    }
}

/// Reads EVM bytecode written as hex text, with or without a leading `0x`.
fn evm_hex(input: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(input).ok()?.trim();
    let digits = text.strip_prefix("0x").unwrap_or(text);
    if digits.is_empty()
        || !digits.len().is_multiple_of(2)
        || !digits.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).ok())
        .collect()
}

fn evm_report(code: &[u8], options: &Options) -> Report {
    let (blocks, ir, truncated) = evm::analyze(code, options.max_instructions);
    Report {
        format: "EVM bytecode".into(),
        architecture: Architecture::Evm,
        entry: Some(0),
        sections: vec![Section {
            name: "code".into(),
            address: 0,
            size: code.len() as u64,
            file_offset: 0,
            executable: true,
        }],
        symbols: Vec::new(),
        blocks,
        ir,
        notes: Vec::new(),
        truncated,
    }
}

/// Inspects a file.
pub fn inspect(input: &[u8], options: &Options) -> Result<Report, InspectError> {
    if input.is_empty() {
        return Err(InspectError::Empty);
    }
    if let Some(architecture) = &options.force_architecture {
        if *architecture == Architecture::Evm {
            let code = evm_hex(input).unwrap_or_else(|| input.to_vec());
            return Ok(evm_report(&code, options));
        }
        let image = Image {
            format: "raw code",
            architecture: architecture.clone(),
            entry: Some(0),
            segments: vec![formats::Segment {
                address: 0,
                bytes: input.to_vec(),
                executable: true,
            }],
            sections: Vec::new(),
            symbols: Vec::new(),
            notes: Vec::new(),
        };
        return Ok(disassemble(image, options));
    }

    let image = if input.starts_with(b"\x7FELF") {
        formats::parse_elf(input)?
    } else if input.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) {
        formats::parse_macho(input)?
    } else if input.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) {
        formats::parse_fat_macho(input)?
    } else if input.starts_with(b"MZ") {
        formats::parse_pe(input)?
    } else if let Some(code) = evm_hex(input) {
        return Ok(evm_report(&code, options));
    } else {
        return Err(InspectError::UnknownFormat);
    };
    Ok(disassemble(image, options))
}

fn decode_one(architecture: &Architecture, bytes: &[u8], address: u64) -> Option<Decoded> {
    match architecture {
        Architecture::X86_64 => decode::decode_x86(bytes, address, 64),
        Architecture::X86 => decode::decode_x86(bytes, address, 32),
        Architecture::Riscv64 => decode::decode_riscv(bytes, address),
        Architecture::Aarch64 => decode::decode_aarch64(bytes, address),
        Architecture::Evm | Architecture::Unknown(_) => None,
    }
}

/// Recursive descent: follows control flow from known starting points, so that data mixed into a
/// code section is not misread as instructions.
fn disassemble(mut image: Image, options: &Options) -> Report {
    struct Seen {
        length: u64,
        bytes: String,
        text: String,
        flow: Flow,
    }

    // A symbol only starts code if it lies in an executable section. A file can have symbols for
    // data too, and Mach-O even names its own header, which would otherwise decode as garbage.
    let executable: Vec<(u64, u64)> = image
        .sections
        .iter()
        .filter(|s| s.executable)
        .map(|s| (s.address, s.address.saturating_add(s.size)))
        .collect();
    let in_code = |address: u64| {
        executable.is_empty()
            || executable
                .iter()
                .any(|(low, high)| (*low..*high).contains(&address))
    };
    let mut roots: BTreeSet<u64> = image
        .symbols
        .iter()
        .map(|s| s.address)
        .filter(|a| in_code(*a))
        .collect();
    roots.extend(image.entry);
    roots.extend(options.extra_roots.iter().copied());

    let mut work: Vec<u64> = roots.iter().rev().copied().collect();
    // The work list pops from the end, so the entry point goes first. A large binary can use up
    // the whole instruction budget, and the entry point is what people look at first.
    work.extend(image.entry);
    let mut seen: BTreeMap<u64, Seen> = BTreeMap::new();
    let mut leaders: BTreeSet<u64> = roots.clone();
    let mut truncated = false;
    let mut undecodable = 0usize;

    if matches!(image.architecture, Architecture::Unknown(_)) {
        image.notes.push(
            "No decoder exists for this architecture, so only its structure is shown.".into(),
        );
        work.clear();
    }

    'outer: while let Some(mut address) = work.pop() {
        loop {
            if seen.contains_key(&address) {
                break;
            }
            if seen.len() >= options.max_instructions {
                truncated = true;
                break 'outer;
            }
            let Some(bytes) = image.code_at(address) else {
                break;
            };
            let Some(decoded) = decode_one(&image.architecture, bytes, address) else {
                undecodable += 1;
                break;
            };
            let length = decoded.length as u64;
            let hex: String = bytes[..decoded.length.min(bytes.len())]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let flow = decoded.flow;
            seen.insert(
                address,
                Seen {
                    length,
                    bytes: hex,
                    text: decoded.text,
                    flow,
                },
            );
            let next = address.wrapping_add(length);
            match flow {
                Flow::Next | Flow::IndirectCall => address = next,
                Flow::Call(target) => {
                    leaders.insert(target);
                    work.push(target);
                    address = next;
                }
                Flow::Branch(target) => {
                    leaders.insert(target);
                    leaders.insert(next);
                    work.push(target);
                    address = next;
                }
                Flow::Jump(target) => {
                    leaders.insert(target);
                    work.push(target);
                    break;
                }
                Flow::Return | Flow::IndirectJump | Flow::Stop => break,
            }
        }
    }
    if undecodable > 0 {
        image.notes.push(format!(
            "{undecodable} paths ended at bytes that do not decode."
        ));
    }

    // Splits what was found into basic blocks.
    let mut blocks = Vec::new();
    let addresses: Vec<u64> = seen.keys().copied().collect();
    let mut i = 0;
    while i < addresses.len() {
        let start = addresses[i];
        let mut instructions = Vec::new();
        let mut successors = Vec::new();
        let mut at = start;
        let end;
        loop {
            let entry = &seen[&at];
            instructions.push(Instruction {
                address: at,
                bytes: entry.bytes.clone(),
                text: entry.text.clone(),
            });
            let next = at.wrapping_add(entry.length);
            i += 1;
            let flow = entry.flow;
            let fall = |successors: &mut Vec<Edge>| {
                if seen.contains_key(&next) {
                    successors.push(Edge {
                        target: next,
                        kind: EdgeKind::Fallthrough,
                    });
                }
            };
            match flow {
                Flow::Jump(target) => {
                    successors.push(Edge {
                        target,
                        kind: EdgeKind::Branch,
                    });
                    end = next;
                    break;
                }
                Flow::Branch(target) => {
                    successors.push(Edge {
                        target,
                        kind: EdgeKind::Branch,
                    });
                    fall(&mut successors);
                    end = next;
                    break;
                }
                Flow::Return | Flow::Stop => {
                    end = next;
                    break;
                }
                Flow::IndirectJump => {
                    successors.push(Edge {
                        target: u64::MAX,
                        kind: EdgeKind::Unresolved,
                    });
                    end = next;
                    break;
                }
                Flow::Call(target) => {
                    successors.push(Edge {
                        target,
                        kind: EdgeKind::Call,
                    });
                    if !seen.contains_key(&next) || leaders.contains(&next) {
                        fall(&mut successors);
                        end = next;
                        break;
                    }
                }
                Flow::Next | Flow::IndirectCall => {
                    if !seen.contains_key(&next) || leaders.contains(&next) {
                        fall(&mut successors);
                        end = next;
                        break;
                    }
                }
            }
            at = next;
        }
        blocks.push(Block {
            start,
            end,
            instructions,
            successors,
        });
    }

    Report {
        format: image.format.to_string(),
        architecture: image.architecture,
        entry: image.entry,
        sections: image.sections,
        symbols: image.symbols,
        blocks,
        ir: Vec::new(),
        notes: image.notes,
        truncated,
    }
}
