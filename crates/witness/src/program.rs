//! A small text syntax for guest programs, and the pipeline that proves their execution.
//!
//! ```text
//! movimm r1, 100
//! movimm r2, 250
//! add r3, r1, r2
//! store r3, [r7+0]
//! cpuid
//! load r4, [r7+0]
//! kick 0
//! vmcall
//! ```

use serde::Serialize;
use std::fmt;
use zkhypervm::demo::demo_environment;
use zkhypervm::emulator::GuestInstruction;
use zkhypervm::folding::FoldingEngine;

/// Upper bound on the steps of one run. This keeps a browser tab responsive, and a hostile input
/// cannot use it to hang the page.
pub const MAX_STEPS: usize = 20_000;

/// Upper bound on the length of a guest program.
pub const MAX_INSTRUCTIONS: usize = 4_096;

#[derive(Debug, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

fn register(token: &str) -> Result<u8, String> {
    let digits = token
        .strip_prefix('r')
        .ok_or_else(|| format!("expected a register such as r3, found `{token}`"))?;
    let index: u8 = digits
        .parse()
        .map_err(|_| format!("bad register `{token}`"))?;
    if index > 15 {
        return Err(format!(
            "register `{token}` is out of range, since r0 to r15 exist"
        ));
    }
    Ok(index)
}

fn number(token: &str) -> Result<u64, String> {
    let parsed = if let Some(hex) = token.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        token.parse()
    };
    parsed.map_err(|_| format!("bad number `{token}`"))
}

/// Parses `[r7+8]`, `[r7-8]` or `[r7]`.
fn memory(token: &str) -> Result<(u8, i64), String> {
    let inner = token
        .strip_prefix('[')
        .and_then(|t| t.strip_suffix(']'))
        .ok_or_else(|| format!("expected a memory operand such as [r7+8], found `{token}`"))?;
    let split = inner.find(['+', '-']);
    let (base, offset) = match split {
        Some(at) => {
            let magnitude = number(&inner[at + 1..])?;
            let magnitude =
                i64::try_from(magnitude).map_err(|_| "offset is too large".to_string())?;
            let signed = if inner.as_bytes()[at] == b'-' {
                -magnitude
            } else {
                magnitude
            };
            (&inner[..at], signed)
        }
        None => (inner, 0),
    };
    Ok((register(base)?, offset))
}

fn parse_line(text: &str) -> Result<GuestInstruction, String> {
    let (name, rest) = match text.split_once(char::is_whitespace) {
        Some((name, rest)) => (name, rest),
        None => (text, ""),
    };
    let args: Vec<&str> = rest
        .split(',')
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .collect();
    let want = |count: usize| -> Result<(), String> {
        if args.len() == count {
            Ok(())
        } else {
            Err(format!(
                "`{name}` takes {count} operands, but has {}",
                args.len()
            ))
        }
    };
    Ok(match name.to_ascii_lowercase().as_str() {
        "add" | "sub" => {
            want(3)?;
            let (dst, src1, src2) = (register(args[0])?, register(args[1])?, register(args[2])?);
            if name.eq_ignore_ascii_case("add") {
                GuestInstruction::Add { dst, src1, src2 }
            } else {
                GuestInstruction::Sub { dst, src1, src2 }
            }
        }
        "movimm" => {
            want(2)?;
            GuestInstruction::MovImm {
                dst: register(args[0])?,
                imm: number(args[1])?,
            }
        }
        "load" => {
            want(2)?;
            let (base, offset) = memory(args[1])?;
            GuestInstruction::LoadMem {
                dst: register(args[0])?,
                base,
                offset,
            }
        }
        "store" => {
            want(2)?;
            let (base, offset) = memory(args[1])?;
            GuestInstruction::StoreMem {
                src: register(args[0])?,
                base,
                offset,
            }
        }
        "cpuid" => {
            want(0)?;
            GuestInstruction::Cpuid
        }
        "vmcall" => {
            want(0)?;
            GuestInstruction::Vmcall
        }
        "hlt" => {
            want(0)?;
            GuestInstruction::Hlt
        }
        "movcr" => {
            want(2)?;
            let cr_num = args[0]
                .strip_prefix("cr")
                .and_then(|d| d.parse().ok())
                .filter(|n| matches!(n, 0 | 3 | 4))
                .ok_or_else(|| format!("expected cr0, cr3 or cr4, found `{}`", args[0]))?;
            GuestInstruction::MovCr {
                cr_num,
                reg_src: register(args[1])?,
            }
        }
        "rdmsr" => {
            want(1)?;
            GuestInstruction::Rdmsr {
                msr_idx: u32::try_from(number(args[0])?)
                    .map_err(|_| "MSR index is too large".to_string())?,
            }
        }
        "wrmsr" => {
            want(2)?;
            GuestInstruction::Wrmsr {
                msr_idx: u32::try_from(number(args[0])?)
                    .map_err(|_| "MSR index is too large".to_string())?,
                val: number(args[1])?,
            }
        }
        "kick" => {
            want(1)?;
            GuestInstruction::VirtioKick {
                queue_id: u16::try_from(number(args[0])?)
                    .map_err(|_| "queue id is too large".to_string())?,
            }
        }
        other => return Err(format!("unknown instruction `{other}`")),
    })
}

/// Parses a program. `#` and `;` start comments, and blank lines are ignored.
pub fn parse_program(source: &str) -> Result<Vec<GuestInstruction>, ParseError> {
    let mut out = Vec::new();
    for (i, raw) in source.lines().enumerate() {
        let line = i + 1;
        let text = raw.split(['#', ';']).next().unwrap_or("").trim();
        if text.is_empty() {
            continue;
        }
        if out.len() >= MAX_INSTRUCTIONS {
            return Err(ParseError {
                line,
                message: format!("programs are limited to {MAX_INSTRUCTIONS} instructions"),
            });
        }
        out.push(parse_line(text).map_err(|message| ParseError { line, message })?);
    }
    Ok(out)
}

/// The built-in demonstration program.
pub const DEMO_PROGRAM: &str = "\
movimm r1, 100
movimm r2, 250
add r3, r1, r2
store r3, [r7+0]
cpuid
load r4, [r7+0]
kick 0
vmcall
sub r5, r4, r1
";

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct ProofReport {
    pub steps: usize,
    pub alu_steps: usize,
    pub memory_steps: usize,
    pub vm_exits: usize,
    pub mediation_steps: usize,
    pub vm_entries: usize,
    pub tlb_hits: usize,
    pub tlb_misses: usize,
    pub virtio_events: usize,
    /// Whether the terminal decider accepted the folded accumulators.
    pub verified: bool,
    pub verification_error: Option<String>,
    /// The guest's registers after the run, as a visible result of executing the program.
    pub registers: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProveError {
    EmptyProgram,
    TooManySteps { requested: usize, limit: usize },
    Execution(&'static str),
}

impl fmt::Display for ProveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProveError::EmptyProgram => write!(f, "the program has no instructions"),
            ProveError::TooManySteps { requested, limit } => {
                write!(
                    f,
                    "{requested} steps were requested, but the limit is {limit}"
                )
            }
            ProveError::Execution(message) => write!(f, "guest execution failed: {message}"),
        }
    }
}

impl std::error::Error for ProveError {}

/// Runs a guest program `iterations` times under the verifiable hypervisor, folds each step into
/// the IVC accumulators, and runs the terminal decider. It is deterministic and uses no clock, so it
/// behaves identically in a browser.
pub fn prove_program(
    program: &[GuestInstruction],
    iterations: usize,
) -> Result<ProofReport, ProveError> {
    if program.is_empty() {
        return Err(ProveError::EmptyProgram);
    }
    let requested = program.len().saturating_mul(iterations);
    if requested > MAX_STEPS {
        return Err(ProveError::TooManySteps {
            requested,
            limit: MAX_STEPS,
        });
    }
    let (mut vm, _) = demo_environment();
    let mut engine = FoldingEngine::new();
    'run: for _ in 0..iterations {
        for instruction in program {
            let keep_going = vm
                .step(instruction, &mut engine)
                .map_err(ProveError::Execution)?;
            if !keep_going && matches!(instruction, GuestInstruction::Hlt) {
                break 'run;
            }
        }
    }
    let verdict = engine.verify_terminal_proof();
    Ok(ProofReport {
        steps: vm.stats.total_steps,
        alu_steps: vm.stats.alu_steps,
        memory_steps: vm.stats.mem_steps,
        vm_exits: vm.stats.vmexit_count,
        mediation_steps: vm.stats.hyper_med_steps,
        vm_entries: vm.stats.vmentry_count,
        tlb_hits: vm.stats.tlb_hits,
        tlb_misses: vm.stats.tlb_misses,
        virtio_events: vm.stats.virtio_dma_events,
        verified: verdict.is_ok(),
        verification_error: verdict.err().map(str::to_string),
        registers: (0..16).map(|r| format!("{:#x}", vm.read_gpr(r))).collect(),
    })
}
