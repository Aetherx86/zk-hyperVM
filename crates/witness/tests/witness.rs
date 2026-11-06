//! Witness checking against real Circom output, and the proving pipeline.
//!
//! The fixtures come from the real toolchain. `mult.circom` was compiled with Circom 2, and its
//! witness was calculated by snarkjs for a = 3, b = 11, c = 7, which gives out = 231.

use zkhypervm::crypto::Scalar;
use zkhypervm_witness::circom::{CircomError, R1cs, Witness};
use zkhypervm_witness::program::{
    parse_program, prove_program, ProveError, DEMO_PROGRAM, MAX_STEPS,
};

const R1CS_FILE: &[u8] = include_bytes!("fixtures/mult.r1cs");
const WTNS_FILE: &[u8] = include_bytes!("fixtures/mult.wtns");

fn scalars(values: &[u64]) -> Vec<Scalar> {
    values.iter().map(|v| Scalar::from(*v)).collect()
}

#[test]
fn real_circom_files_parse_with_the_expected_shape() {
    let r1cs = R1cs::parse(R1CS_FILE).unwrap();
    assert_eq!(r1cs.wires, 6);
    assert_eq!(r1cs.public_outputs, 1);
    assert_eq!(r1cs.public_inputs, 1);
    assert_eq!(r1cs.private_inputs, 2);
    assert_eq!(r1cs.constraints.len(), 2);

    let witness = Witness::parse(WTNS_FILE).unwrap();
    assert_eq!(witness.values, scalars(&[1, 231, 7, 3, 11, 33]));
}

#[test]
fn the_real_witness_satisfies_the_real_circuit() {
    let r1cs = R1cs::parse(R1CS_FILE).unwrap();
    let witness = Witness::parse(WTNS_FILE).unwrap();
    assert_eq!(r1cs.check(&witness), Ok(()));
}

#[test]
fn any_wrong_value_is_caught() {
    let r1cs = R1cs::parse(R1CS_FILE).unwrap();
    let good = Witness::parse(WTNS_FILE).unwrap();
    // Changing any single wire other than the constant has to break some constraint.
    for wire in 1..good.values.len() {
        let mut bad = good.clone();
        bad.values[wire] += Scalar::from(1u64);
        assert!(
            matches!(r1cs.check(&bad), Err(CircomError::Violated { .. })),
            "a change to wire {wire} went unnoticed"
        );
    }
    let mut wrong_one = good.clone();
    wrong_one.values[0] = Scalar::from(2u64);
    assert_eq!(r1cs.check(&wrong_one), Err(CircomError::FirstWireMustBeOne));

    let mut short = good.clone();
    short.values.pop();
    assert!(matches!(
        r1cs.check(&short),
        Err(CircomError::WitnessSizeMismatch { .. })
    ));
}

/// The two checkers are independent code paths, and they have to agree.
#[test]
fn conversion_to_ccs_agrees_with_the_direct_check() {
    let r1cs = R1cs::parse(R1CS_FILE).unwrap();
    let ccs = r1cs.to_ccs();
    let good = Witness::parse(WTNS_FILE).unwrap();
    let (w, x) = r1cs.split_witness(&good);
    assert!(
        ccs.is_satisfied(&w, &x),
        "the real witness should satisfy the CCS"
    );
    assert_eq!(
        x,
        scalars(&[231, 7]),
        "public wires are the output and the public input"
    );
    assert_eq!(w, scalars(&[3, 11, 33]));

    for wire in 1..good.values.len() {
        let mut bad = good.clone();
        bad.values[wire] += Scalar::from(1u64);
        let (w, x) = r1cs.split_witness(&bad);
        assert!(
            !ccs.is_satisfied(&w, &x),
            "the CCS accepted a change to wire {wire}"
        );
    }
}

#[test]
fn every_truncation_of_real_files_is_rejected() {
    for cut in 0..R1CS_FILE.len() {
        assert!(
            R1cs::parse(&R1CS_FILE[..cut]).is_err(),
            "accepted {cut} bytes of the r1cs"
        );
    }
    for cut in 0..WTNS_FILE.len() {
        assert!(
            Witness::parse(&WTNS_FILE[..cut]).is_err(),
            "accepted {cut} bytes of the wtns"
        );
    }
}

#[test]
fn damaged_real_files_never_panic_and_rarely_pass() {
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let witness = Witness::parse(WTNS_FILE).unwrap();
    for _ in 0..20_000 {
        let mut file = R1CS_FILE.to_vec();
        let at = next() as usize % file.len();
        file[at] = next() as u8;
        if let Ok(parsed) = R1cs::parse(&file) {
            let _ = parsed.check(&witness);
            if parsed.wires > 0 && (parsed.public_count() as u32) < parsed.wires {
                let _ = parsed.to_ccs();
            }
        }
        let mut file = WTNS_FILE.to_vec();
        let at = next() as usize % file.len();
        file[at] = next() as u8;
        let _ = Witness::parse(&file);
    }
}

#[test]
fn wrong_file_types_and_versions_are_refused() {
    assert_eq!(R1cs::parse(WTNS_FILE), Err(CircomError::BadMagic));
    assert_eq!(Witness::parse(R1CS_FILE), Err(CircomError::BadMagic));
    let mut version = R1CS_FILE.to_vec();
    version[4] = 9;
    assert_eq!(
        R1cs::parse(&version),
        Err(CircomError::UnsupportedVersion(9))
    );
}

/// The field modulus as these files store it. Sections can come in any order, so it is found by
/// content rather than at a fixed position.
fn prime_bytes() -> Vec<u8> {
    WTNS_FILE[12 + 12 + 4..12 + 12 + 4 + 32].to_vec()
}

fn position_of_prime(file: &[u8]) -> usize {
    let prime = prime_bytes();
    file.windows(32)
        .position(|w| w == prime.as_slice())
        .expect("the file holds the modulus")
}

#[test]
fn a_different_field_is_refused() {
    let mut file = WTNS_FILE.to_vec();
    file[position_of_prime(WTNS_FILE)] ^= 1;
    assert_eq!(Witness::parse(&file), Err(CircomError::UnsupportedField));
    let mut file = R1CS_FILE.to_vec();
    file[position_of_prime(R1CS_FILE)] ^= 1;
    assert_eq!(R1cs::parse(&file), Err(CircomError::UnsupportedField));
}

#[test]
fn values_at_or_above_the_modulus_are_refused() {
    // A forged witness could otherwise pass as a different number that reduces to a correct one.
    let mut file = WTNS_FILE.to_vec();
    let last = file.len() - 32;
    file[last..].copy_from_slice(&[0xFF; 32]);
    assert_eq!(Witness::parse(&file), Err(CircomError::NonCanonicalElement));
}

#[test]
fn forged_counts_do_not_allocate_or_panic() {
    // Builds a file claiming 2^32 - 1 constraints in a tiny section.
    let mut file = Vec::new();
    file.extend_from_slice(b"r1cs");
    file.extend_from_slice(&1u32.to_le_bytes());
    file.extend_from_slice(&2u32.to_le_bytes());
    file.extend_from_slice(&1u32.to_le_bytes());
    file.extend_from_slice(&64u64.to_le_bytes());
    file.extend_from_slice(&32u32.to_le_bytes());
    file.extend_from_slice(&prime_bytes());
    for value in [3u32, 0, 0, 0] {
        file.extend_from_slice(&value.to_le_bytes());
    }
    file.extend_from_slice(&0u64.to_le_bytes());
    file.extend_from_slice(&u32::MAX.to_le_bytes());
    file.extend_from_slice(&2u32.to_le_bytes());
    file.extend_from_slice(&12u64.to_le_bytes());
    file.extend_from_slice(&[0u8; 12]);
    assert_eq!(R1cs::parse(&file), Err(CircomError::Truncated));
}

#[test]
fn programs_parse_with_comments_and_every_instruction() {
    let source = "
        # a comment
        movimm r1, 0x10 ; another
        add r2, r1, r1
        sub r3, r2, r1
        load r4, [r7+8]
        store r4, [r7-8]
        store r4, [r7]
        cpuid
        vmcall
        movcr cr3, r1
        rdmsr 0x10
        wrmsr 16, 5
        kick 2
        hlt
    ";
    assert_eq!(parse_program(source).unwrap().len(), 13);
}

#[test]
fn program_errors_name_the_line_and_problem() {
    let cases = [
        ("bogus", "unknown instruction"),
        ("add r1, r2", "takes 3 operands"),
        ("add r1, r2, r99", "out of range"),
        ("add r1, r2, x3", "expected a register"),
        ("movimm r1, banana", "bad number"),
        ("load r1, r2", "expected a memory operand"),
        ("load r1, [r2+99999999999999999999]", "bad number"),
        ("movcr cr9, r1", "expected cr0"),
        ("rdmsr 0xFFFFFFFFFF", "too large"),
        ("kick 70000", "too large"),
        ("cpuid r1", "takes 0 operands"),
    ];
    for (source, needle) in cases {
        let error = parse_program(&format!("\n{source}")).unwrap_err();
        assert_eq!(error.line, 2, "{source}");
        assert!(
            error.message.contains(needle),
            "{source}: {}",
            error.message
        );
    }
}

#[test]
fn the_proving_pipeline_runs_and_verifies() {
    let program = parse_program(DEMO_PROGRAM).unwrap();
    assert_eq!(program.len(), 9);
    let report = prove_program(&program, 2).unwrap();
    assert!(report.verified, "{:?}", report.verification_error);
    assert!(report.steps >= 18);
    assert!(report.memory_steps > 0);
    assert!(report.vm_exits > 0);
    // The sum went to memory through nested paging, and came back into r4 after a VM exit.
    assert_eq!(report.registers[4], "0x15e");
}

#[test]
fn guest_arithmetic_produces_the_expected_registers() {
    let program =
        parse_program("movimm r1, 100\nmovimm r2, 250\nadd r3, r1, r2\nsub r5, r3, r1").unwrap();
    let report = prove_program(&program, 1).unwrap();
    assert!(report.verified);
    assert_eq!(report.registers[3], "0x15e");
    assert_eq!(report.registers[5], "0xfa");
    assert_eq!(report.alu_steps, 4);
}

#[test]
fn a_bad_memory_access_is_an_error_and_not_a_crash() {
    let program = parse_program("movimm r1, 0xFFFFFFFFFFFF\nload r2, [r1]").unwrap();
    assert!(matches!(
        prove_program(&program, 1),
        Err(ProveError::Execution(_))
    ));
}

#[test]
fn proving_is_deterministic() {
    let program = parse_program(DEMO_PROGRAM).unwrap();
    assert_eq!(
        prove_program(&program, 1).unwrap(),
        prove_program(&program, 1).unwrap()
    );
}

#[test]
fn proving_enforces_its_limits() {
    let program = parse_program("cpuid").unwrap();
    assert_eq!(prove_program(&[], 1), Err(ProveError::EmptyProgram));
    assert!(matches!(
        prove_program(&program, MAX_STEPS + 1),
        Err(ProveError::TooManySteps { .. })
    ));
    assert!(matches!(
        prove_program(&program, usize::MAX),
        Err(ProveError::TooManySteps { .. })
    ));
}

#[test]
fn reports_serialize_for_the_browser() {
    let program = parse_program("movimm r1, 7").unwrap();
    let report = prove_program(&program, 1).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"verified\":true"), "{json}");
    assert!(json.contains("\"0x7\""), "{json}");
}
