//! The browser's entry points.
//!
//! These use a plain C-style ABI over linear memory, so that building needs nothing beyond `cargo`.
//! JavaScript copies input in with `zkhv_alloc`, calls a function, and reads back a JSON string whose
//! location comes as `(pointer << 32) | length`, freeing both buffers with `zkhv_free`. Results are
//! always `{"ok": ...}` or `{"error": "..."}`.

use serde_json::{json, Value};
use zkhypervm_inspector::{inspect, Architecture, Options};
use zkhypervm_witness::circom::{R1cs, Witness};
use zkhypervm_witness::program::{parse_program, prove_program};

fn failure(message: impl std::fmt::Display) -> Value {
    json!({ "error": message.to_string() })
}

/// Inspects a file. `architecture` is 0 for automatic detection, and otherwise forces one.
pub fn inspect_json(input: &[u8], architecture: u32, max_instructions: u32) -> String {
    let force_architecture = match architecture {
        1 => Some(Architecture::X86_64),
        2 => Some(Architecture::X86),
        3 => Some(Architecture::Aarch64),
        4 => Some(Architecture::Riscv64),
        5 => Some(Architecture::Evm),
        _ => None,
    };
    let options = Options {
        force_architecture,
        max_instructions: if max_instructions == 0 {
            50_000
        } else {
            max_instructions as usize
        },
        extra_roots: Vec::new(),
    };
    let value = match inspect(input, &options) {
        Ok(report) => match serde_json::to_value(&report) {
            Ok(body) => json!({ "ok": body }),
            Err(e) => failure(e),
        },
        Err(e) => failure(e),
    };
    value.to_string()
}

/// Runs a guest program under the hypervisor, folds it, and verifies the result.
pub fn prove_json(source: &str, iterations: u32) -> String {
    let value = match parse_program(source) {
        Ok(program) => match prove_program(&program, iterations as usize) {
            Ok(report) => match serde_json::to_value(&report) {
                Ok(body) => json!({ "ok": body }),
                Err(e) => failure(e),
            },
            Err(e) => failure(e),
        },
        Err(e) => failure(e),
    };
    value.to_string()
}

/// Checks a Circom witness against its circuit, and against the circuit's conversion to CCS.
pub fn check_circom_json(r1cs_file: &[u8], witness_file: &[u8]) -> String {
    let outcome = (|| -> Result<Value, zkhypervm_witness::circom::CircomError> {
        let r1cs = R1cs::parse(r1cs_file)?;
        let witness = Witness::parse(witness_file)?;
        r1cs.check(&witness)?;
        let (w, x) = r1cs.split_witness(&witness);
        let ccs_agrees = r1cs.to_ccs().is_satisfied(&w, &x);
        Ok(json!({
            "wires": r1cs.wires,
            "constraints": r1cs.constraints.len(),
            "public_outputs": r1cs.public_outputs,
            "public_inputs": r1cs.public_inputs,
            "private_inputs": r1cs.private_inputs,
            "satisfied": true,
            "ccs_agrees": ccs_agrees,
        }))
    })();
    match outcome {
        Ok(body) => json!({ "ok": body }).to_string(),
        Err(e) => failure(e).to_string(),
    }
}

#[cfg(target_arch = "wasm32")]
mod abi {
    use super::*;

    fn respond(text: String) -> u64 {
        let bytes = text.into_bytes().into_boxed_slice();
        let length = bytes.len() as u64;
        let pointer = Box::into_raw(bytes) as *mut u8 as usize as u64;
        (pointer << 32) | length
    }

    /// # Safety
    /// The buffer must have come from `zkhv_alloc` and still be live.
    unsafe fn slice<'a>(pointer: *const u8, length: usize) -> &'a [u8] {
        if length == 0 {
            &[]
        } else {
            // SAFETY: guaranteed by this function's contract.
            unsafe { std::slice::from_raw_parts(pointer, length) }
        }
    }

    #[no_mangle]
    pub extern "C" fn zkhv_alloc(length: usize) -> *mut u8 {
        Box::into_raw(vec![0u8; length].into_boxed_slice()) as *mut u8
    }

    /// # Safety
    /// `pointer` and `length` must describe a buffer from this module that has not been freed.
    #[no_mangle]
    pub unsafe extern "C" fn zkhv_free(pointer: *mut u8, length: usize) {
        // SAFETY: guaranteed by this function's contract.
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(pointer, length)) });
    }

    /// # Safety
    /// The buffer must have come from `zkhv_alloc` and still be live.
    #[no_mangle]
    pub unsafe extern "C" fn zkhv_inspect(
        pointer: *const u8,
        length: usize,
        architecture: u32,
        limit: u32,
    ) -> u64 {
        // SAFETY: guaranteed by this function's contract.
        respond(inspect_json(
            unsafe { slice(pointer, length) },
            architecture,
            limit,
        ))
    }

    /// # Safety
    /// The buffer must have come from `zkhv_alloc` and still be live.
    #[no_mangle]
    pub unsafe extern "C" fn zkhv_prove(pointer: *const u8, length: usize, iterations: u32) -> u64 {
        // SAFETY: guaranteed by this function's contract.
        let bytes = unsafe { slice(pointer, length) };
        match std::str::from_utf8(bytes) {
            Ok(source) => respond(prove_json(source, iterations)),
            Err(_) => respond(failure("the program is not valid UTF-8").to_string()),
        }
    }

    /// # Safety
    /// Both buffers must have come from `zkhv_alloc` and still be live.
    #[no_mangle]
    pub unsafe extern "C" fn zkhv_check_circom(
        r1cs: *const u8,
        r1cs_length: usize,
        witness: *const u8,
        witness_length: usize,
    ) -> u64 {
        // SAFETY: guaranteed by this function's contract.
        respond(check_circom_json(
            unsafe { slice(r1cs, r1cs_length) },
            unsafe { slice(witness, witness_length) },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspection_results_are_json_with_string_addresses() {
        let out: Value = serde_json::from_str(&inspect_json(b"0x600456fe5b00", 0, 0)).unwrap();
        assert_eq!(out["ok"]["format"], "EVM bytecode");
        assert_eq!(out["ok"]["blocks"][0]["start"], "0x0");
        assert_eq!(out["ok"]["entry"], "0x0");
    }

    #[test]
    fn high_addresses_survive_json_exactly() {
        // A high-half address, far above what a JSON number can hold without losing precision.
        let code = [0x90u8, 0xC3];
        let out: Value = serde_json::from_str(&inspect_json(&code, 1, 0)).unwrap();
        assert!(out["ok"]["blocks"][0]["instructions"][1]["address"].is_string());
    }

    #[test]
    fn errors_come_back_as_json() {
        let out: Value = serde_json::from_str(&inspect_json(b"nonsense", 0, 0)).unwrap();
        assert!(out["error"].as_str().unwrap().contains("recognized"));
        let out: Value = serde_json::from_str(&prove_json("bogus", 1)).unwrap();
        assert!(out["error"].as_str().unwrap().contains("line 1"));
        let out: Value = serde_json::from_str(&check_circom_json(b"x", b"y")).unwrap();
        assert!(out["error"].is_string());
    }

    #[test]
    fn a_proof_comes_back_verified() {
        let out: Value = serde_json::from_str(&prove_json("movimm r1, 5", 1)).unwrap();
        assert_eq!(out["ok"]["verified"], true);
        assert_eq!(out["ok"]["registers"][1], "0x5");
    }
}
