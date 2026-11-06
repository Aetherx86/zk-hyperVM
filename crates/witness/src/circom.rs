//! Readers for Circom's binary formats, so that circuits compiled elsewhere can be checked here.
//!
//! Both `.r1cs` and `.wtns` files are untrusted input. Counts are checked against the bytes actually
//! present before anything is allocated, field elements must be canonical, and wire indices must be
//! in range, so a forged file can only ever produce an error.

use ark_ff::{BigInteger, BigInteger256, PrimeField, Zero};
use std::fmt;
use zkhypervm::ccs::{CCSStructure, MatrixEntry, SparseMatrix};
use zkhypervm::crypto::Scalar;

#[derive(Debug, PartialEq, Eq)]
pub enum CircomError {
    BadMagic,
    UnsupportedVersion(u32),
    Truncated,
    MissingSection(u32),
    DuplicateSection(u32),
    /// Only BN254's scalar field is supported, which is the one zk-HyperKVM folds over.
    UnsupportedField,
    NonCanonicalElement,
    WireOutOfRange {
        wire: u32,
        wires: u32,
    },
    InconsistentHeader,
    Violated {
        constraint: usize,
    },
    WitnessSizeMismatch {
        expected: usize,
        found: usize,
    },
    FirstWireMustBeOne,
}

impl fmt::Display for CircomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircomError::BadMagic => write!(f, "this is not a Circom file of the expected type"),
            CircomError::UnsupportedVersion(v) => write!(f, "unsupported file version {v}"),
            CircomError::Truncated => write!(f, "the file is truncated"),
            CircomError::MissingSection(s) => write!(f, "the file has no section {s}"),
            CircomError::DuplicateSection(s) => write!(f, "section {s} appears twice"),
            CircomError::UnsupportedField => write!(f, "only the BN254 scalar field is supported"),
            CircomError::NonCanonicalElement => {
                write!(f, "a field element is not below the modulus")
            }
            CircomError::WireOutOfRange { wire, wires } => {
                write!(f, "wire {wire} is out of range for {wires} wires")
            }
            CircomError::InconsistentHeader => write!(f, "the file's header is inconsistent"),
            CircomError::Violated { constraint } => {
                write!(f, "constraint {constraint} is not satisfied")
            }
            CircomError::WitnessSizeMismatch { expected, found } => {
                write!(
                    f,
                    "the circuit has {expected} wires, but the witness has {found}"
                )
            }
            CircomError::FirstWireMustBeOne => {
                write!(f, "wire 0 of a witness must hold the value 1")
            }
        }
    }
}

impl std::error::Error for CircomError {}

const FIELD_BYTES: usize = 32;

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, at: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CircomError> {
        if self.remaining() < n {
            return Err(CircomError::Truncated);
        }
        let out = &self.bytes[self.at..self.at + n];
        self.at += n;
        Ok(out)
    }

    fn u32(&mut self) -> Result<u32, CircomError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, CircomError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    fn scalar(&mut self) -> Result<Scalar, CircomError> {
        scalar_from_le(self.take(FIELD_BYTES)?)
    }
}

fn scalar_from_le(bytes: &[u8]) -> Result<Scalar, CircomError> {
    let mut limbs = [0u64; 4];
    let (chunks, _) = bytes.as_chunks::<8>();
    for (i, chunk) in chunks.iter().enumerate() {
        limbs[i] = u64::from_le_bytes(*chunk);
    }
    // `from_bigint` refuses values at or above the modulus, where reducing would hide a forgery.
    Scalar::from_bigint(BigInteger256::new(limbs)).ok_or(CircomError::NonCanonicalElement)
}

fn check_field_header(reader: &mut Reader<'_>) -> Result<(), CircomError> {
    let size = reader.u32()? as usize;
    if size != FIELD_BYTES {
        return Err(CircomError::UnsupportedField);
    }
    let prime = reader.take(FIELD_BYTES)?;
    if prime != Scalar::MODULUS.to_bytes_le().as_slice() {
        return Err(CircomError::UnsupportedField);
    }
    Ok(())
}

/// Splits a file into its `(type, body)` sections, which may come in any order.
fn sections<'a>(reader: &mut Reader<'a>, count: u32) -> Result<Vec<(u32, &'a [u8])>, CircomError> {
    let mut out: Vec<(u32, &'a [u8])> = Vec::new();
    for _ in 0..count {
        let kind = reader.u32()?;
        let size = reader.u64()?;
        let size = usize::try_from(size).map_err(|_| CircomError::Truncated)?;
        let body = reader.take(size)?;
        if out.iter().any(|(k, _)| *k == kind) {
            return Err(CircomError::DuplicateSection(kind));
        }
        out.push((kind, body));
    }
    Ok(out)
}

fn section<'a>(all: &[(u32, &'a [u8])], kind: u32) -> Result<&'a [u8], CircomError> {
    all.iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, body)| *body)
        .ok_or(CircomError::MissingSection(kind))
}

pub type LinearCombination = Vec<(u32, Scalar)>;

#[derive(Clone, Debug, PartialEq)]
pub struct Constraint {
    pub a: LinearCombination,
    pub b: LinearCombination,
    pub c: LinearCombination,
}

/// A rank-1 constraint system, where each constraint says `A(w) * B(w) = C(w)`.
#[derive(Clone, Debug, PartialEq)]
pub struct R1cs {
    pub wires: u32,
    pub public_outputs: u32,
    pub public_inputs: u32,
    pub private_inputs: u32,
    pub constraints: Vec<Constraint>,
}

impl R1cs {
    /// Parses a `.r1cs` file.
    pub fn parse(bytes: &[u8]) -> Result<R1cs, CircomError> {
        let mut reader = Reader::new(bytes);
        if reader.take(4)? != b"r1cs" {
            return Err(CircomError::BadMagic);
        }
        let version = reader.u32()?;
        if version != 1 {
            return Err(CircomError::UnsupportedVersion(version));
        }
        let count = reader.u32()?;
        let all = sections(&mut reader, count)?;

        let mut header = Reader::new(section(&all, 1)?);
        check_field_header(&mut header)?;
        let wires = header.u32()?;
        let public_outputs = header.u32()?;
        let public_inputs = header.u32()?;
        let private_inputs = header.u32()?;
        let _labels = header.u64()?;
        let constraint_count = header.u32()? as usize;

        let public = u64::from(public_outputs) + u64::from(public_inputs);
        if wires == 0 || public + 1 > u64::from(wires) {
            return Err(CircomError::InconsistentHeader);
        }

        let body = section(&all, 2)?;
        let mut reader = Reader::new(body);
        // Every constraint takes at least three 4-byte counts, which caps a forged count.
        if constraint_count > body.len() / 12 {
            return Err(CircomError::Truncated);
        }
        let mut constraints = Vec::with_capacity(constraint_count);
        for _ in 0..constraint_count {
            let a = read_combination(&mut reader, wires)?;
            let b = read_combination(&mut reader, wires)?;
            let c = read_combination(&mut reader, wires)?;
            constraints.push(Constraint { a, b, c });
        }
        Ok(R1cs {
            wires,
            public_outputs,
            public_inputs,
            private_inputs,
            constraints,
        })
    }

    /// Number of public wires, not counting the constant wire.
    pub fn public_count(&self) -> usize {
        (self.public_outputs + self.public_inputs) as usize
    }

    /// Checks a witness against every constraint, reporting the first one that fails.
    pub fn check(&self, witness: &Witness) -> Result<(), CircomError> {
        if witness.values.len() != self.wires as usize {
            return Err(CircomError::WitnessSizeMismatch {
                expected: self.wires as usize,
                found: witness.values.len(),
            });
        }
        if witness.values[0] != Scalar::from(1u64) {
            return Err(CircomError::FirstWireMustBeOne);
        }
        let eval = |combination: &LinearCombination| -> Scalar {
            let mut sum = Scalar::zero();
            for (wire, coefficient) in combination {
                sum += witness.values[*wire as usize] * coefficient;
            }
            sum
        };
        for (i, constraint) in self.constraints.iter().enumerate() {
            if eval(&constraint.a) * eval(&constraint.b) != eval(&constraint.c) {
                return Err(CircomError::Violated { constraint: i });
            }
        }
        Ok(())
    }

    /// Where a Circom wire lands in a CCS vector `z = (w, 1, x)`.
    fn column(&self, wire: u32) -> usize {
        let public = self.public_count();
        let private = self.wires as usize - 1 - public;
        match wire as usize {
            0 => private,
            i if i <= public => private + i,
            i => i - 1 - public,
        }
    }

    /// Converts to CCS, the constraint system zk-HyperKVM folds, as `(A o B) - C = 0`.
    pub fn to_ccs(&self) -> CCSStructure {
        let m = self.constraints.len().max(1);
        let n = self.wires as usize;
        let build = |pick: fn(&Constraint) -> &LinearCombination| {
            let mut entries = Vec::new();
            for (row, constraint) in self.constraints.iter().enumerate() {
                for (wire, value) in pick(constraint) {
                    entries.push(MatrixEntry {
                        row,
                        col: self.column(*wire),
                        val: *value,
                    });
                }
            }
            SparseMatrix::new(m, n, entries)
        };
        CCSStructure::new(
            m,
            n,
            self.public_count(),
            vec![build(|c| &c.a), build(|c| &c.b), build(|c| &c.c)],
            vec![vec![0, 1], vec![2]],
            vec![Scalar::from(1u64), -Scalar::from(1u64)],
        )
    }

    /// Splits a witness into the CCS assignment `(w, x)`.
    pub fn split_witness(&self, witness: &Witness) -> (Vec<Scalar>, Vec<Scalar>) {
        let public = self.public_count();
        let x = witness.values[1..=public].to_vec();
        let w = witness.values[public + 1..].to_vec();
        (w, x)
    }
}

fn read_combination(reader: &mut Reader<'_>, wires: u32) -> Result<LinearCombination, CircomError> {
    let terms = reader.u32()? as usize;
    if terms > reader.remaining() / (4 + FIELD_BYTES) {
        return Err(CircomError::Truncated);
    }
    let mut out = Vec::with_capacity(terms);
    for _ in 0..terms {
        let wire = reader.u32()?;
        if wire >= wires {
            return Err(CircomError::WireOutOfRange { wire, wires });
        }
        out.push((wire, reader.scalar()?));
    }
    Ok(out)
}

/// A full assignment of every wire in a circuit.
#[derive(Clone, Debug, PartialEq)]
pub struct Witness {
    pub values: Vec<Scalar>,
}

impl Witness {
    /// Parses a `.wtns` file.
    pub fn parse(bytes: &[u8]) -> Result<Witness, CircomError> {
        let mut reader = Reader::new(bytes);
        if reader.take(4)? != b"wtns" {
            return Err(CircomError::BadMagic);
        }
        let version = reader.u32()?;
        if version != 2 {
            return Err(CircomError::UnsupportedVersion(version));
        }
        let count = reader.u32()?;
        let all = sections(&mut reader, count)?;

        let mut header = Reader::new(section(&all, 1)?);
        check_field_header(&mut header)?;
        let wires = header.u32()? as usize;

        let body = section(&all, 2)?;
        if wires != body.len() / FIELD_BYTES || !body.len().is_multiple_of(FIELD_BYTES) {
            return Err(CircomError::InconsistentHeader);
        }
        let mut reader = Reader::new(body);
        let mut values = Vec::with_capacity(wires);
        for _ in 0..wires {
            values.push(reader.scalar()?);
        }
        Ok(Witness { values })
    }
}
