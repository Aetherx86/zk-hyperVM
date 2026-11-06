//! Forged counts must not make the parsers ask for memory.
//!
//! A forged count gets the same `Truncated` error whether or not it is capped first, so the return
//! value cannot show this. This test binary records allocation sizes instead. It holds only this one
//! test, so that no other test's allocations are in the record.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use zkhypervm_witness::circom::{CircomError, R1cs};

struct Recording;

static LARGEST: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call goes straight to the system allocator, and the record changes nothing about it.
unsafe impl GlobalAlloc for Recording {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LARGEST.fetch_max(new_size, Ordering::Relaxed);
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Recording = Recording;

/// The BN254 scalar field modulus in the file format's byte order, from a real witness file.
fn prime_bytes() -> Vec<u8> {
    let wtns = include_bytes!("fixtures/mult.wtns");
    wtns[12 + 12 + 4..12 + 12 + 4 + 32].to_vec()
}

/// A tiny file with the given counts: 12 bytes of constraints, far too few for them.
fn forged_r1cs(constraints: u32) -> Vec<u8> {
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
    file.extend_from_slice(&constraints.to_le_bytes());
    file.extend_from_slice(&2u32.to_le_bytes());
    file.extend_from_slice(&12u64.to_le_bytes());
    file.extend_from_slice(&[0u8; 12]);
    file
}

#[test]
fn a_forged_constraint_count_allocates_nothing_in_proportion_to_it() {
    let file = forged_r1cs(u32::MAX);
    LARGEST.store(0, Ordering::Relaxed);
    let result = R1cs::parse(&file);
    let largest = LARGEST.load(Ordering::Relaxed);
    assert_eq!(result, Err(CircomError::Truncated));
    assert!(
        largest < 1 << 16,
        "a {}-byte file asked for {largest} bytes",
        file.len()
    );
}
