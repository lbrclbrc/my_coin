// zkcrypto/src/poseidon_hash.rs
// Poseidon over the Pallas/Pasta field (Halo2 friendly).
// - poseidon_hash_blocks(list[bytes32(be)]) -> bytes (32-byte, big-endian)
// - get_pallas_modulus_py() -> hex string (big-endian)

use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};

use pasta_curves::pallas;
use pasta_curves::group::ff::PrimeField;

use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3};

type Fp = pallas::Base; // Pallas prime field (used by Halo2).

/// Python list[bytes] -> Vec<[u8; 32]> with strict per-element length checks.
fn collect_32b_be(py_list: &PyList) -> PyResult<Vec<[u8; 32]>> {
    let mut out = Vec::with_capacity(py_list.len());
    for item in py_list.iter() {
        let bv: &[u8] = item
            .extract()
            .map_err(|_| PyErr::new::<exceptions::PyTypeError, _>(
                "each element must be a bytes-like object",
            ))?;
        if bv.len() != 32 {
            return Err(PyErr::new::<exceptions::PyValueError, _>(format!(
                "each block must be exactly 32 bytes, got {} bytes",
                bv.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bv);
        out.push(arr);
    }
    Ok(out)
}

/// 32-byte big-endian encoding to Fp using ff::PrimeField::from_repr (little-endian representation).
/// Note: the ff representation is little-endian; the input is big-endian, so the bytes are reversed.
fn be32_to_fp(be: &[u8; 32]) -> PyResult<Fp> {
    let mut le = *be;
    le.reverse();
    let repr = <Fp as PrimeField>::Repr::from(le);
    let ct = Fp::from_repr(repr);
    if bool::from(ct.is_some()) {
        Ok(ct.unwrap())
    } else {
        Err(PyErr::new::<exceptions::PyValueError, _>(
            "input is not a canonical element of this field (out of range)",
        ))
    }
}

/// Fp -> 32-byte big-endian encoding.
fn fp_to_be32(x: &Fp) -> [u8; 32] {
    let le = x.to_repr(); // FieldBytes (LE, internally 32 bytes)
    let le_bytes: &[u8] = le.as_ref();

    let mut be = [0u8; 32];
    be.copy_from_slice(le_bytes);
    be.reverse();
    be
}

/// Generic CPU-side helper:
/// inputs: slice of byte slices, each element must be a 32-byte big-endian canonical encoding of a Pallas Fp element.
/// Returns: Ok(Vec<u8>) with a 32-byte big-endian Poseidon output, or Err(String) on failure.
///
/// This helper only performs bytes <-> Fp conversion and calls the existing Poseidon core used by poseidon_hash_blocks.
/// The Poseidon algorithm itself is unchanged; the helper exposes a unified bytes interface for generators.
pub fn poseidon_hash_bytes(inputs: &[&[u8]]) -> Result<Vec<u8>, String> {
    // Check inputs and convert to Fp.
    if inputs.is_empty() {
        return Err("poseidon_hash_bytes: inputs must be non-empty".to_string());
    }
    let mut elems: Vec<Fp> = Vec::with_capacity(inputs.len());
    for b in inputs.iter() {
        if b.len() != 32 {
            return Err(format!("poseidon_hash_bytes expects 32-byte elements, got {}", b.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(b);
        // arr is big-endian; convert to little-endian repr.
        arr.reverse();
        let repr = <Fp as PrimeField>::Repr::from(arr);
        let ct = Fp::from_repr(repr);
        if !bool::from(ct.is_some()) {
            return Err("poseidon_hash_bytes: input not in Pallas Fp field".to_string());
        }
        elems.push(ct.unwrap());
    }

    // Compute Poseidon output (Fp) using the same combination strategy as poseidon_hash_blocks.
    let out_fp: Fp;
    if elems.len() == 1 {
        let input = [elems[0]];
        out_fp = Hash::<Fp, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash(input);
    } else {
        // First compress (x0, x1).
        let mut acc =
            Hash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init()
                .hash([elems[0], elems[1]]);
        // Then iterate H(acc, xi).
        for x in elems.iter().skip(2) {
            acc = Hash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init()
                .hash([acc, *x]);
        }
        out_fp = acc;
    }

    // Convert to big-endian bytes and return as Vec<u8>.
    let be = fp_to_be32(&out_fp);
    Ok(be.to_vec())
}

/// Poseidon hash exposed to Python.
///   - Input: list of 32-byte blocks (n >= 1), each a canonical big-endian encoding of a Pallas Fp element.
///   - Internal:
///       n == 1: out = H(x0)
///       n >= 2: acc = H(x0, x1); for i >= 2, acc = H(acc, xi)
///   - Output: 32-byte big-endian encoding of an Fp element.
#[pyfunction]
pub fn poseidon_hash_blocks<'py>(py: Python<'py>, py_list: &PyList) -> PyResult<&'py PyBytes> {
    let blocks_be = collect_32b_be(py_list)?;
    let n = blocks_be.len();

    if n == 0 {
        return Err(PyErr::new::<exceptions::PyValueError, _>(
            "at least one 32-byte block is required",
        ));
    }

    // Convert to Fp.
    let mut elems: Vec<Fp> = Vec::with_capacity(n);
    for be in &blocks_be {
        elems.push(be32_to_fp(be)?);
    }

    let out: Fp = if n == 1 {
        let input = [elems[0]];
        Hash::<Fp, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash(input)
    } else {
        // First compress (x0, x1).
        let mut acc =
            Hash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init()
                .hash([elems[0], elems[1]]);
        // Then iterate H(acc, xi).
        for x in elems.iter().skip(2) {
            acc = Hash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init()
                .hash([acc, *x]);
        }
        acc
    };

    let be = fp_to_be32(&out);
    Ok(PyBytes::new(py, &be))
}

/// Return the modulus of the Pallas base field as big-endian hex.
/// Useful for modular reduction in Python code.
/// p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
#[pyfunction]
pub fn get_pallas_modulus_py() -> PyResult<String> {
    // Constant taken from the Pallas Fp definition in pasta_curves.
    let be_hex = "40000000000000000000000000000000224698fc094cf91b992d30ed00000001";
    Ok(be_hex.to_string())
}
