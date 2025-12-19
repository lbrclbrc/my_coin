// zkcrypto/src/zkproof_for_anon_pay_verify.rs
//
// Verifier for "AnonPay" proof.
//
// Public inputs (32B each):
//   pin_commit_root
//   pin_nullifier
//   pin_commit_change
//   pin_value_pay
//
// Proof: halo2 proof bytes.
//
// This verifier rebuilds vk from empty circuit (same as generator),
// then runs halo2 verify_proof.
//

use ff::PrimeField;
use halo2_proofs::{
    pasta::{EqAffine, Fp},
    plonk::{keygen_vk, verify_proof, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

// reuse circuit type from generator module
use crate::zkproof_for_anon_pay_gen::AnonPayCircuit;

// must match generator
const K: u32 = 12;

/// 32-byte big-endian -> Pallas Fp (canonical only)
fn be32_to_fp(bytes: &[u8]) -> Result<Fp, String> {
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut le = [0u8; 32];
    le.copy_from_slice(bytes);
    le.reverse();
    let repr = <Fp as PrimeField>::Repr::from(le);
    let ct = Fp::from_repr(repr);
    if bool::from(ct.is_some()) {
        Ok(ct.unwrap())
    } else {
        Err("bytes not in Pallas Fp field".to_string())
    }
}

fn verify_anon_pay_proof_from_bytes(
    pin_commit_root: &[u8],
    pin_nullifier: &[u8],
    pin_commit_change: &[u8],
    pin_value_pay: &[u8],
    proof: &[u8],
) -> Result<bool, String> {
    if pin_commit_root.len() != 32 {
        return Err("pin_commit_root must be 32 bytes".to_string());
    }
    if pin_nullifier.len() != 32 {
        return Err("pin_nullifier must be 32 bytes".to_string());
    }
    if pin_commit_change.len() != 32 {
        return Err("pin_commit_change must be 32 bytes".to_string());
    }
    if pin_value_pay.len() != 32 {
        return Err("pin_value_pay must be 32 bytes".to_string());
    }

    let root_fp = be32_to_fp(pin_commit_root)?;
    let nullifier_fp = be32_to_fp(pin_nullifier)?;
    let change_fp = be32_to_fp(pin_commit_change)?;
    let vpay_fp = be32_to_fp(pin_value_pay)?;

    // params / vk
    let params: Params<EqAffine> = Params::new(K);
    let empty_circuit = AnonPayCircuit::default();
    let vk = keygen_vk(&params, &empty_circuit)
        .map_err(|e| format!("keygen_vk: {:?}", e))?;

    // instances layout must match generator/circuit:
    // single column (poseidon.output), rows:
    //   row0=root, row1=nullifier, row2=commit_change, row3=value_pay
    let instances: Vec<Vec<Fp>> = vec![vec![root_fp, nullifier_fp, change_fp, vpay_fp]];

    let instance_slices: Vec<&[Fp]> = instances.iter().map(|v| v.as_slice()).collect();
    let instance_per_circuit: Vec<&[&[Fp]]> = vec![instance_slices.as_slice()];
    let instance_refs: &[&[&[Fp]]] = instance_per_circuit.as_slice();

    let mut transcript =
        Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    // IMPORTANT: strategy is passed by value (same as ii_blue_apply verifier)
    let strategy = SingleVerifier::new(&params);

    let result = verify_proof(
        &params,
        &vk,
        strategy,
        instance_refs,
        &mut transcript,
    );

    match result {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[pyfunction]
pub fn verify_zkproof_for_anon_pay(
    pin_commit_root: &PyBytes,
    pin_nullifier: &PyBytes,
    pin_commit_change: &PyBytes,
    pin_value_pay: &PyBytes,
    proof: &PyBytes,
) -> PyResult<bool> {
    let root_b = pin_commit_root.as_bytes();
    let nullifier_b = pin_nullifier.as_bytes();
    let change_b = pin_commit_change.as_bytes();
    let vpay_b = pin_value_pay.as_bytes();
    let proof_b = proof.as_bytes();

    match verify_anon_pay_proof_from_bytes(root_b, nullifier_b, change_b, vpay_b, proof_b) {
        Ok(ok) => Ok(ok),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(e)),
    }
}

pub fn register_zkproof_for_anon_pay_verify(m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(verify_zkproof_for_anon_pay, m)?)?;
    Ok(())
}
