// zkcrypto/src/zkproof_for_acct_to_anon_tx_verifier.rs
// Strong Verifier that never panics / raises: on any internal error it returns `false`.
// Uses the same AcctToAnonTxCircuit type from the STRONG generator to ensure vk shape matches.

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

// Import the exact circuit type used by the generator so vk layout matches.
use crate::zkproof_for_acct_to_anon_tx_gen::AcctToAnonTxCircuit;

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

fn zkproof_for_acct_to_anon_tx_verify_from_bytes(
    proof_bytes: &[u8],
    pin_val_bytes: &[u8],
    pin_nonce_bytes: &[u8],
    pin_addr_bytes: &[u8],
    pin_anon_commit_bytes: &[u8],
) -> Result<bool, String> {
    if pin_val_bytes.len() != 32 {
        eprintln!("verify: pin_val wrong len: {}", pin_val_bytes.len());
        return Ok(false);
    }
    if pin_nonce_bytes.len() != 32 {
        eprintln!("verify: pin_nonce wrong len: {}", pin_nonce_bytes.len());
        return Ok(false);
    }
    if pin_addr_bytes.len() != 32 {
        eprintln!("verify: pin_addr wrong len: {}", pin_addr_bytes.len());
        return Ok(false);
    }
    if pin_anon_commit_bytes.len() != 32 {
        eprintln!(
            "verify: pin_anon_commit wrong len: {}",
            pin_anon_commit_bytes.len()
        );
        return Ok(false);
    }

    let val_fp = match be32_to_fp(pin_val_bytes) {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("verify: val -> fp failed: {}", e);
            return Ok(false);
        }
    };
    let nonce_fp = match be32_to_fp(pin_nonce_bytes) {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("verify: nonce -> fp failed: {}", e);
            return Ok(false);
        }
    };
    let addr_fp = match be32_to_fp(pin_addr_bytes) {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("verify: addr -> fp failed: {}", e);
            return Ok(false);
        }
    };
    let anon_commit_fp = match be32_to_fp(pin_anon_commit_bytes) {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("verify: anon_commit -> fp failed: {}", e);
            return Ok(false);
        }
    };

    let k: u32 = 9;
    let params: Params<EqAffine> = Params::new(k);
    let empty_circuit = AcctToAnonTxCircuit::default();
    let vk = match keygen_vk(&params, &empty_circuit) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("verify: keygen_vk failed: {:?}", e);
            return Ok(false);
        }
    };

    let instances: Vec<Vec<Fp>> = vec![
        vec![addr_fp, anon_commit_fp, val_fp, nonce_fp],
        vec![],
        vec![],
    ];
    let instance_slices: Vec<&[Fp]> = instances.iter().map(|v| v.as_slice()).collect();
    let instance_refs_vec: Vec<&[&[Fp]]> = vec![instance_slices.as_slice()];
    let instance_refs: &[&[&[Fp]]] = instance_refs_vec.as_slice();

    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof_bytes[..]);
    let strategy = SingleVerifier::new(&params);

    match verify_proof(&params, &vk, strategy, instance_refs, &mut transcript) {
        Ok(_) => Ok(true),
        Err(e) => {
            eprintln!("verify_proof: Err: {:?}", e);
            Ok(false)
        }
    }
}

#[pyfunction]
pub fn verify_zkproof_for_acct_to_anon_tx(
    _py: Python,
    zkproof: &PyBytes,
    pin_val: &PyBytes,
    pin_nonce: &PyBytes,
    pin_addr: &PyBytes,
    pin_anon_commit: &PyBytes,
) -> PyResult<bool> {
    let proof_bytes = zkproof.as_bytes();
    let pin_val_bytes = pin_val.as_bytes();
    let pin_nonce_bytes = pin_nonce.as_bytes();
    let pin_addr_bytes = pin_addr.as_bytes();
    let pin_anon_commit_bytes = pin_anon_commit.as_bytes();

    match zkproof_for_acct_to_anon_tx_verify_from_bytes(
        proof_bytes,
        pin_val_bytes,
        pin_nonce_bytes,
        pin_addr_bytes,
        pin_anon_commit_bytes,
    ) {
        Ok(b) => Ok(b),
        Err(e) => {
            eprintln!("verify wrapper: unexpected Err: {}", e);
            Ok(false)
        }
    }
}

pub fn register_zkproof_for_acct_to_anon_tx_verify(m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(verify_zkproof_for_acct_to_anon_tx, m)?)?;
    Ok(())
}
