// zkcrypto/src/zkproof_for_ii_blue_apply_verifier.rs
// Verifier that never panics or raises: on any internal error it returns `false`.
// Uses the same IiBlueApplyCircuit type from the generator to ensure vk shape matches.

use ff::PrimeField;
use halo2_proofs::{
    pasta::{EqAffine, Fp},
    plonk::{verify_proof, keygen_vk, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};
use pasta_curves::{
    arithmetic::CurveAffine,
    group::{Curve, GroupEncoding},
    pallas::{Affine as EpAffine, Point as Ep},
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

// Import the exact circuit type used by the generator so vk layout matches.
use crate::zkproof_for_ii_blue_apply_gen::IiBlueApplyCircuit;

/// 32-byte big-endian to Pallas Fp (consistent with the generator).
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

/// Decode pk bytes (supports 64-byte x||y or 32-byte compressed).
/// Returns (affine_point, x_fp, y_fp).
fn decode_pk_bytes(pk_bytes: &[u8]) -> Result<(EpAffine, Fp, Fp), String> {
    if !(pk_bytes.len() == 64 || pk_bytes.len() == 32) {
        return Err("pk_bytes must be 64 bytes (x||y) or 32 bytes (compressed)".to_string());
    }

    let pk: EpAffine = if pk_bytes.len() == 64 {
        let mut x_repr = <Fp as PrimeField>::Repr::default();
        x_repr.as_mut().copy_from_slice(&pk_bytes[0..32]);
        let x_ct = Fp::from_repr(x_repr);
        let x = if bool::from(x_ct.is_some()) { x_ct.unwrap() } else { return Err("invalid pk x bytes".to_string()); };

        let mut y_repr = <Fp as PrimeField>::Repr::default();
        y_repr.as_mut().copy_from_slice(&pk_bytes[32..64]);
        let y_ct = Fp::from_repr(y_repr);
        let y = if bool::from(y_ct.is_some()) { y_ct.unwrap() } else { return Err("invalid pk y bytes".to_string()); };

        let pk_ct = EpAffine::from_xy(x, y);
        if bool::from(pk_ct.is_some()) { pk_ct.unwrap() } else { return Err("pk not on curve".to_string()); }
    } else {
        let mut repr = <Ep as GroupEncoding>::Repr::default();
        repr.as_mut().copy_from_slice(pk_bytes);
        let p_ct = Ep::from_bytes(&repr);
        if bool::from(p_ct.is_some()) {
            let p = p_ct.unwrap();
            // to_affine is available via trait `Curve` imported above
            p.to_affine()
        } else {
            return Err("invalid compressed pk bytes".to_string());
        }
    };

    let pk_coords_ct = pk.coordinates();
    if !bool::from(pk_coords_ct.is_some()) {
        return Err("pk is point at infinity, not supported".to_string());
    }
    let pk_coords = pk_coords_ct.unwrap();
    let pkx = *pk_coords.x();
    let pky = *pk_coords.y();

    Ok((pk, pkx, pky))
}

/// Main verifier: builds public instances and calls verify_proof.
/// This function never returns Err; on any error it returns Ok(false).
fn zkproof_for_ii_blue_apply_verify_from_bytes(
    proof_bytes: &[u8],
    new_token_bytes: &[u8],
    new_pk_bytes: &[u8],
    master_seed_hash_bytes: &[u8],
) -> Result<bool, String> {
    // Basic length checks; wrong length is treated as verification failure without raising.
    if new_token_bytes.len() != 32 {
        eprintln!("verify: new_token wrong len: {}", new_token_bytes.len());
        return Ok(false);
    }
    if master_seed_hash_bytes.len() != 32 {
        eprintln!("verify: master_seed_hash wrong len: {}", master_seed_hash_bytes.len());
        return Ok(false);
    }

    // Decode pk.
    let decode_res = decode_pk_bytes(new_pk_bytes);
    let (_pk_affine, pkx, pky) = match decode_res {
        Ok(t) => t,
        Err(e) => {
            eprintln!("verify: decode_pk_bytes failed: {}", e);
            return Ok(false);
        }
    };

    // be32 -> Fp.
    let token_fp = match be32_to_fp(new_token_bytes) {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("verify: token -> fp failed: {}", e);
            return Ok(false);
        }
    };
    let master_seed_hash_fp = match be32_to_fp(master_seed_hash_bytes) {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("verify: master_seed_hash -> fp failed: {}", e);
            return Ok(false);
        }
    };

    // params & vk: use the same circuit type as the generator.
    let k: u32 = 9;
    let params: Params<EqAffine> = Params::new(k);
    let empty_circuit = IiBlueApplyCircuit::default();
    let vk = match keygen_vk(&params, &empty_circuit) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("verify: keygen_vk failed: {:?}", e);
            return Ok(false);
        }
    };

    // Instances layout must match the generator:
    //   column 0 (poseidon.output): row0 = master_seed_hash_fp, row1 = token_fp
    //   column 1 (ecc.pk_x): row0 = pkx
    //   column 2 (ecc.pk_y): row0 = pky
    let instances: Vec<Vec<Fp>> = vec![
        vec![master_seed_hash_fp, token_fp],
        vec![pkx],
        vec![pky],
    ];
    let instance_slices: Vec<&[Fp]> = instances.iter().map(|v| v.as_slice()).collect();
    let instance_refs_vec: Vec<&[&[Fp]]> = vec![instance_slices.as_slice()];
    let instance_refs: &[&[&[Fp]]] = instance_refs_vec.as_slice();

    // Debug output for inspection.
    eprintln!("=== Verifier debug: proof_bytes.len() = {}", proof_bytes.len());
    for (col_idx, col) in instances.iter().enumerate() {
        eprintln!("instance column {} has {} rows", col_idx, col.len());
        for (row_idx, v) in col.iter().enumerate() {
            let repr = v.to_repr();
            let mut be = repr.as_ref().to_vec();
            be.reverse();
            eprintln!(
                "  col {} row {}: 0x{}",
                col_idx,
                row_idx,
                be.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
            );
        }
    }

    // verify_proof.
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof_bytes[..]);
    let strategy = SingleVerifier::new(&params);

    match verify_proof(&params, &vk, strategy, instance_refs, &mut transcript) {
        Ok(_) => {
            eprintln!("verify_proof: Ok");
            Ok(true)
        }
        Err(e) => {
            // Log the error and return false instead of propagating Err.
            eprintln!("verify_proof: Err: {:?}", e);
            Ok(false)
        }
    }
}

#[pyfunction]
pub fn verify_zkproof_for_ii_blue_apply(
    _py: Python,
    zkproof: &PyBytes,
    new_token: &PyBytes,
    new_pk: &PyBytes,
    master_seed_hash: &PyBytes,
) -> PyResult<bool> {
    let proof_bytes = zkproof.as_bytes();
    let new_token_bytes = new_token.as_bytes();
    let new_pk_bytes = new_pk.as_bytes();
    let master_seed_hash_bytes = master_seed_hash.as_bytes();

    // Call the internal verifier; it guarantees Ok(false) on any error.
    match zkproof_for_ii_blue_apply_verify_from_bytes(
        proof_bytes,
        new_token_bytes,
        new_pk_bytes,
        master_seed_hash_bytes,
    ) {
        Ok(b) => Ok(b),
        Err(e) => {
            // Defensive fallback: internal code should not return Err, but if it does, do not raise to Python.
            eprintln!("verify wrapper: unexpected Err: {}", e);
            Ok(false)
        }
    }
}

pub fn register_zkproof_for_ii_blue_addr_verify(m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(verify_zkproof_for_ii_blue_apply, m)?)?;
    Ok(())
}
