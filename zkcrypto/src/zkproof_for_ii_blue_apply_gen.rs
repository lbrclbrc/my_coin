// zkproof_for_ii_blue_apply_generator.rs
// Poseidon/ECC-based circuit and proof generator for the ii_blue apply flow.
use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    pasta::{EqAffine, Fp},
    plonk::{create_proof, keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
    poly::commitment::Params,
    transcript::{Blake2bWrite, Challenge255},
};
use pasta_curves::{
    arithmetic::CurveAffine,
    group::{prime::PrimeCurveAffine, Curve, Group, GroupEncoding},
    pallas::{Affine as EpAffine, Point as Ep, Scalar},
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;
use rand_core::OsRng;

// Reuse the existing Poseidon and ECC chips (these functions are exported from their chip modules).
use crate::poseidon_chip::{
    bytes32_to_fp_in_circuit, hash_fp_in_circuit, hash_two_in_circuit, PoseidonHashConfig,
};
use crate::ecc_chip::{
    ecc_scalar_mul_region, precompute_base_points, scalar_from_bytes_mod_order,
    scalar_to_bits_le, SimpleEccConfig, NUM_BITS,
};

/// Convert a 32-byte big-endian encoding into a Pallas Fp element.
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

#[derive(Clone, Debug)]
pub struct IiBlueApplyConfig {
    poseidon: PoseidonHashConfig,
    ecc: SimpleEccConfig,
}

#[derive(Clone, Debug)]
pub struct IiBlueApplyCircuit {
    master_seed: Value<Fp>,
    token_bytes: [Value<Fp>; 32],
    bits: [bool; NUM_BITS],
    base_points: [EpAffine; NUM_BITS],
    pk: EpAffine,
}

impl Default for IiBlueApplyCircuit {
    fn default() -> Self {
        IiBlueApplyCircuit {
            master_seed: Value::unknown(),
            token_bytes: [Value::unknown(); 32],
            bits: [false; NUM_BITS],
            base_points: precompute_base_points(),
            pk: <EpAffine as PrimeCurveAffine>::identity(),
        }
    }
}

impl Circuit<Fp> for IiBlueApplyCircuit {
    type Config = IiBlueApplyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        IiBlueApplyCircuit::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let poseidon_cfg = PoseidonHashConfig::configure(meta);
        let ecc_cfg = SimpleEccConfig::configure(meta);

        IiBlueApplyConfig {
            poseidon: poseidon_cfg,
            ecc: ecc_cfg,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let _ = &self.pk;

        // 1) assign master_seed
        let ms_cell: AssignedCell<Fp, Fp> = layouter.assign_region(
            || "load master_seed",
            |mut region| {
                let cell = region.assign_advice(
                    || "master_seed",
                    config.poseidon.input,
                    0,
                    || self.master_seed,
                )?;
                Ok(cell)
            },
        )?;

        // 2) Poseidon(master_seed) -> expose public master_seed_hash (row 0)
        let ms_hash_cell = hash_fp_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "poseidon(master_seed)"),
            ms_cell.clone(),
        )?;
        // master_seed_hash is written to poseidon.output at row 0.
        config.poseidon.expose_public(
            layouter.namespace(|| "expose master_seed_hash"),
            &ms_hash_cell,
            0usize,
        )?;

        // 3) assign token bytes (32) and pack into token_fp
        let token_byte_cells: Vec<AssignedCell<Fp, Fp>> = layouter.assign_region(
            || "assign token bytes",
            |mut region| {
                let mut cells = Vec::with_capacity(32);
                for i in 0..32 {
                    let cell = region.assign_advice(
                        || format!("token_byte_{}", i),
                        config.poseidon.byte_col,
                        i,
                        || self.token_bytes[i],
                    )?;
                    cells.push(cell);
                }
                Ok(cells)
            },
        )?;

        let token_fp_cell = bytes32_to_fp_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "token bytes -> fp"),
            &token_byte_cells,
        )?;

        // 4) Poseidon(master_seed, token_fp) -> digest_cell
        let digest_cell = hash_two_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "poseidon(master_seed, token_fp)"),
            ms_cell.clone(),
            token_fp_cell.clone(),
        )?;

        // 5) ecc scalar multiplication -> returns (pk_x_cell, pk_y_cell, packed_bits_cell)
        let (pk_x_cell, pk_y_cell, packed_bits_cell) = ecc_scalar_mul_region(
            &config.ecc,
            layouter.namespace(|| "ecc scalar mul"),
            &self.bits,
            &self.base_points,
        )?;

        // 6) constrain packed_bits == digest
        layouter.assign_region(
            || "constrain packed_bits == digest",
            |mut region| {
                region.constrain_equal(packed_bits_cell.cell(), digest_cell.cell())
            },
        )?;

        // 7) expose pk (public pkx, pky) using ecc pk_x/pk_y instance columns (each 1 row)
        config.ecc.expose_public(
            layouter.namespace(|| "expose pk"),
            &pk_x_cell,
            &pk_y_cell,
        )?;

        // 8) expose token_fp as public input (write to poseidon.output row 1)
        config.poseidon.expose_public(
            layouter.namespace(|| "expose token"),
            &token_fp_cell,
            1usize,
        )?;

        Ok(())
    }
}

/// Generator on the CPU side.
fn zkproof_for_ii_blue_apply_from_bytes(
    master_seed_bytes: &[u8],
    new_token_bytes: &[u8],
    new_pk_bytes: &[u8],
    master_seed_hash_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    if master_seed_bytes.len() != 32 {
        return Err(format!("master_seed must be 32 bytes, got {}", master_seed_bytes.len()));
    }
    if new_token_bytes.len() != 32 {
        return Err(format!("new_token must be 32 bytes, got {}", new_token_bytes.len()));
    }
    if master_seed_hash_bytes.len() != 32 {
        return Err(format!("master_seed_hash must be 32 bytes, got {}", master_seed_hash_bytes.len()));
    }

    let master_seed_fp = be32_to_fp(master_seed_bytes)?;
    let master_seed_hash_fp = be32_to_fp(master_seed_hash_bytes)?;

    // CPU-side Poseidon digest (off-chain).
    let digest_bytes: Vec<u8> = crate::poseidon_hash::poseidon_hash_bytes(&[master_seed_bytes, new_token_bytes])
        .map_err(|e| format!("poseidon_hash_bytes failed: {:?}", e))?;

    // Reduce digest to a scalar and derive pk (off-chain check).
    let sk_scalar: Scalar = scalar_from_bytes_mod_order(&digest_bytes);
    let pk_from_sk = (Ep::generator() * sk_scalar).to_affine();
    let pk_from_sk_coords_ct = pk_from_sk.coordinates();
    if !bool::from(pk_from_sk_coords_ct.is_some()) {
        return Err("derived pk is point at infinity, not supported".to_string());
    }
    let pk_from_sk_coords = pk_from_sk_coords_ct.unwrap();
    let derived_pkx = *pk_from_sk_coords.x();
    let derived_pky = *pk_from_sk_coords.y();

    let (pk_affine, pkx, pky) = decode_pk_bytes(new_pk_bytes)?;

    if derived_pkx != pkx || derived_pky != pky {
        fn fp_to_hex_be<T: ff::PrimeField>(v: &T) -> String {
            let repr = v.to_repr();
            let mut be = repr.as_ref().to_vec();
            be.reverse();
            be.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
        }
        fn scalar_to_hex_be(s: &Scalar) -> String {
            let repr = s.to_repr();
            let mut be = repr.as_ref().to_vec();
            be.reverse();
            be.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
        }
        fn bytes_to_hex(b: &[u8]) -> String {
            b.iter().map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join("")
        }

        let digest_hex_be = bytes_to_hex(&digest_bytes);
        let sk_hex_be = scalar_to_hex_be(&sk_scalar);

        return Err(format!(
            "new_pk does not match master_seed/new_token-derived scalar\n\
             diagnostic:\n\
             poseidon_digest_be(hex)      = {}\n\
             rust_sk_scalar_be(hex)       = {}\n\
             rust_derived_pk_x(hex)       = {}\n\
             rust_derived_pk_y(hex)       = {}\n",
             digest_hex_be,
             sk_hex_be,
             fp_to_hex_be(&derived_pkx),
             fp_to_hex_be(&derived_pky),
        ));
    }

    // bits witness and base_points
    let bits = scalar_to_bits_le(&sk_scalar);
    let base_points = precompute_base_points();

    // prepare token_bytes as Value<Fp>
    let mut token_values: [Value<Fp>; 32] = [Value::unknown(); 32];
    for i in 0..32 {
        token_values[i] = Value::known(Fp::from(new_token_bytes[i] as u64));
    }

    let circuit = IiBlueApplyCircuit {
        master_seed: Value::known(master_seed_fp),
        token_bytes: token_values,
        bits,
        base_points,
        pk: pk_affine,
    };

    // params / vk / pk
    let k: u32 = 9;
    let params: Params<EqAffine> = Params::new(k);

    let empty_circuit = IiBlueApplyCircuit::default();
    let vk = keygen_vk(&params, &empty_circuit)
        .map_err(|e| format!("keygen_vk: {:?}", e))?;
    let pk_prover = keygen_pk(&params, vk, &empty_circuit)
        .map_err(|e| format!("keygen_pk: {:?}", e))?;

    // Instances layout must match the columns and rows in the circuit's ConstraintSystem.
    // poseidon.output column holds two rows (row0=master_seed_hash, row1=token_fp),
    // and ecc exposes pk_x, pk_y as two separate columns (each with 1 row).
    let token_fp = be32_to_fp(new_token_bytes)?;

    // instances per column, in the order columns were declared in configure():
    //   0: poseidon.output -> two rows: [master_seed_hash_fp, token_fp]
    //   1: ecc.pk_x        -> one row:  [pkx]
    //   2: ecc.pk_y        -> one row:  [pky]
    let instances: Vec<Vec<Fp>> = vec![
        vec![master_seed_hash_fp, token_fp], // poseidon.output column, rows 0..1
        vec![pkx],
        vec![pky],
    ];

    // convert to the nested slices expected by create_proof:
    // create_proof expects a &[&[&[Fp]]] (per-circuit list), so we build:
    //   instance_slices: &[&[Fp]] == per-column slices for one circuit
    //   instance_per_circuit: Vec<&[&[Fp]]> with length equal to the number of circuits (1)
    let instance_slices: Vec<&[Fp]> = instances.iter().map(|v| v.as_slice()).collect();
    let instance_per_circuit: Vec<&[&[Fp]]> = vec![instance_slices.as_slice()];
    let instance_refs: &[&[&[Fp]]] = instance_per_circuit.as_slice();

    // create proof
    let mut transcript =
        Blake2bWrite::<Vec<u8>, EqAffine, Challenge255<EqAffine>>::init(vec![]);
    let proof_res = create_proof(
        &params,
        &pk_prover,
        &[circuit],
        instance_refs,
        OsRng,
        &mut transcript,
    );

    if let Err(e) = proof_res {
        return Err(format!("create_proof: {:?}", e));
    }

    let proof = transcript.finalize();
    Ok(proof)
}

#[pyfunction]
pub fn get_zkproof_for_ii_blue_apply(
    py: Python,
    master_seed: &PyBytes,
    new_token: &PyBytes,
    new_pk: &PyBytes,
    master_seed_hash: &PyBytes,
) -> PyResult<PyObject> {
    let master_seed_bytes = master_seed.as_bytes();
    let new_token_bytes = new_token.as_bytes();
    let new_pk_bytes = new_pk.as_bytes();
    let master_seed_hash_bytes = master_seed_hash.as_bytes();

    match zkproof_for_ii_blue_apply_from_bytes(
        master_seed_bytes,
        new_token_bytes,
        new_pk_bytes,
        master_seed_hash_bytes,
    ) {
        Ok(proof_vec) => Ok(PyBytes::new(py, &proof_vec).into()),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(e)),
    }
}

pub fn register_zkproof_for_ii_blue_addr_apply(m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get_zkproof_for_ii_blue_apply, m)?)?;
    Ok(())
}
