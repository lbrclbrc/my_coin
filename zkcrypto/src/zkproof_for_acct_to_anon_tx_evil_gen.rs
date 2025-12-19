// zkcrypto/src/zkproof_for_acct_to_anon_tx_evil_gen.rs
//
// Self-contained Evil GEN for AcctToAnonTx.
// It intentionally uses two different secret keys:
//   - sk_commit: used in anon_commit chain
//   - sk_addr  : used to derive pk_bytes and thus public addr
//
// This file DOES NOT depend on the normal GEN module.
// We copy the exact *WEAK* circuit/config here so vk shape matches.

use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    pasta::{EqAffine, Fp},
    plonk::{create_proof, keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
    poly::commitment::Params,
    transcript::{Blake2bWrite, Challenge255},
};
use pasta_curves::{
    group::{Group, GroupEncoding},
    pallas::{Affine as EpAffine, Point as Ep, Scalar},
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;
use rand_core::OsRng;

// reuse existing chips (same as normal GEN)
use crate::poseidon_chip::{
    bytes32_to_fp_in_circuit, hash_fp_in_circuit, hash_two_in_circuit, PoseidonHashConfig,
};
use crate::ecc_chip::{
    ecc_scalar_mul_region, precompute_base_points, scalar_from_bytes_mod_order,
    scalar_to_bits_le, SimpleEccConfig, NUM_BITS,
};

const K: u32 = 9;

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

/// CPU-side: arbitrary 32B -> Fp mod p (mirrors bytes32_to_fp_in_circuit)
fn bytes32_to_fp_mod_p(bytes: &[u8]) -> Fp {
    let mut acc = Fp::zero();
    let mut base = Fp::one();
    let base_256 = Fp::from(256u64);

    for b in bytes.iter().rev() {
        let limb = Fp::from(*b as u64);
        acc = acc + limb * base;
        base = base * base_256;
    }
    acc
}

/// Fp -> 32B big-endian canonical bytes
fn fp_to_be32_bytes(v: &Fp) -> [u8; 32] {
    let repr = v.to_repr();
    let mut be = [0u8; 32];
    be.copy_from_slice(repr.as_ref());
    be.reverse();
    be
}

#[derive(Clone, Debug)]
pub struct AcctToAnonTxConfig {
    poseidon: PoseidonHashConfig,
    ecc: SimpleEccConfig,
}

#[derive(Clone, Debug)]
pub struct AcctToAnonTxCircuit {
    sk_bytes: [Value<Fp>; 32],     // secret
    pk_bytes: [Value<Fp>; 32],     // secret, compressed pk bytes
    val_bytes: [Value<Fp>; 32],    // public
    nonce_bytes: [Value<Fp>; 32],  // public
    addr_bytes: [Value<Fp>; 32],   // public
    bits: [bool; NUM_BITS],
    base_points: [EpAffine; NUM_BITS],
}

impl Default for AcctToAnonTxCircuit {
    fn default() -> Self {
        AcctToAnonTxCircuit {
            sk_bytes: [Value::unknown(); 32],
            pk_bytes: [Value::unknown(); 32],
            val_bytes: [Value::unknown(); 32],
            nonce_bytes: [Value::unknown(); 32],
            addr_bytes: [Value::unknown(); 32],
            bits: [false; NUM_BITS],
            base_points: precompute_base_points(),
        }
    }
}

fn bytes_to_values(b: &[u8]) -> [Value<Fp>; 32] {
    let mut arr = [Value::unknown(); 32];
    for i in 0..32 {
        arr[i] = Value::known(Fp::from(b[i] as u64));
    }
    arr
}

fn assign_bytes32(
    cfg: &PoseidonHashConfig,
    mut layouter: impl Layouter<Fp>,
    name: &str,
    bytes: &[Value<Fp>; 32],
) -> Result<Vec<AssignedCell<Fp, Fp>>, Error> {
    layouter.assign_region(
        || name,
        |mut region| {
            let mut cells = Vec::with_capacity(32);
            for i in 0..32 {
                let cell = region.assign_advice(
                    || format!("{}_{}", name, i),
                    cfg.byte_col,
                    i,
                    || bytes[i],
                )?;
                cells.push(cell);
            }
            Ok(cells)
        },
    )
}

impl Circuit<Fp> for AcctToAnonTxCircuit {
    type Config = AcctToAnonTxConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        AcctToAnonTxCircuit::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let poseidon_cfg = PoseidonHashConfig::configure(meta);
        let ecc_cfg = SimpleEccConfig::configure(meta);

        AcctToAnonTxConfig {
            poseidon: poseidon_cfg,
            ecc: ecc_cfg,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // ---- public inputs: val / nonce / addr bytes -> fp ----
        let val_cells = assign_bytes32(
            &config.poseidon,
            layouter.namespace(|| "assign val bytes"),
            "val",
            &self.val_bytes,
        )?;
        let nonce_cells = assign_bytes32(
            &config.poseidon,
            layouter.namespace(|| "assign nonce bytes"),
            "nonce",
            &self.nonce_bytes,
        )?;
        let addr_cells = assign_bytes32(
            &config.poseidon,
            layouter.namespace(|| "assign addr bytes"),
            "addr",
            &self.addr_bytes,
        )?;

        let val_fp_cell = bytes32_to_fp_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "val bytes -> fp"),
            &val_cells,
        )?;
        let nonce_fp_cell = bytes32_to_fp_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "nonce bytes -> fp"),
            &nonce_cells,
        )?;
        let addr_fp_cell = bytes32_to_fp_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "addr bytes -> fp"),
            &addr_cells,
        )?;

        // expose public: row2=val_fp, row3=nonce_fp
        config.poseidon.expose_public(
            layouter.namespace(|| "expose val_fp"),
            &val_fp_cell,
            2usize,
        )?;
        config.poseidon.expose_public(
            layouter.namespace(|| "expose nonce_fp"),
            &nonce_fp_cell,
            3usize,
        )?;

        // ---- secret input: sk bytes -> fp ----
        let sk_cells = assign_bytes32(
            &config.poseidon,
            layouter.namespace(|| "assign sk bytes"),
            "sk",
            &self.sk_bytes,
        )?;
        let sk_fp_cell = bytes32_to_fp_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "sk bytes -> fp"),
            &sk_cells,
        )?;

        // ---- secret: pk bytes -> fp, then Poseidon(pk_fp) ----
        let pk_cells = assign_bytes32(
            &config.poseidon,
            layouter.namespace(|| "assign pk bytes"),
            "pk",
            &self.pk_bytes,
        )?;
        let pk_fp_cell = bytes32_to_fp_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "pk bytes -> fp"),
            &pk_cells,
        )?;
        let addr_from_pk_bytes_cell = hash_fp_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "poseidon(pk_fp)"),
            pk_fp_cell.clone(),
        )?;

        // ---- ECC mul kept but UNUSED (weak circuit does not bind it) ----
        let (_pk_x_cell, _pk_y_cell, _packed_bits_cell) = ecc_scalar_mul_region(
            &config.ecc,
            layouter.namespace(|| "ecc scalar mul"),
            &self.bits,
            &self.base_points,
        )?;

        // constrain derived addr(from pk bytes) == public addr
        layouter.assign_region(
            || "constrain derived addr == public addr (bytes)",
            |mut region| {
                region.constrain_equal(
                    addr_from_pk_bytes_cell.cell(),
                    addr_fp_cell.cell(),
                )
            },
        )?;

        // expose derived addr at row0 (= pin_addr)
        config.poseidon.expose_public(
            layouter.namespace(|| "expose derived addr"),
            &addr_from_pk_bytes_cell,
            0usize,
        )?;

        // ---- anon_commit = Poseidon(val, sk, nonce, addr) left-fold ----
        let t1 = hash_two_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "poseidon(val, sk)"),
            val_fp_cell.clone(),
            sk_fp_cell.clone(),
        )?;
        let t2 = hash_two_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "poseidon(t1, nonce)"),
            t1,
            nonce_fp_cell.clone(),
        )?;
        let anon_commit_cell = hash_two_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "poseidon(t2, addr)"),
            t2,
            addr_fp_cell.clone(),
        )?;

        // expose anon_commit at row1
        config.poseidon.expose_public(
            layouter.namespace(|| "expose anon_commit"),
            &anon_commit_cell,
            1usize,
        )?;

        Ok(())
    }
}

/// Evil CPU-side generator:
/// Public inputs derived internally as:
///   addr = Poseidon(pk_fp(sk_addr))
///   anon_commit = Poseidon(val_fp, sk_fp(sk_commit), nonce_fp, addr_fp)
fn zkproof_for_acct_to_anon_tx_evil_from_bytes(
    sk_commit_bytes: &[u8],
    sk_addr_bytes: &[u8],
    pin_val_bytes: &[u8],
    pin_nonce_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    if sk_commit_bytes.len() != 32 {
        return Err(format!("sk_commit must be 32 bytes, got {}", sk_commit_bytes.len()));
    }
    if sk_addr_bytes.len() != 32 {
        return Err(format!("sk_addr must be 32 bytes, got {}", sk_addr_bytes.len()));
    }
    if pin_val_bytes.len() != 32 {
        return Err(format!("pin_val must be 32 bytes, got {}", pin_val_bytes.len()));
    }
    if pin_nonce_bytes.len() != 32 {
        return Err(format!("pin_nonce must be 32 bytes, got {}", pin_nonce_bytes.len()));
    }

    // ---- sk_addr for pk/addr ----
    let sk_addr_scalar: Scalar = scalar_from_bytes_mod_order(sk_addr_bytes);
    let pk_point = Ep::generator() * sk_addr_scalar;
    let pk_bytes_repr = pk_point.to_bytes();
    let pk_bytes = pk_bytes_repr.as_ref();

    let pk_fp = bytes32_to_fp_mod_p(pk_bytes);
    let pk_fp_be = fp_to_be32_bytes(&pk_fp);
    let addr_bytes_vec = crate::poseidon_hash::poseidon_hash_bytes(&[pk_fp_be.as_slice()])
        .map_err(|e| format!("poseidon_hash_bytes(pk_fp) failed: {:?}", e))?;
    let addr_bytes = addr_bytes_vec.as_slice();

    // ---- sk_commit for anon_commit ----
    let val_fp_mod = bytes32_to_fp_mod_p(pin_val_bytes);
    let sk_commit_fp_mod = bytes32_to_fp_mod_p(sk_commit_bytes);
    let nonce_fp_mod = bytes32_to_fp_mod_p(pin_nonce_bytes);
    let addr_fp_mod = bytes32_to_fp_mod_p(addr_bytes);

    let val_be = fp_to_be32_bytes(&val_fp_mod);
    let sk_commit_be = fp_to_be32_bytes(&sk_commit_fp_mod);
    let nonce_be = fp_to_be32_bytes(&nonce_fp_mod);
    let addr_be = fp_to_be32_bytes(&addr_fp_mod);

    let anon_commit_vec = crate::poseidon_hash::poseidon_hash_bytes(
        &[val_be.as_slice(), sk_commit_be.as_slice(), nonce_be.as_slice(), addr_be.as_slice()],
    )
    .map_err(|e| format!("poseidon_hash_bytes(commit) failed: {:?}", e))?;
    let anon_commit_bytes = anon_commit_vec.as_slice();

    // bits witness + base_points
    // weak circuit doesn't constrain bits vs sk_bytes, so any bits ok
    let bits = scalar_to_bits_le(&sk_addr_scalar);
    let base_points = precompute_base_points();

    let circuit = AcctToAnonTxCircuit {
        sk_bytes: bytes_to_values(sk_commit_bytes),
        pk_bytes: bytes_to_values(pk_bytes),
        val_bytes: bytes_to_values(pin_val_bytes),
        nonce_bytes: bytes_to_values(pin_nonce_bytes),
        addr_bytes: bytes_to_values(addr_bytes),
        bits,
        base_points,
    };

    let params: Params<EqAffine> = Params::new(K);
    let empty_circuit = AcctToAnonTxCircuit::default();
    let vk = keygen_vk(&params, &empty_circuit)
        .map_err(|e| format!("keygen_vk: {:?}", e))?;
    let pk_prover = keygen_pk(&params, vk, &empty_circuit)
        .map_err(|e| format!("keygen_pk: {:?}", e))?;

    let addr_fp = be32_to_fp(addr_bytes)?;
    let anon_commit_fp = be32_to_fp(anon_commit_bytes)?;
    let val_fp = be32_to_fp(pin_val_bytes)?;
    let nonce_fp = be32_to_fp(pin_nonce_bytes)?;

    let instances: Vec<Vec<Fp>> = vec![
        vec![addr_fp, anon_commit_fp, val_fp, nonce_fp],
        vec![],
        vec![],
    ];

    let instance_slices: Vec<&[Fp]> = instances.iter().map(|v| v.as_slice()).collect();
    let instance_per_circuit: Vec<&[&[Fp]]> = vec![instance_slices.as_slice()];
    let instance_refs: &[&[&[Fp]]] = instance_per_circuit.as_slice();

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

    Ok(transcript.finalize())
}

#[pyfunction]
pub fn get_evil_zkproof_for_acct_to_anon_tx(
    py: Python,
    sk_commit: &PyBytes,
    sk_addr: &PyBytes,
    pin_val: &PyBytes,
    pin_nonce: &PyBytes,
) -> PyResult<PyObject> {
    let sk_commit_bytes = sk_commit.as_bytes();
    let sk_addr_bytes = sk_addr.as_bytes();
    let pin_val_bytes = pin_val.as_bytes();
    let pin_nonce_bytes = pin_nonce.as_bytes();

    match zkproof_for_acct_to_anon_tx_evil_from_bytes(
        sk_commit_bytes,
        sk_addr_bytes,
        pin_val_bytes,
        pin_nonce_bytes,
    ) {
        Ok(proof_vec) => Ok(PyBytes::new(py, &proof_vec).into()),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(e)),
    }
}

pub fn register_zkproof_for_acct_to_anon_tx_evil(m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get_evil_zkproof_for_acct_to_anon_tx, m)?)?;
    Ok(())
}
