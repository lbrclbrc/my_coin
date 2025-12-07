// zkcrypto/src/zkproof_for_anon_pay_gen.rs
//
// ZK proof generator for "AnonPay".
//
// Public inputs (32B each):
//   pin_commit_root
//   pin_nullifier
//   pin_commit_change
//   pin_value_pay
//
// Secret inputs (32B each unless noted):
//   sin_value_initial
//   sin_value_change
//   sin_sk
//   sin_nonce_initial
//   sin_src
//   sin_path_siblings[32]   (each 32B hex)
//   sin_path_dirs[32]       (0/1, secret)
//
// Statement proved:
//  A) old_commit = Poseidon(value_initial, sk, nonce_initial, src)
//     and old_commit is in public Merkle tree with root = pin_commit_root.
//  B) nullifier = Poseidon(sk, nonce_initial, src) == pin_nullifier.
//  C) commit_change = Poseidon(value_change, sk, ZERO32, pin_nullifier) == pin_commit_change.
//  D) value_initial = value_change + value_pay  (in Fp)
//
// Merkle direction:
//   dir = 0 => sibling on RIGHT, parent = H(cur, sib)
//   dir = 1 => sibling on LEFT,  parent = H(sib, cur)
//

use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    pasta::{EqAffine, Fp},
    plonk::{
        create_proof, keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error, Selector,
        Expression,
    },
    poly::commitment::Params,
    transcript::{Blake2bWrite, Challenge255},
};
use halo2_proofs::poly::Rotation;

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;
use rand_core::OsRng;

use crate::poseidon_chip::{
    bytes32_to_fp_in_circuit, hash_bytes_in_circuit, hash_two_in_circuit,
    PoseidonHashConfig,
};

// fixed merkle depth
const DEPTH: usize = 32;
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

#[derive(Clone, Debug)]
pub struct AnonPayConfig {
    poseidon: PoseidonHashConfig,
    merkle_sel: Selector,
    balance_sel: Selector,
}

#[derive(Clone, Debug)]
pub struct AnonPayCircuit {
    // public bytes
    commit_root_bytes: [Value<Fp>; 32],
    nullifier_bytes: [Value<Fp>; 32],
    commit_change_bytes: [Value<Fp>; 32],
    value_pay_bytes: [Value<Fp>; 32],

    // secret bytes
    value_initial_bytes: [Value<Fp>; 32],
    value_change_bytes: [Value<Fp>; 32],
    sk_bytes: [Value<Fp>; 32],
    nonce_initial_bytes: [Value<Fp>; 32],
    src_bytes: [Value<Fp>; 32],

    // merkle path
    path_siblings_bytes: Vec<[Value<Fp>; 32]>,
    path_dirs: [bool; DEPTH],
}

impl Default for AnonPayCircuit {
    fn default() -> Self {
        AnonPayCircuit {
            commit_root_bytes: [Value::unknown(); 32],
            nullifier_bytes: [Value::unknown(); 32],
            commit_change_bytes: [Value::unknown(); 32],
            value_pay_bytes: [Value::unknown(); 32],

            value_initial_bytes: [Value::unknown(); 32],
            value_change_bytes: [Value::unknown(); 32],
            sk_bytes: [Value::unknown(); 32],
            nonce_initial_bytes: [Value::unknown(); 32],
            src_bytes: [Value::unknown(); 32],

            path_siblings_bytes: vec![[Value::unknown(); 32]; DEPTH],
            path_dirs: [false; DEPTH],
        }
    }
}

impl Circuit<Fp> for AnonPayCircuit {
    type Config = AnonPayConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        AnonPayCircuit::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let poseidon_cfg = PoseidonHashConfig::configure(meta);

        let merkle_sel = meta.selector();
        let balance_sel = meta.selector();

        let one = Fp::one();

        meta.create_gate("merkle select left/right", |meta| {
            let s = meta.query_selector(merkle_sel);

            let dir = meta.query_advice(poseidon_cfg.input, Rotation::cur());
            let cur = meta.query_advice(poseidon_cfg.input, Rotation::next());
            let sib = meta.query_advice(poseidon_cfg.input, Rotation(2));
            let left = meta.query_advice(poseidon_cfg.input, Rotation(3));
            let right = meta.query_advice(poseidon_cfg.input, Rotation(4));

            let one_const = Expression::Constant(one);

            let bool_check = dir.clone() * (one_const.clone() - dir.clone());

            let left_eq = left - (cur.clone() + dir.clone() * (sib.clone() - cur.clone()));
            let right_eq = right - (sib.clone() + dir * (cur - sib));

            vec![
                s.clone() * bool_check,
                s.clone() * left_eq,
                s * right_eq,
            ]
        });

        meta.create_gate("value balance", |meta| {
            let s = meta.query_selector(balance_sel);
            let v_init = meta.query_advice(poseidon_cfg.input, Rotation::cur());
            let v_change = meta.query_advice(poseidon_cfg.input, Rotation::next());
            let v_pay = meta.query_advice(poseidon_cfg.input, Rotation(2));

            vec![
                s.clone() * (v_init - v_change - v_pay),

                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(3)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(4)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(5)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(6)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(7)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(8)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(9)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(10)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(11)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(12)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(13)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(14)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(15)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(16)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(17)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(18)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(19)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(20)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(21)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(22)),

                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(23)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(24)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(25)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(26)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(27)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(28)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(29)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(30)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(31)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(32)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(33)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(34)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(35)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(36)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(37)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(38)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(39)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(40)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(41)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(42)),

                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(43)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(44)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(45)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(46)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(47)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(48)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(49)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(50)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(51)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(52)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(53)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(54)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(55)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(56)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(57)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(58)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(59)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(60)),
                s.clone() * meta.query_advice(poseidon_cfg.input, Rotation(61)),
                s * meta.query_advice(poseidon_cfg.input, Rotation(62)),
            ]
        });

        AnonPayConfig {
            poseidon: poseidon_cfg,
            merkle_sel,
            balance_sel,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {

        // ---------- assign public bytes ----------
        let root_cells = assign_bytes32(
            &config.poseidon,
            layouter.namespace(|| "assign commit_root bytes"),
            "root",
            &self.commit_root_bytes,
        )?;
        let nullifier_cells = assign_bytes32(
            &config.poseidon,
            layouter.namespace(|| "assign nullifier bytes"),
            "nullifier",
            &self.nullifier_bytes,
        )?;
        let change_cells = assign_bytes32(
            &config.poseidon,
            layouter.namespace(|| "assign commit_change bytes"),
            "commit_change",
            &self.commit_change_bytes,
        )?;
        let pay_cells = assign_bytes32(
            &config.poseidon,
            layouter.namespace(|| "assign value_pay bytes"),
            "value_pay",
            &self.value_pay_bytes,
        )?;

        let root_fp_cell = bytes32_to_fp_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "root bytes -> fp"),
            &root_cells,
        )?;
        let nullifier_fp_cell = bytes32_to_fp_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "nullifier bytes -> fp"),
            &nullifier_cells,
        )?;
        let change_fp_cell = bytes32_to_fp_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "commit_change bytes -> fp"),
            &change_cells,
        )?;
        let pay_fp_cell = bytes32_to_fp_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "value_pay bytes -> fp"),
            &pay_cells,
        )?;

        config.poseidon.expose_public(layouter.namespace(|| "expose root"), &root_fp_cell, 0)?;
        config.poseidon.expose_public(layouter.namespace(|| "expose nullifier"), &nullifier_fp_cell, 1)?;
        config.poseidon.expose_public(layouter.namespace(|| "expose commit_change"), &change_fp_cell, 2)?;
        config.poseidon.expose_public(layouter.namespace(|| "expose value_pay"), &pay_fp_cell, 3)?;

        // ---------- assign secret bytes ----------
        let vinit_cells = assign_bytes32(
            &config.poseidon,
            layouter.namespace(|| "assign value_initial bytes"),
            "vinit",
            &self.value_initial_bytes,
        )?;
        let vchange_cells = assign_bytes32(
            &config.poseidon,
            layouter.namespace(|| "assign value_change bytes"),
            "vchange",
            &self.value_change_bytes,
        )?;
        let sk_cells = assign_bytes32(
            &config.poseidon,
            layouter.namespace(|| "assign sk bytes"),
            "sk",
            &self.sk_bytes,
        )?;
        let nonce_cells = assign_bytes32(
            &config.poseidon,
            layouter.namespace(|| "assign nonce_initial bytes"),
            "nonce_init",
            &self.nonce_initial_bytes,
        )?;
        let src_cells = assign_bytes32(
            &config.poseidon,
            layouter.namespace(|| "assign src bytes"),
            "src",
            &self.src_bytes,
        )?;

        // ---------- compute derived nullifier = H(sk, nonce_init, src) ----------
        let mut nf_bytes = Vec::with_capacity(96);
        nf_bytes.extend_from_slice(&sk_cells);
        nf_bytes.extend_from_slice(&nonce_cells);
        nf_bytes.extend_from_slice(&src_cells);

        let derived_nullifier_cell = hash_bytes_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "poseidon(sk, nonce_init, src)"),
            &nf_bytes,
        )?;

        layouter.assign_region(
            || "constrain derived_nullifier == public nullifier",
            |mut region| region.constrain_equal(derived_nullifier_cell.cell(), nullifier_fp_cell.cell()),
        )?;

        // ---------- compute old_commit = H(vinit, sk, nonce_init, src) ----------
        let mut old_commit_bytes = Vec::with_capacity(128);
        old_commit_bytes.extend_from_slice(&vinit_cells);
        old_commit_bytes.extend_from_slice(&sk_cells);
        old_commit_bytes.extend_from_slice(&nonce_cells);
        old_commit_bytes.extend_from_slice(&src_cells);

        let old_commit_cell = hash_bytes_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "poseidon(vinit, sk, nonce_init, src)"),
            &old_commit_bytes,
        )?;

        // ---------- commit_change uses ZERO32 nonce ----------
        let zero_bytes = [Value::known(Fp::zero()); 32];
        let zero_cells = assign_bytes32(
            &config.poseidon,
            layouter.namespace(|| "assign zero nonce bytes"),
            "zero_nonce",
            &zero_bytes,
        )?;

        let mut change_bytes = Vec::with_capacity(128);
        change_bytes.extend_from_slice(&vchange_cells);
        change_bytes.extend_from_slice(&sk_cells);
        change_bytes.extend_from_slice(&zero_cells);
        change_bytes.extend_from_slice(&nullifier_cells);

        let derived_change_cell = hash_bytes_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "poseidon(vchange, sk, 0, nullifier)"),
            &change_bytes,
        )?;

        layouter.assign_region(
            || "constrain derived_change == public commit_change",
            |mut region| region.constrain_equal(derived_change_cell.cell(), change_fp_cell.cell()),
        )?;

        // ---------- value balance ----------
        let vinit_fp_cell = bytes32_to_fp_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "vinit bytes -> fp"),
            &vinit_cells,
        )?;
        let vchange_fp_cell = bytes32_to_fp_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "vchange bytes -> fp"),
            &vchange_cells,
        )?;

        layouter.assign_region(
            || "value balance region",
            |mut region| {
                config.balance_sel.enable(&mut region, 0)?;

                let vinit_copy = region.assign_advice(|| "vinit_copy", config.poseidon.input, 0, || vinit_fp_cell.value().copied())?;
                let vchange_copy = region.assign_advice(|| "vchange_copy", config.poseidon.input, 1, || vchange_fp_cell.value().copied())?;
                let vpay_copy = region.assign_advice(|| "vpay_copy", config.poseidon.input, 2, || pay_fp_cell.value().copied())?;

                region.constrain_equal(vinit_copy.cell(), vinit_fp_cell.cell())?;
                region.constrain_equal(vchange_copy.cell(), vchange_fp_cell.cell())?;
                region.constrain_equal(vpay_copy.cell(), pay_fp_cell.cell())?;

                let mut i = 0;
                while i < 20 {
                    let vinit_copy = region.assign_advice(|| "vinit_copy", config.poseidon.input, 3 + i, || vinit_cells[i].value().copied())?;
                    region.constrain_equal(vinit_copy.cell(), vinit_cells[i].cell())?;
                    i += 1;
                }

                let mut i = 0;
                while i < 20 {
                    let vchange_copy = region.assign_advice(|| "vchange_copy", config.poseidon.input, 23 + i, || vchange_cells[i].value().copied())?;
                    region.constrain_equal(vchange_copy.cell(), vchange_cells[i].cell())?;
                    i += 1;
                }

                let mut i = 0;
                while i < 20 {
                    let vpay_copy = region.assign_advice(|| "vpay_copy", config.poseidon.input, 43 + i, || pay_cells[i].value().copied())?;
                    region.constrain_equal(vpay_copy.cell(), pay_cells[i].cell())?;
                    i += 1;
                }

                Ok(())
            },
        )?;

        // ---------- Merkle path ----------
        let mut cur_cell = old_commit_cell;

        for i in 0..DEPTH {
            let sib_cells = assign_bytes32(
                &config.poseidon,
                layouter.namespace(|| format!("assign sibling bytes {}", i)),
                "sib",
                &self.path_siblings_bytes[i],
            )?;
            let sib_fp_cell = bytes32_to_fp_in_circuit(
                &config.poseidon,
                layouter.namespace(|| format!("sibling bytes -> fp {}", i)),
                &sib_cells,
            )?;

            let dir_fp = if self.path_dirs[i] { Fp::one() } else { Fp::zero() };

            let (left_cell, right_cell) = layouter.assign_region(
                || format!("merkle select {}", i),
                |mut region| {
                    config.merkle_sel.enable(&mut region, 0)?;

                    let dir_cell = region.assign_advice(|| "dir", config.poseidon.input, 0, || Value::known(dir_fp))?;
                    let cur_copy = region.assign_advice(|| "cur", config.poseidon.input, 1, || cur_cell.value().copied())?;
                    let sib_copy = region.assign_advice(|| "sib", config.poseidon.input, 2, || sib_fp_cell.value().copied())?;

                    let left_val = cur_cell.value().zip(sib_fp_cell.value()).map(|(c, s)| *c + dir_fp * (*s - *c));
                    let left_cell = region.assign_advice(|| "left", config.poseidon.input, 3, || left_val)?;

                    let right_val = cur_cell.value().zip(sib_fp_cell.value()).map(|(c, s)| *s + dir_fp * (*c - *s));
                    let right_cell = region.assign_advice(|| "right", config.poseidon.input, 4, || right_val)?;

                    region.constrain_equal(cur_copy.cell(), cur_cell.cell())?;
                    region.constrain_equal(sib_copy.cell(), sib_fp_cell.cell())?;
                    let _ = dir_cell;
                    Ok((left_cell, right_cell))
                },
            )?;

            let parent_cell = hash_two_in_circuit(
                &config.poseidon,
                layouter.namespace(|| format!("poseidon merkle parent {}", i)),
                left_cell,
                right_cell,
            )?;
            cur_cell = parent_cell;
        }

        layouter.assign_region(
            || "constrain merkle root",
            |mut region| region.constrain_equal(cur_cell.cell(), root_fp_cell.cell()),
        )?;

        Ok(())
    }
}

/// CPU-side generator
fn zkproof_for_anon_pay_from_bytes(
    pin_commit_root: &[u8],
    pin_nullifier: &[u8],
    pin_commit_change: &[u8],
    pin_value_pay: &[u8],

    sin_value_initial: &[u8],
    sin_value_change: &[u8],
    sin_sk: &[u8],
    sin_nonce_initial: &[u8],
    sin_src: &[u8],

    sin_path_siblings: &[Vec<u8>],
    sin_path_dirs: &[u8],
) -> Result<Vec<u8>, String> {
    if pin_commit_root.len() != 32 { return Err("pin_commit_root must be 32 bytes".to_string()); }
    if pin_nullifier.len() != 32 { return Err("pin_nullifier must be 32 bytes".to_string()); }
    if pin_commit_change.len() != 32 { return Err("pin_commit_change must be 32 bytes".to_string()); }
    if pin_value_pay.len() != 32 { return Err("pin_value_pay must be 32 bytes".to_string()); }

    if sin_value_initial.len() != 32 { return Err("sin_value_initial must be 32 bytes".to_string()); }
    if sin_value_change.len() != 32 { return Err("sin_value_change must be 32 bytes".to_string()); }
    if sin_sk.len() != 32 { return Err("sin_sk must be 32 bytes".to_string()); }
    if sin_nonce_initial.len() != 32 { return Err("sin_nonce_initial must be 32 bytes".to_string()); }
    if sin_src.len() != 32 { return Err("sin_src must be 32 bytes".to_string()); }

    if sin_path_siblings.len() != DEPTH { return Err("sin_path_siblings must be length 32".to_string()); }
    if sin_path_dirs.len() != DEPTH { return Err("sin_path_dirs must be length 32".to_string()); }

    // canonicalize like circuit
    let vinit_fp_mod = bytes32_to_fp_mod_p(sin_value_initial);
    let vchange_fp_mod = bytes32_to_fp_mod_p(sin_value_change);
    let sk_fp_mod = bytes32_to_fp_mod_p(sin_sk);
    let nonce_fp_mod = bytes32_to_fp_mod_p(sin_nonce_initial);
    let src_fp_mod = bytes32_to_fp_mod_p(sin_src);

    let vinit_be = fp_to_be32_bytes(&vinit_fp_mod);
    let vchange_be = fp_to_be32_bytes(&vchange_fp_mod);
    let sk_be = fp_to_be32_bytes(&sk_fp_mod);
    let nonce_be = fp_to_be32_bytes(&nonce_fp_mod);
    let src_be = fp_to_be32_bytes(&src_fp_mod);

    let nullifier_fp_mod = bytes32_to_fp_mod_p(pin_nullifier);
    let nullifier_be = fp_to_be32_bytes(&nullifier_fp_mod);

    let vpay_fp_mod = bytes32_to_fp_mod_p(pin_value_pay);

    // old_commit = H(vinit, sk, nonce_init, src)
    let old_commit = crate::poseidon_hash::poseidon_hash_bytes(
        &[vinit_be.as_slice(), sk_be.as_slice(), nonce_be.as_slice(), src_be.as_slice()],
    ).map_err(|e| format!("poseidon old_commit failed: {:?}", e))?;

    // nullifier = H(sk, nonce_init, src)
    let derived_nullifier = crate::poseidon_hash::poseidon_hash_bytes(
        &[sk_be.as_slice(), nonce_be.as_slice(), src_be.as_slice()],
    ).map_err(|e| format!("poseidon nullifier failed: {:?}", e))?;
    if derived_nullifier.as_slice() != pin_nullifier {
        return Err("pin_nullifier mismatch".to_string());
    }

    // commit_change = H(vchange, sk, 0, nullifier_pub)
    let zero_be = fp_to_be32_bytes(&Fp::zero());
    let derived_change = crate::poseidon_hash::poseidon_hash_bytes(
        &[vchange_be.as_slice(), sk_be.as_slice(), zero_be.as_slice(), nullifier_be.as_slice()],
    ).map_err(|e| format!("poseidon commit_change failed: {:?}", e))?;
    if derived_change.as_slice() != pin_commit_change {
        return Err("pin_commit_change mismatch".to_string());
    }

    // vinit = vchange + vpay
    if vinit_fp_mod != vchange_fp_mod + vpay_fp_mod {
        return Err("value_initial != value_change + value_pay".to_string());
    }

    // merkle root mirror
    let mut cur_fp_mod = bytes32_to_fp_mod_p(old_commit.as_slice());
    let mut cur_be = fp_to_be32_bytes(&cur_fp_mod);

    for i in 0..DEPTH {
        let sib = &sin_path_siblings[i];
        if sib.len() != 32 { return Err("each sibling must be 32 bytes".to_string()); }

        let sib_fp_mod = bytes32_to_fp_mod_p(sib.as_slice());
        let sib_be = fp_to_be32_bytes(&sib_fp_mod);

        let dir = sin_path_dirs[i];
        let parent = if dir == 0 {
            crate::poseidon_hash::poseidon_hash_bytes(&[cur_be.as_slice(), sib_be.as_slice()])
        } else {
            crate::poseidon_hash::poseidon_hash_bytes(&[sib_be.as_slice(), cur_be.as_slice()])
        }.map_err(|e| format!("poseidon merkle parent failed: {:?}", e))?;

        cur_fp_mod = bytes32_to_fp_mod_p(parent.as_slice());
        cur_be = fp_to_be32_bytes(&cur_fp_mod);
    }
    if cur_be.as_slice() != pin_commit_root {
        return Err("pin_commit_root mismatch".to_string());
    }

    // witnesses
    let mut sib_values: Vec<[Value<Fp>; 32]> = Vec::with_capacity(DEPTH);
    for i in 0..DEPTH {
        sib_values.push(bytes_to_values(&sin_path_siblings[i]));
    }

    let mut dir_bools = [false; DEPTH];
    for i in 0..DEPTH {
        dir_bools[i] = sin_path_dirs[i] == 1;
    }

    let circuit = AnonPayCircuit {
        commit_root_bytes: bytes_to_values(pin_commit_root),
        nullifier_bytes: bytes_to_values(pin_nullifier),
        commit_change_bytes: bytes_to_values(pin_commit_change),
        value_pay_bytes: bytes_to_values(pin_value_pay),

        value_initial_bytes: bytes_to_values(sin_value_initial),
        value_change_bytes: bytes_to_values(sin_value_change),
        sk_bytes: bytes_to_values(sin_sk),
        nonce_initial_bytes: bytes_to_values(sin_nonce_initial),
        src_bytes: bytes_to_values(sin_src),

        path_siblings_bytes: sib_values,
        path_dirs: dir_bools,
    };

    let params: Params<EqAffine> = Params::new(K);
    let empty_circuit = AnonPayCircuit::default();

    let vk = keygen_vk(&params, &empty_circuit).map_err(|e| format!("keygen_vk: {:?}", e))?;
    let pk = keygen_pk(&params, vk, &empty_circuit).map_err(|e| format!("keygen_pk: {:?}", e))?;

    let root_fp = be32_to_fp(pin_commit_root)?;
    let nullifier_fp = be32_to_fp(pin_nullifier)?;
    let change_fp = be32_to_fp(pin_commit_change)?;
    let vpay_fp = be32_to_fp(pin_value_pay)?;

    let instances: Vec<Vec<Fp>> = vec![
        vec![root_fp, nullifier_fp, change_fp, vpay_fp],
    ];

    let instance_slices: Vec<&[Fp]> = instances.iter().map(|v| v.as_slice()).collect();
    let instance_per_circuit: Vec<&[&[Fp]]> = vec![instance_slices.as_slice()];
    let instance_refs: &[&[&[Fp]]] = instance_per_circuit.as_slice();

    let mut transcript =
        Blake2bWrite::<Vec<u8>, EqAffine, Challenge255<EqAffine>>::init(vec![]);

    let proof_res = create_proof(
        &params,
        &pk,
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
pub fn get_zkproof_for_anon_pay(
    py: Python,
    pin_commit_root: &PyBytes,
    pin_nullifier: &PyBytes,
    pin_commit_change: &PyBytes,
    pin_value_pay: &PyBytes,

    sin_value_initial: &PyBytes,
    sin_value_change: &PyBytes,
    sin_sk: &PyBytes,
    sin_nonce_initial: &PyBytes,
    sin_src: &PyBytes,

    sin_path_siblings: &PyAny,
    sin_path_dirs: &PyAny,
) -> PyResult<PyObject> {

    let pin_commit_root_bytes = pin_commit_root.as_bytes();
    let pin_nullifier_bytes = pin_nullifier.as_bytes();
    let pin_commit_change_bytes = pin_commit_change.as_bytes();
    let pin_value_pay_bytes = pin_value_pay.as_bytes();

    let sin_value_initial_bytes = sin_value_initial.as_bytes();
    let sin_value_change_bytes = sin_value_change.as_bytes();
    let sin_sk_bytes = sin_sk.as_bytes();
    let sin_nonce_initial_bytes = sin_nonce_initial.as_bytes();
    let sin_src_bytes = sin_src.as_bytes();

    let sibs_vec: Vec<Vec<u8>> = sin_path_siblings.extract()
        .map_err(|_| PyErr::new::<pyo3::exceptions::PyTypeError, _>("sin_path_siblings must be List[bytes]"))?;
    let dirs_vec: Vec<u8> = sin_path_dirs.extract()
        .map_err(|_| PyErr::new::<pyo3::exceptions::PyTypeError, _>("sin_path_dirs must be List[int]"))?;

    match zkproof_for_anon_pay_from_bytes(
        pin_commit_root_bytes,
        pin_nullifier_bytes,
        pin_commit_change_bytes,
        pin_value_pay_bytes,

        sin_value_initial_bytes,
        sin_value_change_bytes,
        sin_sk_bytes,
        sin_nonce_initial_bytes,
        sin_src_bytes,

        &sibs_vec,
        &dirs_vec,
    ) {
        Ok(proof_vec) => Ok(PyBytes::new(py, &proof_vec).into()),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(e)),
    }
}

pub fn register_zkproof_for_anon_pay_apply(m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get_zkproof_for_anon_pay, m)?)?;
    Ok(())
}
