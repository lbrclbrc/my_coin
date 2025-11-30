// zkcrypto/src/zkproof_for_acct_to_anon_tx_gen.rs
//
// STRONG generator for AcctToAnonTx.
// Fixes weak binding while KEEPING public addr semantics unchanged:
//   addr = Poseidon(pk_fp(pk_bytes(sk*G)))
//   anon_commit = Poseidon(val_fp, sk_fp(raw), nonce_fp, addr_fp)
//
// Strong binding added (no new external APIs):
//   raw sk_bytes  <->  q(0..3)  <->  bits (raw mod r)  <->  pk_coords  <->  pk_bytes(compressed)
//
// Public inputs layout unchanged:
//   poseidon.output: row0=addr_fp, row1=anon_commit_fp, row2=val_fp, row3=nonce_fp

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

use pasta_curves::{
    arithmetic::CurveAffine,
    group::{Curve, Group, GroupEncoding},
    pallas::{Affine as EpAffine, Point as Ep, Scalar},
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;
use rand_core::OsRng;

use crate::poseidon_chip::{
    bytes32_to_fp_in_circuit, hash_fp_in_circuit, hash_two_in_circuit, PoseidonHashConfig,
};
use crate::ecc_chip::{
    ecc_scalar_mul_region, precompute_base_points, scalar_from_bytes_mod_order,
    scalar_to_bits_le, SimpleEccConfig, NUM_BITS,
};

const K: u32 = 9;

// Pallas scalar field order r, big-endian bytes (same constant as python R)
const SCALAR_ORDER_BE: [u8; 32] = [
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x22, 0x46, 0x98, 0xfc, 0x09, 0x94, 0xa8, 0xdd,
    0x8c, 0x46, 0xeb, 0x21, 0x00, 0x00, 0x00, 0x01,
];

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
    bind_sel: Selector,
    pk_last_sel: Selector,
}

#[derive(Clone, Debug)]
pub struct AcctToAnonTxCircuit {
    sk_bytes: [Value<Fp>; 32],      // secret raw sk bytes (exactly sin_sk_bytes)
    pk_bytes: [Value<Fp>; 32],      // secret compressed pk bytes derived from same scalar
    pk_x_bytes_le: [Value<Fp>; 32], // secret little-endian x bytes (no sign bit)
    y_odd: Value<Fp>,               // secret boolean y parity bit (0/1)

    q: Value<Fp>,                   // secret small integer: 0/1/2/3

    val_bytes: [Value<Fp>; 32],     // public
    nonce_bytes: [Value<Fp>; 32],   // public
    addr_bytes: [Value<Fp>; 32],    // public

    bits: [bool; NUM_BITS],
    base_points: [EpAffine; NUM_BITS],
}

impl Default for AcctToAnonTxCircuit {
    fn default() -> Self {
        AcctToAnonTxCircuit {
            sk_bytes: [Value::unknown(); 32],
            pk_bytes: [Value::unknown(); 32],
            pk_x_bytes_le: [Value::unknown(); 32],
            y_odd: Value::unknown(),

            q: Value::unknown(),

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

// ---- helper: compare 32B big-endian a >= b ----
fn geq_be32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true
}

// ---- helper: big-endian subtraction a - b (assumes a>=b) ----
fn sub_be32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let ai = a[i] as i16;
        let bi = b[i] as i16;
        let mut v = ai - bi - borrow;
        if v < 0 {
            v += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = v as u8;
    }
    out
}

// ---- helper: compute q = floor(raw/r) with q in 0..3 ----
fn quotient_q_u64(raw_be: &[u8; 32]) -> u64 {
    let mut rem = *raw_be;
    let mut q: u64 = 0;
    while q < 3 && geq_be32(&rem, &SCALAR_ORDER_BE) {
        rem = sub_be32(&rem, &SCALAR_ORDER_BE);
        q += 1;
    }
    q
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
        let bind_sel = meta.selector();
        let pk_last_sel = meta.selector();

        // r mod p as Fp constant
        let r_mod_p = bytes32_to_fp_mod_p(&SCALAR_ORDER_BE);

        let one_fp = Fp::one();
        let two_fp = Fp::from(2u64);
        let three_fp = Fp::from(3u64);
        let c128 = Fp::from(128u64);

        // Gate: q in {0,1,2,3} and sk_raw = sk_adj + q*r (in Fp)
        meta.create_gate("bind sk_raw to bits via q(0..3)", |meta| {
            let s = meta.query_selector(bind_sel);

            // poseidon.input column layout:
            // row0: q
            // row1: sk_adj
            // row2: sk_raw_copy
            let q = meta.query_advice(poseidon_cfg.input, Rotation::cur());
            let sk_adj = meta.query_advice(poseidon_cfg.input, Rotation::next());
            let sk_raw = meta.query_advice(poseidon_cfg.input, Rotation(2));

            let r_const = Expression::Constant(r_mod_p);
            let c1 = Expression::Constant(one_fp);
            let c2 = Expression::Constant(two_fp);
            let c3 = Expression::Constant(three_fp);

            // q*(q-1)*(q-2)*(q-3)=0
            let range_check =
                q.clone()
                * (q.clone() - c1.clone())
                * (q.clone() - c2.clone())
                * (q.clone() - c3.clone());

            let bind_check = sk_raw - sk_adj - q * r_const;

            vec![
                s.clone() * range_check,
                s * bind_check,
            ]
        });

        // Gate for pk last byte parity:
        // y_odd in {0,1}, pk_last = x_last + y_odd*128
        meta.create_gate("bind pk last byte parity", |meta| {
            let s = meta.query_selector(pk_last_sel);

            // poseidon.input column:
            // row0: pk_last
            // row1: x_last
            // row2: y_odd
            let pk_last = meta.query_advice(poseidon_cfg.input, Rotation::cur());
            let x_last = meta.query_advice(poseidon_cfg.input, Rotation::next());
            let y_odd = meta.query_advice(poseidon_cfg.input, Rotation(2));

            let one_const = Expression::Constant(Fp::one());
            let c128_const = Expression::Constant(c128);

            let bool_check = y_odd.clone() * (one_const - y_odd.clone());
            let eq = pk_last - x_last - y_odd * c128_const;

            vec![ s.clone() * bool_check, s * eq ]
        });

        AcctToAnonTxConfig {
            poseidon: poseidon_cfg,
            ecc: ecc_cfg,
            bind_sel,
            pk_last_sel,
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

        // ---- secret input: raw sk bytes -> fp ----
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

        // ---- secret input: pk bytes -> fp, then Poseidon(pk_fp)  (KEEP OLD addr meaning) ----
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

        // ---- ECC: scalar mul from bits -> (pk_x, pk_y, packed_bits) ----
        let (pk_x_cell, pk_y_cell, packed_bits_cell) = ecc_scalar_mul_region(
            &config.ecc,
            layouter.namespace(|| "ecc scalar mul"),
            &self.bits,
            &self.base_points,
        )?;

        // ---- STRONG 1: bind raw sk bytes <-> bits via q(0..3) ----
        let r_mod_p = bytes32_to_fp_mod_p(&SCALAR_ORDER_BE);

        let (_q_cell, sk_adj_cell, sk_raw_copy_cell) = layouter.assign_region(
            || "bind sk_raw to bits via q",
            |mut region| {
                config.bind_sel.enable(&mut region, 0)?;

                let q_cell = region.assign_advice(
                    || "q",
                    config.poseidon.input,
                    0,
                    || self.q,
                )?;

                let sk_adj_val = sk_fp_cell.value().zip(self.q).map(|(sk_raw, q)| {
                    *sk_raw - r_mod_p * q
                });

                let sk_adj_cell = region.assign_advice(
                    || "sk_adj",
                    config.poseidon.input,
                    1,
                    || sk_adj_val,
                )?;

                let sk_raw_copy_cell = region.assign_advice(
                    || "sk_raw_copy",
                    config.poseidon.input,
                    2,
                    || sk_fp_cell.value().map(|v| *v),
                )?;

                Ok((q_cell, sk_adj_cell, sk_raw_copy_cell))
            },
        )?;

        // enforce sk_raw_copy == sk_fp_cell
        layouter.assign_region(
            || "constrain sk_raw_copy == sk_fp_cell",
            |mut region| {
                region.constrain_equal(sk_raw_copy_cell.cell(), sk_fp_cell.cell())
            },
        )?;

        // enforce packed_bits == sk_adj  (so bits == raw mod r)
        layouter.assign_region(
            || "constrain packed_bits == sk_adj",
            |mut region| {
                region.constrain_equal(packed_bits_cell.cell(), sk_adj_cell.cell())
            },
        )?;

        // ---- STRONG 2: bind pk_bytes(compressed) <-> pk_coords ----
        // We witness pk_x_bytes_le and y_odd on CPU side, then constrain:
        //   (a) pk_x_bytes_le packs to pk_x_cell
        //   (b) pk_bytes[0..30] == pk_x_bytes_le[0..30]
        //   (c) pk_bytes[31] == pk_x_bytes_le[31] + y_odd*128

        // assign pk_x little-endian bytes
        let x_le_cells = assign_bytes32(
            &config.poseidon,
            layouter.namespace(|| "assign pk_x bytes le"),
            "pkx_le",
            &self.pk_x_bytes_le,
        )?;

        // pack little-endian x bytes into Fp by reversing to big-endian for bytes32_to_fp_in_circuit
        let mut x_le_cells_rev = Vec::with_capacity(32);
        for i in (0..32).rev() {
            x_le_cells_rev.push(x_le_cells[i].clone());
        }
        let pk_x_from_le_cell = bytes32_to_fp_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "pk_x le bytes -> fp"),
            &x_le_cells_rev,
        )?;

        // enforce pk_x_from_le == pk_x_cell
        layouter.assign_region(
            || "constrain pk_x_from_le == pk_x",
            |mut region| {
                region.constrain_equal(pk_x_from_le_cell.cell(), pk_x_cell.cell())
            },
        )?;

        // enforce pk_bytes[0..30] == x_le_bytes[0..30]
        layouter.assign_region(
            || "constrain pk_bytes prefix == x_le",
            |mut region| {
                for i in 0..31 {
                    region.constrain_equal(pk_cells[i].cell(), x_le_cells[i].cell())?;
                }
                Ok(())
            },
        )?;

        // enforce last byte parity: pk_last = x_last + y_odd*128
        layouter.assign_region(
            || "bind pk last byte parity",
            |mut region| {
                config.pk_last_sel.enable(&mut region, 0)?;

                let pk_last_cell = region.assign_advice(
                    || "pk_last",
                    config.poseidon.input,
                    0,
                    || pk_cells[31].value().copied(),
                )?;
                let x_last_cell = region.assign_advice(
                    || "x_last",
                    config.poseidon.input,
                    1,
                    || x_le_cells[31].value().copied(),
                )?;
                let y_odd_cell = region.assign_advice(
                    || "y_odd",
                    config.poseidon.input,
                    2,
                    || self.y_odd,
                )?;

                // tie these input-column cells to the byte-column cells
                region.constrain_equal(pk_last_cell.cell(), pk_cells[31].cell())?;
                region.constrain_equal(x_last_cell.cell(), x_le_cells[31].cell())?;
                let _ = y_odd_cell;
                Ok(())
            },
        )?;

        // ---- bind derived addr(bytes) == public addr ----
        layouter.assign_region(
            || "constrain derived addr(bytes) == public addr",
            |mut region| {
                region.constrain_equal(
                    addr_from_pk_bytes_cell.cell(),
                    addr_fp_cell.cell(),
                )
            },
        )?;

        // expose derived addr at row0 (= pin_addr), KEEP OLD LAYOUT
        config.poseidon.expose_public(
            layouter.namespace(|| "expose derived addr"),
            &addr_from_pk_bytes_cell,
            0usize,
        )?;

        // ---- anon_commit = Poseidon(val, sk_raw_fp, nonce, addr) ----
        let t1 = hash_two_in_circuit(
            &config.poseidon,
            layouter.namespace(|| "poseidon(val, sk_raw)"),
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

        // pk_y_cell is intentionally unused as public; keep binding only through compression
        let _ = pk_y_cell;

        Ok(())
    }
}

/// CPU-side strong generator (public semantics unchanged)
fn zkproof_for_acct_to_anon_tx_from_bytes(
    sin_sk_bytes: &[u8],
    pin_val_bytes: &[u8],
    pin_nonce_bytes: &[u8],
    pin_addr_bytes: &[u8],
    pin_anon_commit_bytes: &[u8],
) -> Result<Vec<u8>, String> {

    if sin_sk_bytes.len() != 32 {
        return Err(format!("sin_sk must be 32 bytes, got {}", sin_sk_bytes.len()));
    }
    if pin_val_bytes.len() != 32 {
        return Err(format!("pin_val must be 32 bytes, got {}", pin_val_bytes.len()));
    }
    if pin_nonce_bytes.len() != 32 {
        return Err(format!("pin_nonce must be 32 bytes, got {}", pin_nonce_bytes.len()));
    }
    if pin_addr_bytes.len() != 32 {
        return Err(format!("pin_addr must be 32 bytes, got {}", pin_addr_bytes.len()));
    }
    if pin_anon_commit_bytes.len() != 32 {
        return Err(format!("pin_anon_commit must be 32 bytes, got {}", pin_anon_commit_bytes.len()));
    }

    // raw bytes (big-endian integer) -> scalar mod r   (protocol definition)
    let sk_scalar: Scalar = scalar_from_bytes_mod_order(sin_sk_bytes);

    // compute q = floor(raw/r), q in 0..3
    let mut raw_be = [0u8; 32];
    raw_be.copy_from_slice(sin_sk_bytes);
    let q_u64: u64 = quotient_q_u64(&raw_be);
    let q_fp = Fp::from(q_u64);

    // pk from scalar
    let pk_point = Ep::generator() * sk_scalar;
    let pk_bytes_repr = pk_point.to_bytes();
    let pk_bytes = pk_bytes_repr.as_ref();

    // derive x_le bytes and y parity from pk coords (CPU witness)
    let pk_aff = pk_point.to_affine();
    let mut x_le_bytes = [0u8; 32];
    let y_odd_u64: u64;

    let coords_ct = pk_aff.coordinates();
    if bool::from(coords_ct.is_some()) {
        let coords = coords_ct.unwrap();
        let x_repr = coords.x().to_repr();   // little-endian
        x_le_bytes.copy_from_slice(x_repr.as_ref());

        let y_repr = coords.y().to_repr();   // little-endian
        let y_bytes = y_repr.as_ref();
        y_odd_u64 = (y_bytes[0] & 1) as u64;

        // optional CPU sanity check: compressed format is x_le with msb of last byte set by y_odd
        let mut check = x_le_bytes;
        if y_odd_u64 == 1 {
            check[31] |= 0x80;
        }
        if check.as_slice() != pk_bytes {
            return Err("pk_bytes encoding mismatch with assumed compression".to_string());
        }
    } else {
        // identity: pk_bytes should be all-zero, x bytes all-zero, y_odd=0
        for i in 0..32 {
            if pk_bytes[i] != 0 {
                return Err("identity pk_bytes not all zero".to_string());
            }
        }
        y_odd_u64 = 0;
    }

    // (1) derived_addr = Poseidon(pk_fp(pk_bytes))  [same as old]
    let pk_fp = bytes32_to_fp_mod_p(pk_bytes);
    let pk_fp_be = fp_to_be32_bytes(&pk_fp);

    let derived_addr_bytes = crate::poseidon_hash::poseidon_hash_bytes(&[pk_fp_be.as_slice()])
        .map_err(|e| format!("poseidon_hash_bytes(pk_fp) failed: {:?}", e))?;
    if derived_addr_bytes.as_slice() != pin_addr_bytes {
        return Err("pin_addr does not match Poseidon(pk_fp) derived from sin_sk".to_string());
    }

    // (2) anon_commit = Poseidon(val_fp, sk_fp(raw), nonce_fp, addr_fp)
    let val_fp_mod = bytes32_to_fp_mod_p(pin_val_bytes);
    let sk_fp_mod = bytes32_to_fp_mod_p(sin_sk_bytes); // IMPORTANT: raw sk bytes
    let nonce_fp_mod = bytes32_to_fp_mod_p(pin_nonce_bytes);
    let addr_fp_mod = bytes32_to_fp_mod_p(pin_addr_bytes);

    let val_be = fp_to_be32_bytes(&val_fp_mod);
    let sk_be = fp_to_be32_bytes(&sk_fp_mod);
    let nonce_be = fp_to_be32_bytes(&nonce_fp_mod);
    let addr_be = fp_to_be32_bytes(&addr_fp_mod);

    let anon_commit_bytes = crate::poseidon_hash::poseidon_hash_bytes(
        &[val_be.as_slice(), sk_be.as_slice(), nonce_be.as_slice(), addr_be.as_slice()],
    )
    .map_err(|e| format!("poseidon_hash_bytes(commit) failed: {:?}", e))?;
    if anon_commit_bytes.as_slice() != pin_anon_commit_bytes {
        return Err("pin_anon_commit does not match Poseidon(val, sk, nonce, addr)".to_string());
    }

    // witnesses: bits from scalar and base points
    let bits = scalar_to_bits_le(&sk_scalar);
    let base_points = precompute_base_points();

    let circuit = AcctToAnonTxCircuit {
        sk_bytes: bytes_to_values(sin_sk_bytes),      // raw bytes
        pk_bytes: bytes_to_values(pk_bytes),          // compressed pk bytes
        pk_x_bytes_le: bytes_to_values(&x_le_bytes),  // x le bytes
        y_odd: Value::known(Fp::from(y_odd_u64)),

        q: Value::known(q_fp),

        val_bytes: bytes_to_values(pin_val_bytes),
        nonce_bytes: bytes_to_values(pin_nonce_bytes),
        addr_bytes: bytes_to_values(pin_addr_bytes),

        bits,
        base_points,
    };

    let params: Params<EqAffine> = Params::new(K);
    let empty_circuit = AcctToAnonTxCircuit::default();
    let vk = keygen_vk(&params, &empty_circuit)
        .map_err(|e| format!("keygen_vk: {:?}", e))?;
    let pk_prover = keygen_pk(&params, vk, &empty_circuit)
        .map_err(|e| format!("keygen_pk: {:?}", e))?;

    let addr_fp = be32_to_fp(pin_addr_bytes)?;
    let anon_commit_fp = be32_to_fp(pin_anon_commit_bytes)?;
    let val_fp = be32_to_fp(pin_val_bytes)?;
    let nonce_fp = be32_to_fp(pin_nonce_bytes)?;

    // instances layout unchanged:
    //   poseidon.output: row0=addr_fp, row1=anon_commit_fp, row2=val_fp, row3=nonce_fp
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
pub fn get_zkproof_for_acct_to_anon_tx(
    py: Python,
    sin_sk: &PyBytes,
    pin_val: &PyBytes,
    pin_nonce: &PyBytes,
    pin_addr: &PyBytes,
    pin_anon_commit: &PyBytes,
) -> PyResult<PyObject> {
    let sin_sk_bytes = sin_sk.as_bytes();
    let pin_val_bytes = pin_val.as_bytes();
    let pin_nonce_bytes = pin_nonce.as_bytes();
    let pin_addr_bytes = pin_addr.as_bytes();
    let pin_anon_commit_bytes = pin_anon_commit.as_bytes();

    match zkproof_for_acct_to_anon_tx_from_bytes(
        sin_sk_bytes,
        pin_val_bytes,
        pin_nonce_bytes,
        pin_addr_bytes,
        pin_anon_commit_bytes,
    ) {
        Ok(proof_vec) => Ok(PyBytes::new(py, &proof_vec).into()),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(e)),
    }
}

pub fn register_zkproof_for_acct_to_anon_tx_apply(m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get_zkproof_for_acct_to_anon_tx, m)?)?;
    Ok(())
}
