// zkcrypto/src/ecc_chip.rs
use ff::PrimeField;
use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, Value},
    pasta::Fp,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};
use pasta_curves::{
    arithmetic::CurveAffine,
    group::{prime::PrimeCurveAffine, Curve, Group},
    pallas::{Affine as EpAffine, Point as Ep, Scalar},
};

pub const NUM_BITS: usize = 255;

/// Expand a scalar into a little-endian bit array truncated to NUM_BITS.
pub fn scalar_to_bits_le(s: &Scalar) -> [bool; NUM_BITS] {
    let repr = s.to_repr();
    let bytes = repr.as_ref();
    let mut bits = [false; NUM_BITS];
    let mut i = 0usize;
    for &b in bytes.iter() {
        for j in 0..8 {
            if i >= NUM_BITS {
                break;
            }
            bits[i] = ((b >> j) & 1u8) == 1;
            i += 1;
        }
        if i >= NUM_BITS {
            break;
        }
    }
    bits
}

pub fn precompute_base_points() -> [EpAffine; NUM_BITS] {
    let mut res = [<EpAffine as PrimeCurveAffine>::identity(); NUM_BITS];
    let mut p = Ep::generator();
    for i in 0..NUM_BITS {
        res[i] = p.to_affine();
        p = p.double();
    }
    res
}

/// Map arbitrary bytes to a scalar by interpreting them as an integer modulo the group order.
pub fn scalar_from_bytes_mod_order(bytes: &[u8]) -> Scalar {
    let mut acc = Scalar::zero();
    let mut base = Scalar::one();
    let base_256 = Scalar::from(256u64);

    for b in bytes.iter().rev() {
        let limb = Scalar::from(*b as u64);
        acc += limb * base;
        base *= base_256;
    }
    acc
}

/// Configuration for the ECC scalar multiplication circuit with an extra packed column.
#[derive(Clone, Debug)]
pub struct SimpleEccConfig {
    pub acc_x: Column<Advice>,
    pub acc_y: Column<Advice>,
    pub base_x: Column<Advice>,
    pub base_y: Column<Advice>,
    pub lambda: Column<Advice>,
    pub den_inv: Column<Advice>,
    pub next_x: Column<Advice>,
    pub next_y: Column<Advice>,
    pub bit: Column<Advice>,
    pub is_inf: Column<Advice>,
    pub next_is_inf: Column<Advice>,
    pub packed: Column<Advice>, // packed bits column
    pub q_add: Selector,
    pub pk_x: Column<Instance>,
    pub pk_y: Column<Instance>,
}

impl SimpleEccConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let acc_x = meta.advice_column();
        let acc_y = meta.advice_column();
        let base_x = meta.advice_column();
        let base_y = meta.advice_column();
        let lambda = meta.advice_column();
        let den_inv = meta.advice_column();
        let next_x = meta.advice_column();
        let next_y = meta.advice_column();
        let bit = meta.advice_column();
        let is_inf = meta.advice_column();
        let next_is_inf = meta.advice_column();
        let packed = meta.advice_column(); // advice column for packed bits

        meta.enable_equality(acc_x);
        meta.enable_equality(acc_y);
        meta.enable_equality(next_x);
        meta.enable_equality(next_y);
        meta.enable_equality(packed); // enable equality for packed so we can constrain it if needed

        let pk_x = meta.instance_column();
        let pk_y = meta.instance_column();
        meta.enable_equality(pk_x);
        meta.enable_equality(pk_y);

        let q_add = meta.selector();

        meta.create_gate("conditional ecc add with infinity", |meta| {
            let q = meta.query_selector(q_add);

            let acc_x = meta.query_advice(acc_x, Rotation::cur());
            let acc_y = meta.query_advice(acc_y, Rotation::cur());
            let base_x = meta.query_advice(base_x, Rotation::cur());
            let base_y = meta.query_advice(base_y, Rotation::cur());
            let lambda = meta.query_advice(lambda, Rotation::cur());
            let den_inv = meta.query_advice(den_inv, Rotation::cur());
            let next_x = meta.query_advice(next_x, Rotation::cur());
            let next_y = meta.query_advice(next_y, Rotation::cur());
            let bit = meta.query_advice(bit, Rotation::cur());
            let is_inf = meta.query_advice(is_inf, Rotation::cur());
            let next_is_inf = meta.query_advice(next_is_inf, Rotation::cur());

            let one = Expression::Constant(Fp::one());

            let denom = base_x.clone() - acc_x.clone();
            let numer = base_y.clone() - acc_y.clone();

            let w_add = (one.clone() - is_inf.clone()) * bit.clone();
            let w_take_base = is_inf.clone() * bit.clone();
            let w_keep_acc = one.clone() - bit.clone();

            let eq1 = w_add.clone() * (denom.clone() * den_inv.clone() - one.clone());
            let eq2 = w_add.clone() * (lambda.clone() * denom - numer);

            let lambda_sq = lambda.clone() * lambda.clone();
            let x3_expr = lambda_sq - acc_x.clone() - base_x.clone();
            let y3_expr = lambda.clone() * (acc_x.clone() - x3_expr.clone()) - acc_y.clone();

            let eq3 = next_x.clone()
                - (w_add.clone() * x3_expr.clone()
                    + w_take_base.clone() * base_x.clone()
                    + w_keep_acc.clone() * acc_x.clone());

            let eq4 = next_y.clone()
                - (w_add.clone() * y3_expr.clone()
                    + w_take_base.clone() * base_y.clone()
                    + w_keep_acc.clone() * acc_y.clone());

            let eq5 = bit.clone() * (bit.clone() - one.clone());
            let eq6 = is_inf.clone() * (is_inf.clone() - one.clone());
            let eq7 = next_is_inf.clone() * (next_is_inf.clone() - one.clone());

            let eq8 = next_is_inf - ((one.clone() - bit.clone()) * is_inf.clone());

            vec![
                q.clone() * eq1,
                q.clone() * eq2,
                q.clone() * eq3,
                q.clone() * eq4,
                q.clone() * eq5,
                q.clone() * eq6,
                q.clone() * eq7,
                q * eq8,
            ]
        });

        SimpleEccConfig {
            acc_x,
            acc_y,
            base_x,
            base_y,
            lambda,
            den_inv,
            next_x,
            next_y,
            bit,
            is_inf,
            next_is_inf,
            packed,
            q_add,
            pk_x,
            pk_y,
        }
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        pk_x_cell: &AssignedCell<Fp, Fp>,
        pk_y_cell: &AssignedCell<Fp, Fp>,
    ) -> Result<(), Error> {
        layouter.constrain_instance(pk_x_cell.cell(), self.pk_x, 0)?;
        layouter.constrain_instance(pk_y_cell.cell(), self.pk_y, 0)?;
        Ok(())
    }
}

/// ecc_scalar_mul_region: returns (final_x_cell, final_y_cell, packed_bits_cell)
pub fn ecc_scalar_mul_region(
    config: &SimpleEccConfig,
    mut layouter: impl Layouter<Fp>,
    bits: &[bool; NUM_BITS],
    base_points: &[EpAffine; NUM_BITS],
) -> Result<(AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>), Error> {
    let (final_x_cell, final_y_cell, packed_cell) = layouter.assign_region(
        || "scalar mul",
        |mut region| {
            let mut offset = 0usize;

            let mut acc_x_val = Fp::zero();
            let mut acc_y_val = Fp::zero();
            let mut is_inf_val = Fp::one();

            let mut acc_x_cell: AssignedCell<Fp, Fp>;
            let mut acc_y_cell: AssignedCell<Fp, Fp>;

            // precompute 2^i in the Fp field
            let mut pow2: Vec<Fp> = Vec::with_capacity(NUM_BITS);
            {
                let mut cur = Fp::one();
                for _ in 0..NUM_BITS {
                    pow2.push(cur);
                    cur = cur + cur; // multiply by 2
                }
            }

            // packed accumulator in Fp
            let mut packed_acc_val = Fp::zero();
            let mut packed_assigned: Option<AssignedCell<Fp, Fp>> = None;

            // first row
            {
                let _acc_x = region.assign_advice(
                    || "acc_x_0",
                    config.acc_x,
                    offset,
                    || Value::known(acc_x_val),
                )?;
                let _acc_y = region.assign_advice(
                    || "acc_y_0",
                    config.acc_y,
                    offset,
                    || Value::known(acc_y_val),
                )?;
                let _is_inf = region.assign_advice(
                    || "is_inf_0",
                    config.is_inf,
                    offset,
                    || Value::known(is_inf_val),
                )?;

                let base0 = base_points[0];
                let coords0 = base0.coordinates().unwrap();
                let bx = *coords0.x();
                let by = *coords0.y();

                region.assign_advice(
                    || "base_x_0",
                    config.base_x,
                    offset,
                    || Value::known(bx),
                )?;
                region.assign_advice(
                    || "base_y_0",
                    config.base_y,
                    offset,
                    || Value::known(by),
                )?;

                let bit0 = bits[0];
                let bit0_val = if bit0 { Fp::one() } else { Fp::zero() };
                region.assign_advice(
                    || "bit_0",
                    config.bit,
                    offset,
                    || Value::known(bit0_val),
                )?;

                let (lambda_val, den_inv_val, x3_val, y3_val) =
                    if bit0 && is_inf_val == Fp::zero() {
                        let denom = bx - acc_x_val;
                        let den_inv = denom.invert().unwrap_or(Fp::zero());
                        let numer = by - acc_y_val;
                        let lambda = numer * den_inv;
                        let x3 = lambda.square() - acc_x_val - bx;
                        let y3 = lambda * (acc_x_val - x3) - acc_y_val;
                        (lambda, den_inv, x3, y3)
                    } else {
                        (Fp::zero(), Fp::one(), acc_x_val, acc_y_val)
                    };

                region.assign_advice(
                    || "lambda_0",
                    config.lambda,
                    offset,
                    || Value::known(lambda_val),
                )?;
                region.assign_advice(
                    || "den_inv_0",
                    config.den_inv,
                    offset,
                    || Value::known(den_inv_val),
                )?;

                let next_is_inf_val = if bit0 { Fp::zero() } else { is_inf_val };

                let next_x_val = if bit0 {
                    if is_inf_val == Fp::one() { bx } else { x3_val }
                } else { acc_x_val };
                let next_y_val = if bit0 {
                    if is_inf_val == Fp::one() { by } else { y3_val }
                } else { acc_y_val };

                let next_x_cell = region.assign_advice(
                    || "next_x_0",
                    config.next_x,
                    offset,
                    || Value::known(next_x_val),
                )?;
                let next_y_cell = region.assign_advice(
                    || "next_y_0",
                    config.next_y,
                    offset,
                    || Value::known(next_y_val),
                )?;

                region.assign_advice(
                    || "next_is_inf_0",
                    config.next_is_inf,
                    offset,
                    || Value::known(next_is_inf_val),
                )?;

                // update packed accumulator for bit 0 (2^0 * bit0)
                packed_acc_val = packed_acc_val + (bit0_val * pow2[0]);
                let _packed_cell0 = region.assign_advice(
                    || "packed_0",
                    config.packed,
                    offset,
                    || Value::known(packed_acc_val),
                )?;
                // final packed cell is taken from the last round

                config.q_add.enable(&mut region, offset)?;

                acc_x_val = next_x_val;
                acc_y_val = next_y_val;
                is_inf_val = next_is_inf_val;
                acc_x_cell = next_x_cell.clone();
                acc_y_cell = next_y_cell.clone();
            }

            // following rounds
            for i in 1..NUM_BITS {
                offset += 1;

                let this_acc_x = acc_x_cell.copy_advice(
                    || format!("acc_x_{}", i),
                    &mut region,
                    config.acc_x,
                    offset,
                )?;
                let this_acc_y = acc_y_cell.copy_advice(
                    || format!("acc_y_{}", i),
                    &mut region,
                    config.acc_y,
                    offset,
                )?;
                let _this_is_inf = region.assign_advice(
                    || format!("is_inf_{}", i),
                    config.is_inf,
                    offset,
                    || Value::known(is_inf_val),
                )?;

                let base = base_points[i];
                let coords = base.coordinates().unwrap();
                let bx = *coords.x();
                let by = *coords.y();

                region.assign_advice(
                    || format!("base_x_{}", i),
                    config.base_x,
                    offset,
                    || Value::known(bx),
                )?;
                region.assign_advice(
                    || format!("base_y_{}", i),
                    config.base_y,
                    offset,
                    || Value::known(by),
                )?;

                let bit_i = bits[i];
                let bit_val = if bit_i { Fp::one() } else { Fp::zero() };
                region.assign_advice(
                    || format!("bit_{}", i),
                    config.bit,
                    offset,
                    || Value::known(bit_val),
                )?;

                let (lambda_val, den_inv_val, x3_val, y3_val) =
                    if bit_i && is_inf_val == Fp::zero() {
                        let denom = bx - acc_x_val;
                        let den_inv = denom.invert().unwrap_or(Fp::zero());
                        let numer = by - acc_y_val;
                        let lambda = numer * den_inv;
                        let x3 = lambda.square() - acc_x_val - bx;
                        let y3 = lambda * (acc_x_val - x3) - acc_y_val;
                        (lambda, den_inv, x3, y3)
                    } else {
                        (Fp::zero(), Fp::one(), acc_x_val, acc_y_val)
                    };

                region.assign_advice(
                    || format!("lambda_{}", i),
                    config.lambda,
                    offset,
                    || Value::known(lambda_val),
                )?;
                region.assign_advice(
                    || format!("den_inv_{}", i),
                    config.den_inv,
                    offset,
                    || Value::known(den_inv_val),
                )?;

                let next_is_inf_val = if bit_i { Fp::zero() } else { is_inf_val };

                let next_x_val = if bit_i {
                    if is_inf_val == Fp::one() { bx } else { x3_val }
                } else { acc_x_val };
                let next_y_val = if bit_i {
                    if is_inf_val == Fp::one() { by } else { y3_val }
                } else { acc_y_val };

                let next_x_cell = region.assign_advice(
                    || format!("next_x_{}", i),
                    config.next_x,
                    offset,
                    || Value::known(next_x_val),
                )?;
                let next_y_cell = region.assign_advice(
                    || format!("next_y_{}", i),
                    config.next_y,
                    offset,
                    || Value::known(next_y_val),
                )?;

                region.assign_advice(
                    || format!("next_is_inf_{}", i),
                    config.next_is_inf,
                    offset,
                    || Value::known(next_is_inf_val),
                )?;

                // update packed accumulator: add bit_i * 2^i
                packed_acc_val = packed_acc_val + (bit_val * pow2[i]);
                let packed_cell = region.assign_advice(
                    || format!("packed_{}", i),
                    config.packed,
                    offset,
                    || Value::known(packed_acc_val),
                )?;
                packed_assigned.replace(packed_cell);

                config.q_add.enable(&mut region, offset)?;

                acc_x_val = next_x_val;
                acc_y_val = next_y_val;
                is_inf_val = next_is_inf_val;
                acc_x_cell = next_x_cell.clone();
                acc_y_cell = next_y_cell.clone();

                let _ = this_acc_x;
                let _ = this_acc_y;
            }

            // return final acc cells and final packed cell
            Ok((acc_x_cell, acc_y_cell, packed_assigned.expect("packed assigned")))
        },
    )?;

    Ok((final_x_cell, final_y_cell, packed_cell))
}
