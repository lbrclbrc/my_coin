// zkcrypto/src/poseidon_chip.rs
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    pasta::Fp,
    plonk::{Advice, Column, ConstraintSystem, Error, Instance},
};

use halo2_gadgets::poseidon::{
    self as poseidon,
    Hash as PoseidonHash,
    Pow5Chip as PoseidonChip,
    Pow5Config as PoseidonConfig,
};

/// Poseidon parameters: t = 3, rate = 2.
pub const WIDTH: usize = 3;
pub const RATE: usize = 2;

/// Reusable Poseidon hash configuration.
#[derive(Clone, Debug)]
pub struct PoseidonHashConfig {
    pub input: Column<Advice>,
    pub output: Column<Instance>,
    pub state: [Column<Advice>; WIDTH],
    pub partial_sbox: Column<Advice>,
    pub poseidon: PoseidonConfig<Fp, WIDTH, RATE>,
    // Advice column used for intermediate byte-related values.
    pub byte_col: Column<Advice>,
}

impl PoseidonHashConfig {
    /// Configure Poseidon-related columns and gates in the constraint system.
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        // Input advice column holding a single Fp as circuit input.
        let input = meta.advice_column();
        meta.enable_equality(input);

        // Output instance column holding the Poseidon hash as a public input.
        let output = meta.instance_column();
        meta.enable_equality(output);

        // Constant fixed column used as a constant polynomial carrier.
        let _constant = meta.fixed_column();
        meta.enable_constant(_constant);

        // Poseidon state columns: three advice columns (WIDTH = 3).
        let state: [Column<Advice>; WIDTH] = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        for col in &state {
            meta.enable_equality(*col);
        }

        // partial_sbox column for intermediate S-box values inside the Poseidon gadget.
        let partial_sbox = meta.advice_column();
        meta.enable_equality(partial_sbox);

        // Round constants columns.
        let rc_a = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let rc_b = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];

        // byte_col for storing accumulated or byte-related Fp values inside the circuit.
        let byte_col = meta.advice_column();
        meta.enable_equality(byte_col);

        // Configure Pow5 Poseidon chip and obtain the PoseidonConfig.
        let poseidon = PoseidonChip::<Fp, WIDTH, RATE>::configure::<poseidon::primitives::P128Pow5T3>(
            meta,
            state,
            partial_sbox,
            rc_a,
            rc_b,
        );

        PoseidonHashConfig {
            input,
            output,
            state,
            partial_sbox,
            poseidon,
            byte_col,
        }
    }

    /// Expose the hash cell as a public instance at the given row.
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        hash: &AssignedCell<Fp, Fp>,
        row: usize,
    ) -> Result<(), Error> {
        // Constrain the hash cell to the specified instance row.
        layouter.constrain_instance(hash.cell(), self.output, row)?;
        Ok(())
    }

}

/// Single-input Poseidon hash in the circuit.
pub fn hash_fp_in_circuit(
    cfg: &PoseidonHashConfig,
    mut layouter: impl Layouter<Fp>,
    input_cell: AssignedCell<Fp, Fp>,
) -> Result<AssignedCell<Fp, Fp>, Error> {
    let poseidon_chip = PoseidonChip::<Fp, WIDTH, RATE>::construct(cfg.poseidon.clone());

    let hasher = PoseidonHash::<
        Fp,
        PoseidonChip<Fp, WIDTH, RATE>,
        poseidon::primitives::P128Pow5T3,
        poseidon::primitives::ConstantLength<1>,
        WIDTH,
        RATE,
    >::init(
        poseidon_chip,
        layouter.namespace(|| "Poseidon hash init"),
    )?;

    let digest_cell = hasher.hash(
        layouter.namespace(|| "Poseidon hash(input)"),
        [input_cell],
    )?;

    Ok(digest_cell)
}

/// Helper that combines 32 byte cells into a single field element.
pub fn bytes32_to_fp_in_circuit(
    cfg: &PoseidonHashConfig,
    mut layouter: impl Layouter<Fp>,
    byte_cells: &[AssignedCell<Fp, Fp>], // Must be 32 cells; caller should ensure each cell is range-checked to 0..255.
) -> Result<AssignedCell<Fp, Fp>, Error> {
    assert_eq!(byte_cells.len(), 32, "bytes32_to_fp_in_circuit expects 32 bytes");

    // Precompute 256^k mod p.
    let mut pow256: [Fp; 32] = [Fp::zero(); 32];
    {
        let mut cur = Fp::one();
        for i in 0..32 {
            pow256[i] = cur;
            cur = cur * Fp::from(256u64);
        }
    }

    // Region assigning the accumulator.
    let assigned_acc = layouter.assign_region(
        || "bytes32 to fp region",
        |mut region: Region<'_, Fp>| {
            // Accumulator starts at 0.
            let mut acc_val = Value::<Fp>::known(Fp::zero());
            let mut acc_assigned: Option<AssignedCell<Fp, Fp>> = None;

            for (i, bcell) in byte_cells.iter().enumerate() {
                // Byte value as a field Value.
                let byte_val: Value<Fp> = bcell.value().map(|v| *v);

                // Coefficient is 256^{31-i} (big-endian).
                let coeff = pow256[31 - i];

                let contrib = byte_val.map(|bv| coeff * bv);

                let new_acc_val = acc_val.zip(contrib).map(|(a, c)| a + c);

                // Assign the new accumulator into byte_col at row i.
                let acc_cell = region.assign_advice(
                    || format!("acc_{}", i),
                    cfg.byte_col,
                    i,
                    || new_acc_val,
                )?;

                acc_assigned = Some(acc_cell);
                acc_val = new_acc_val;
            }

            Ok(acc_assigned.expect("acc assigned"))
        },
    )?;

    Ok(assigned_acc)
}

/// Two-input Poseidon hash in the circuit.
pub fn hash_two_in_circuit(
    cfg: &PoseidonHashConfig,
    mut layouter: impl Layouter<Fp>,
    a: AssignedCell<Fp, Fp>,
    b: AssignedCell<Fp, Fp>,
) -> Result<AssignedCell<Fp, Fp>, Error> {
    let poseidon_chip = PoseidonChip::<Fp, WIDTH, RATE>::construct(cfg.poseidon.clone());

    let hasher = PoseidonHash::<
        Fp,
        PoseidonChip<Fp, WIDTH, RATE>,
        poseidon::primitives::P128Pow5T3,
        poseidon::primitives::ConstantLength<2>,
        WIDTH,
        RATE,
    >::init(
        poseidon_chip,
        layouter.namespace(|| "Poseidon hash init (2)"),
    )?;

    let digest_cell = hasher.hash(
        layouter.namespace(|| "Poseidon hash(a,b)"),
        [a, b],
    )?;
    Ok(digest_cell)
}

/// Wrapper that forwards to hash_two_in_circuit.
pub fn hash_2fp_in_circuit(
    cfg: &PoseidonHashConfig,
    layouter: impl Layouter<Fp>,
    a: AssignedCell<Fp, Fp>,
    b: AssignedCell<Fp, Fp>,
) -> Result<AssignedCell<Fp, Fp>, Error> {
    // Forward directly to hash_two_in_circuit.
    hash_two_in_circuit(cfg, layouter, a, b)
}

/// Top-level Poseidon hash over a byte array in the circuit.
pub fn hash_bytes_in_circuit(
    cfg: &PoseidonHashConfig,
    mut layouter: impl Layouter<Fp>,
    byte_cells: &[AssignedCell<Fp, Fp>],
) -> Result<AssignedCell<Fp, Fp>, Error> {
    assert!(byte_cells.len() % 32 == 0, "bytes length must be multiple of 32");

    // Convert each 32-byte block into a single Fp cell.
    let mut fp_inputs: Vec<AssignedCell<Fp, Fp>> = Vec::new();
    let mut chunk_index = 0usize;
    while chunk_index < byte_cells.len() {
        let chunk = &byte_cells[chunk_index..chunk_index + 32];
        let fe_cell = bytes32_to_fp_in_circuit(cfg, layouter.namespace(|| format!("chunk_{}", chunk_index/32)), chunk)?;
        fp_inputs.push(fe_cell);
        chunk_index += 32;
    }

    // Combine the inputs according to the CPU-side hashing scheme.
    if fp_inputs.len() == 1 {
        let res = hash_fp_in_circuit(cfg, layouter.namespace(|| "poseidon single"), fp_inputs.remove(0))?;
        Ok(res)
    } else {
        // First compute H(x0, x1).
        let mut acc = hash_two_in_circuit(cfg, layouter.namespace(|| "poseidon pair 0"), fp_inputs.remove(0), fp_inputs.remove(0))?;
        // Then iteratively compute H(acc, xi) for the remaining inputs.
        let mut idx = 1usize;
        while !fp_inputs.is_empty() {
            let next = fp_inputs.remove(0);
            acc = hash_two_in_circuit(cfg, layouter.namespace(|| format!("poseidon iter {}", idx)), acc, next)?;
            idx += 1;
        }
        Ok(acc)
    }
}
