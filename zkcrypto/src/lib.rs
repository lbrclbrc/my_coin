// zkcrypto/src/lib.rs

use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

mod poseidon_hash;
mod pasta_ecc;
mod zkproof_for_anon_pay_gen;
mod zkproof_for_ii_blue_apply_gen;
pub mod poseidon_chip;
pub mod ecc_chip;
mod zkproof_for_ii_blue_apply_verifier;
mod zkproof_for_acct_to_anon_tx_gen;
mod zkproof_for_acct_to_anon_tx_verifier;
mod zkproof_for_acct_to_anon_tx_evil_gen;
mod zkproof_for_anon_pay_verify;

use poseidon_hash::{poseidon_hash_blocks, get_pallas_modulus_py};
use pasta_ecc::register_pasta_ecc;
use zkproof_for_ii_blue_apply_gen::register_zkproof_for_ii_blue_addr_apply;
use zkproof_for_ii_blue_apply_verifier::register_zkproof_for_ii_blue_addr_verify;
use zkproof_for_acct_to_anon_tx_gen::register_zkproof_for_acct_to_anon_tx_apply;
use zkproof_for_acct_to_anon_tx_verifier::register_zkproof_for_acct_to_anon_tx_verify;
use zkproof_for_acct_to_anon_tx_evil_gen::register_zkproof_for_acct_to_anon_tx_evil;
use zkproof_for_anon_pay_gen::register_zkproof_for_anon_pay_apply;
use zkproof_for_anon_pay_verify::register_zkproof_for_anon_pay_verify;

#[pymodule]
fn zkcrypto(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(poseidon_hash_blocks, m)?)?;
    m.add_function(wrap_pyfunction!(get_pallas_modulus_py, m)?)?;

    register_pasta_ecc(m)?;

    register_zkproof_for_ii_blue_addr_apply(m)?;
    register_zkproof_for_ii_blue_addr_verify(m)?;

    register_zkproof_for_acct_to_anon_tx_apply(m)?;
    register_zkproof_for_acct_to_anon_tx_verify(m)?;
    register_zkproof_for_acct_to_anon_tx_evil(m)?;
    register_zkproof_for_anon_pay_apply(m)?;
    register_zkproof_for_anon_pay_verify(m)?;

    Ok(())
}
