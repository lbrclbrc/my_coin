# wrappers/zkproof_for_acct_to_anon_tx_wrapper.py

import zkcrypto
from tools import turn_hex_str_to_bytes


def get_zkproof_for_acct_to_anon_tx(
    sin_sk,
    pin_val,
    pin_nonce,
    pin_addr,
    pin_anon_commit,
):
    """
    Generate the ZK proof for AcctToAnonTx.
    Inputs may be bytes or hex strings (with or without 0x prefix).
    All inputs are converted to bytes before calling the Rust backend.
    Returns the proof as a lowercase hex string without 0x prefix.
    """
    sk_bytes = turn_hex_str_to_bytes(sin_sk)
    val_bytes = turn_hex_str_to_bytes(pin_val)
    nonce_bytes = turn_hex_str_to_bytes(pin_nonce)
    addr_bytes = turn_hex_str_to_bytes(pin_addr)
    anon_commit_bytes = turn_hex_str_to_bytes(pin_anon_commit)

    proof_bytes = zkcrypto.get_zkproof_for_acct_to_anon_tx(
        sk_bytes,
        val_bytes,
        nonce_bytes,
        addr_bytes,
        anon_commit_bytes,
    )
    return proof_bytes.hex()


def verify_zkproof_for_acct_to_anon_tx(
    proof_hex,
    val_hex,
    nonce_hex,
    addr_hex,
    anon_commit_hex,
):
    """
    Verify the ZK proof for AcctToAnonTx.
    All inputs may be bytes or hex strings.
    Returns True or False.
    """
    proof_bytes = turn_hex_str_to_bytes(proof_hex)
    val_bytes = turn_hex_str_to_bytes(val_hex)
    nonce_bytes = turn_hex_str_to_bytes(nonce_hex)
    addr_bytes = turn_hex_str_to_bytes(addr_hex)
    anon_commit_bytes = turn_hex_str_to_bytes(anon_commit_hex)

    ok = zkcrypto.verify_zkproof_for_acct_to_anon_tx(
        proof_bytes,
        val_bytes,
        nonce_bytes,
        addr_bytes,
        anon_commit_bytes,
    )
    return ok
