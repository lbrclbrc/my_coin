# wrappers/zkproof_for_ii_blue_apply_wrapper.py

import zkcrypto
from tools import turn_hex_str_to_bytes


def get_zkproof_for_ii_blue_apply(master_seed,
                                  new_token,
                                  new_pk,
                                  master_seed_hash):
    """
    Generate a BlueApply-II ZK proof.
    All inputs may be bytes or hex strings (with or without 0x prefix).
    Returns a lowercase hex string without 0x prefix.
    """
    master_seed_bytes = turn_hex_str_to_bytes(master_seed)
    new_token_bytes = turn_hex_str_to_bytes(new_token)
    new_pk_bytes = turn_hex_str_to_bytes(new_pk)
    master_seed_hash_bytes = turn_hex_str_to_bytes(master_seed_hash)

    proof_bytes = zkcrypto.get_zkproof_for_ii_blue_apply(
        master_seed_bytes,
        new_token_bytes,
        new_pk_bytes,
        master_seed_hash_bytes,
    )
    return proof_bytes.hex()


def verify_zkproof_for_ii_blue_apply(zkproof,
                                     new_token,
                                     new_pk,
                                     master_seed_hash):
    """
    Verify a BlueApply-II ZK proof.
    All inputs may be bytes or hex strings.
    Returns True or False.
    """
    proof_bytes = turn_hex_str_to_bytes(zkproof)
    new_token_bytes = turn_hex_str_to_bytes(new_token)
    new_pk_bytes = turn_hex_str_to_bytes(new_pk)
    master_seed_hash_bytes = turn_hex_str_to_bytes(master_seed_hash)

    return zkcrypto.verify_zkproof_for_ii_blue_apply(
        proof_bytes,
        new_token_bytes,
        new_pk_bytes,
        master_seed_hash_bytes,
    )
