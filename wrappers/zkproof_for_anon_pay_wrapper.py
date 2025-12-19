# wrappers/zkproof_for_anon_pay_wrapper.py

import zkcrypto
from tools import turn_hex_str_to_bytes


ZERO32_HEX = "0" * 64


def int_to_be32(i):
    """
    Convert an integer into 32-byte big-endian representation.
    """
    return int(i).to_bytes(32, "big")


def get_zkproof_for_anon_pay(
    pin_commit_root,
    pin_nullifier,
    pin_commit_change,
    pin_value_pay_int,

    sin_value_initial_int,
    sin_value_change_int,
    sin_sk,
    sin_nonce_initial,
    sin_src,

    sin_path_siblings,
    sin_path_dirs,
):
    """
    Generate the zk-proof for AnonPay.
    All hex-string inputs may have an optional 0x prefix.
    Integer inputs are converted into 32-byte big-endian.
    """
    # ----- public inputs -----
    pin_commit_root_bytes = turn_hex_str_to_bytes(pin_commit_root)
    pin_nullifier_bytes = turn_hex_str_to_bytes(pin_nullifier)
    pin_commit_change_bytes = turn_hex_str_to_bytes(pin_commit_change)
    pin_value_pay_bytes = int_to_be32(pin_value_pay_int)

    # ----- secret inputs -----
    sin_value_initial_bytes = int_to_be32(sin_value_initial_int)
    sin_value_change_bytes = int_to_be32(sin_value_change_int)
    sin_sk_bytes = turn_hex_str_to_bytes(sin_sk)
    sin_nonce_initial_bytes = turn_hex_str_to_bytes(sin_nonce_initial)
    sin_src_bytes = turn_hex_str_to_bytes(sin_src)

    # ----- merkle path -----
    if len(sin_path_siblings) != 32:
        raise ValueError("sin_path_siblings must be length 32")
    if len(sin_path_dirs) != 32:
        raise ValueError("sin_path_dirs must be length 32")

    sibs = []
    i = 0
    while i < 32:
        sibs.append(turn_hex_str_to_bytes(sin_path_siblings[i]))
        i += 1

    dirs = []
    j = 0
    while j < 32:
        dirs.append(int(sin_path_dirs[j]))
        j += 1

    proof_bytes = zkcrypto.get_zkproof_for_anon_pay(
        pin_commit_root_bytes,
        pin_nullifier_bytes,
        pin_commit_change_bytes,
        pin_value_pay_bytes,
        sin_value_initial_bytes,
        sin_value_change_bytes,
        sin_sk_bytes,
        sin_nonce_initial_bytes,
        sin_src_bytes,
        sibs,
        dirs,
    )
    return proof_bytes.hex()


def verify_zkproof_for_anon_pay(
    pin_commit_root_hex,
    pin_nullifier_hex,
    pin_commit_change_hex,
    pin_value_pay,
    proof_hex,
):
    """
    Verify the zk-proof for AnonPay.
    All inputs may be bytes or hex strings.
    Returns True or False.
    """
    root_b = turn_hex_str_to_bytes(pin_commit_root_hex)
    nullifier_b = turn_hex_str_to_bytes(pin_nullifier_hex)
    change_b = turn_hex_str_to_bytes(pin_commit_change_hex)

    # pin_value_pay may be int or hex-string
    if isinstance(pin_value_pay, int):
        vpay_b = int_to_be32(pin_value_pay)
    else:
        vpay_b = turn_hex_str_to_bytes(pin_value_pay)

    proof_b = turn_hex_str_to_bytes(proof_hex)

    ok = zkcrypto.verify_zkproof_for_anon_pay(
        root_b,
        nullifier_b,
        change_b,
        vpay_b,
        proof_b,
    )
    return ok
