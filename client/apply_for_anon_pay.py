#!/usr/bin/env python3
# client/apply_for_anon_pay.py
# Apply for AnonPay (pay from an anonymous note to a public account).
# Only builds the envelope and returns it; sending is handled elsewhere.

import os
import sys

THIS_FILE = os.path.abspath(__file__)
MODULE_DIR = os.path.dirname(THIS_FILE)
PROJECT_ROOT = os.path.abspath(os.path.join(MODULE_DIR, ".."))
WRAPPERS_DIR = os.path.join(PROJECT_ROOT, "wrappers")

for p in (WRAPPERS_DIR, PROJECT_ROOT):
    if p and os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

from wrappers.poseidon_hash_wrapper import get_poseidon_hash
from wrappers.zkproof_for_anon_pay_wrapper import (
    get_zkproof_for_anon_pay,
    ZERO32_HEX,
)


def build_apply_for_anon_pay_envelope(
    client,
    acct,
    commit_root_before_hex,
    to_addr_hex,
    amount,
    value_initial,
    nonce_initial_bytes,
    src_bytes,
    siblings,
    dirs,
):
    """
    Build the Anonymous Pay request envelope.

    Request envelope:
    {
      "application_type": "AnonPay",
      "payload": {
        "version":       1,
        "to_addr":       Hex32,
        "amount":        int,
        "nullifier":     Hex32,
        "commit_change": Hex32,
        "zk_proof":      ZKProofHex
      }
    }

    Notes:
    - commit_root_before_hex: current anonymous commitment tree root (pin_root).
    - acct: local Account that controls the note secret key.
    - value_initial: value of the old note (int or something convertible to int).
    - amount: public value paid to to_addr (int or something convertible to int).
    - nonce_initial_bytes: old note nonce (bytes(32) or hex string).
    - src_bytes: old note src field (bytes(32) or hex string).
    - siblings, dirs: MerkleTreeCommit.gen_proof(index) output; caller builds them
      and passes them directly into the zk generator.
    """

    print("\n[CLIENT][AnonPay] prepare envelope.")

    if acct is None:
        print("[CLIENT][AnonPay] acct is None.")
        return None

    if acct.addr is None:
        acct.fill_missing()

    to_addr = to_addr_hex
    print(f"[CLIENT][AnonPay] to_addr = {to_addr}")

    amt = int(amount)
    val_init = int(value_initial)
    val_change = val_init - amt

    print(
        f"[CLIENT][AnonPay] value_initial = {val_init} "
        f"amount = {amt} value_change = {val_change}"
    )

    sk_bytes = acct.ecc_keypair.sk
    if sk_bytes is None or len(sk_bytes) != 32:
        print("[CLIENT][AnonPay] acct sk missing or not 32 bytes.")
        return None

    nonce_bytes = nonce_initial_bytes
    src = src_bytes

    # nullifier = Poseidon(sk_bytes, nonce_bytes, src_bytes)
    nullifier_hex = get_poseidon_hash(sk_bytes, nonce_bytes, src)
    print(f"[CLIENT][AnonPay] nullifier = {nullifier_hex[:16]}...")

    # commit_change = Poseidon(value_change_bytes, sk_bytes, ZERO32, nullifier_bytes)
    val_change_bytes = val_change.to_bytes(32, "big")
    zero_bytes = bytes.fromhex(ZERO32_HEX)
    nullifier_bytes = bytes.fromhex(nullifier_hex)

    commit_change_hex = get_poseidon_hash(
        val_change_bytes,
        sk_bytes,
        zero_bytes,
        nullifier_bytes,
    )
    print(f"[CLIENT][AnonPay] commit_change = {commit_change_hex[:16]}...")

    proof_val = get_zkproof_for_anon_pay(
        commit_root_before_hex,  # pin_root
        nullifier_hex,           # pin_nullifier
        commit_change_hex,       # pin_commit_change
        amt,                     # pin_value_pay (int)

        val_init,                # sin_value_initial
        val_change,              # sin_value_change
        sk_bytes,                # sin_sk
        nonce_bytes,             # sin_nonce_initial
        src,                     # sin_src
        siblings,                # sin_siblings
        dirs,                    # sin_dirs
    )

    if isinstance(proof_val, str):
        proof_hex = proof_val
    else:
        proof_hex = bytes(proof_val).hex()

    print(f"[CLIENT][AnonPay] zk_proof = {proof_hex[:16]}...")

    payload = {
        "version": 1,
        "to_addr": to_addr,
        "amount": int(amt),
        "nullifier": nullifier_hex,
        "commit_change": commit_change_hex,
        "zk_proof": proof_hex,
    }

    envelope = {
        "application_type": "AnonPay",
        "payload": payload,
    }

    print("[CLIENT][AnonPay] envelope built.")
    return envelope
