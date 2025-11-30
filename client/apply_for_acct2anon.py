#!/usr/bin/env python3
# client/apply_for_acct2anon.py
# Apply for AcctToAnon (move public account balance into the anonymous commitment pool).
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
from wrappers.zkproof_for_acct_to_anon_tx_wrapper import get_zkproof_for_acct_to_anon_tx


def build_apply_for_acct2anon_envelope(client, acct, amount):
    print("\n[CLIENT] [AcctToAnon] prepare envelope.")

    if acct is None:
        print("[CLIENT] [AcctToAnon] acct is None.")
        return None

    if acct.addr is None:
        acct.fill_missing()

    if not isinstance(amount, int):
        try:
            amount = int(amount)
        except Exception:
            print("[CLIENT] [AcctToAnon] amount must be int.")
            return None

    if amount <= 0:
        print("[CLIENT] [AcctToAnon] amount must be positive.")
        return None

    from_addr_hex = acct.addr
    print("[CLIENT] [AcctToAnon] from_addr =", from_addr_hex)

    # nonce is a public input of the proof, so the client must use the local cached nonce
    base_nonce = acct.nonce
    if base_nonce is None:
        base_nonce = 0
    nonce_int = int(base_nonce) + 1
    nonce_bytes = nonce_int.to_bytes(32, "big")
    print("[CLIENT] [AcctToAnon] nonce =", nonce_int)

    # secret key bytes from acct (must be an existing SK, do not generate a new one)
    sk_bytes = acct.ecc_keypair.sk
    if sk_bytes is None or len(sk_bytes) != 32:
        print("[CLIENT] [AcctToAnon] acct sk missing or not 32 bytes.")
        return None

    # value bytes
    val_bytes = int(amount).to_bytes(32, "big")

    # addr bytes for proof / commit
    addr_bytes = bytes.fromhex(from_addr_hex)

    # anon_commit = Poseidon(val, sk_raw, nonce, addr)
    anon_commit_hex = get_poseidon_hash(val_bytes, sk_bytes, nonce_bytes, addr_bytes)
    anon_commit_bytes = bytes.fromhex(anon_commit_hex)
    print("[CLIENT] [AcctToAnon] anon_commit =", anon_commit_hex[:16], "...")

    # zk proof (wrapper returns a hex string)
    proof_val = get_zkproof_for_acct_to_anon_tx(
        sk_bytes,
        val_bytes,
        nonce_bytes,
        addr_bytes,
        anon_commit_bytes,
    )
    if isinstance(proof_val, str):
        proof_hex = proof_val
    else:
        proof_hex = bytes(proof_val).hex()

    print("[CLIENT] [AcctToAnon] zk_proof =", proof_hex[:16], "...")

    payload = {
        "version": 1,
        "from_addr": from_addr_hex,
        "amount": int(amount),
        "nonce": nonce_int,
        "anon_commit": anon_commit_hex,
        "zk_proof": proof_hex,
    }

    envelope = {
        "application_type": "AcctToAnon",
        "payload": payload,
    }

    print("[CLIENT] [AcctToAnon] envelope built.")
    return envelope
