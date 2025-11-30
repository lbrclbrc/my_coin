#!/usr/bin/env python3
# demo/zkproof_ii_blue_apply_tests.py
#
# Purpose:
#   Empirically check what the BlueApply zk circuit is really proving.
#
#   The intended statement is roughly:
#     1. master_seed_hash = Poseidon(master_seed)
#     2. new_sk = scalar_from_bytes_mod_order(Poseidon(master_seed, token))
#        new_pk = G * new_sk
#   and the same master_seed must be used in (1) and (2).
#
#   This script does not use the Client class. It talks directly to:
#     - Poseidon hash wrapper
#     - Pallas ECC wrapper
#     - BlueApply-II proof generator / verifier wrappers.

import os
import sys

# Add project root to sys.path
THIS_FILE = os.path.abspath(__file__)
THIS_DIR = os.path.dirname(THIS_FILE)
PROJECT_ROOT = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from wrappers.poseidon_hash_wrapper import get_poseidon_hash
from wrappers.pasta_ecc_wrapper import EccKeypair
from wrappers.zkproof_for_ii_blue_apply_wrapper import (
    get_zkproof_for_ii_blue_apply, 
    verify_zkproof_for_ii_blue_apply
)
from tools import PALLAS_P, SCALAR_ORDER, short_hex


# ========== Basic helpers (no Client involved) ==========


def gen_master_seed_bytes():
    """
    Generate a 32-byte master_seed that is reduced modulo Pallas Fp.

    This mirrors the requirement that master_seed should be a valid field element.
    """
    raw = os.urandom(32)
    raw_int = int.from_bytes(raw, "big")
    ms_int = raw_int % PALLAS_P
    return ms_int.to_bytes(32, "big")


def compute_master_seed_hash_bytes(master_seed_bytes):
    """
    master_seed_hash_bytes = Poseidon(master_seed_bytes).

    This is equivalent to Client._compute_master_seed_hash_bytes.
    """
    digest_hex = get_poseidon_hash(master_seed_bytes)
    return bytes.fromhex(digest_hex)


def derive_pk_from_ms_and_token(master_seed_bytes, token_bytes):
    """
    Derive a public key from (master_seed, token) using the same rule
    as in the BlueApply circuit and client:

      digest_hex = Poseidon(master_seed_bytes, token_bytes)
      new_sk     = scalar_from_bytes_mod_order(digest_hex)
      new_pk     = G * new_sk

    Returns:
      pk_bytes (compressed Pallas public key, 32 bytes).
    """
    digest_hex = get_poseidon_hash(master_seed_bytes, token_bytes)
    digest_int = int(digest_hex, 16) % SCALAR_ORDER
    sk_bytes = digest_int.to_bytes(32, "big")

    kp = EccKeypair()
    kp.set_sk(sk_bytes)
    pk_bytes = kp.get_pk_from_sk()
    return pk_bytes


# ========== Case 1: everything consistent (happy path) ==========


def run_case_good():
    """
    Case-GOOD:
      Use the same master_seed and token=0 consistently in both generator
      and verifier. Proof generation and verification are expected to succeed.
    """
    print("\n[CASE-GOOD] Use the same master_seed and token=0 for generation and verification")

    master_seed = gen_master_seed_bytes()
    ms_hash = compute_master_seed_hash_bytes(master_seed)
    token0 = (0).to_bytes(32, "big")
    pk0 = derive_pk_from_ms_and_token(master_seed, token0)

    print("  master_seed =", short_hex(master_seed))
    print("  ms_hash     =", short_hex(ms_hash))
    print("  token0      =", short_hex(token0))
    print("  pk0         =", short_hex(pk0))

    # The generator returns a hex string; the verifier wrapper accepts hex or bytes.
    proof_hex = get_zkproof_for_ii_blue_apply(master_seed, token0, pk0, ms_hash)

    print("  proof_hex   =", short_hex(proof_hex))

    ok = verify_zkproof_for_ii_blue_apply(
        proof_hex,   # pass hex-string, let the wrapper handle internal conversion
        token0,
        pk0,
        ms_hash,
    )
    print("  verifier result =", ok)
    if not ok:
        print("  [ERROR] Valid inputs failed verification. This indicates a serious issue.")
    else:
        print("  [OK] Valid case is accepted as expected.")


# ========== Case 2: PK derived with (MS, token=1) but generator is told token=0 ==========


def run_case_bad_token():
    """
    Case-BAD-TOKEN:
      PK is derived from (master_seed, token=1), but we call the generator
      with token=0 and that PK.

      This checks whether the generator/verifier accept a proof where
      (MS, token, PK) are inconsistent.
    """
    print("\n[CASE-BAD-TOKEN] PK is derived from token=1 but generator/verifier use token=0")

    master_seed = gen_master_seed_bytes()
    ms_hash = compute_master_seed_hash_bytes(master_seed)

    token0 = (0).to_bytes(32, "big")
    token1 = (1).to_bytes(32, "big")

    pk1 = derive_pk_from_ms_and_token(master_seed, token1)

    print("  master_seed =", short_hex(master_seed))
    print("  ms_hash     =", short_hex(ms_hash))
    print("  token0      =", short_hex(token0))
    print("  token1      =", short_hex(token1))
    print("  pk1 (from token=1) =", short_hex(pk1))

    print("  Now calling generator(master_seed, token0, pk1, ms_hash) ...")
    try:
        proof_hex = get_zkproof_for_ii_blue_apply(master_seed, token0, pk1, ms_hash)
        ok = verify_zkproof_for_ii_blue_apply(
            proof_hex,
            token0,
            pk1,
            ms_hash,
        )
        print("  verifier result =", ok)
        if ok:
            print("  [DANGER] Inconsistent (token, PK) combination was accepted. This is a serious bug.")
        else:
            print("  [OK] Verification failed, so the verifier does not accept mismatched token/PK pairs.")
    except Exception as e:
        print("  [OK] Generator refused to build a proof:", repr(e))
        print("       This means the CPU-side generator already checks that PK matches (master_seed, token0).")


# ========== Case 3: master_seed_hash does not match Poseidon(master_seed) ==========


def run_case_bad_ms_hash():
    """
    Case-BAD-MS-HASH:
      master_seed_hash is forged so that:

        ms_hash_bad != Poseidon(master_seed)

      but it still looks like a valid field element.

      The generator and verifier must reject proofs that try to "lie"
      about the master_seed_hash while keeping the same master_seed.
    """
    print("\n[CASE-BAD-MS-HASH] Use a forged master_seed_hash that does not match Poseidon(master_seed)")

    master_seed = gen_master_seed_bytes()
    ms_hash_good = compute_master_seed_hash_bytes(master_seed)
    token0 = (0).to_bytes(32, "big")
    pk0 = derive_pk_from_ms_and_token(master_seed, token0)

    # Forge a "different but valid" hash by tweaking the integer and
    # reducing modulo Pallas field modulus.
    ms_int = int.from_bytes(ms_hash_good, "big")
    ms_int_fake = (ms_int + 1) % PALLAS_P
    ms_hash_bad = ms_int_fake.to_bytes(32, "big")

    print("  master_seed   =", short_hex(master_seed))
    print("  ms_hash_good  =", short_hex(ms_hash_good))
    print("  ms_hash_bad   =", short_hex(ms_hash_bad))
    print("  token0        =", short_hex(token0))
    print("  pk0           =", short_hex(pk0))

    print("  Now calling generator(master_seed, token0, pk0, ms_hash_bad) ...")
    try:
        proof_hex = get_zkproof_for_ii_blue_apply(master_seed, token0, pk0, ms_hash_bad)
        ok = verify_zkproof_for_ii_blue_apply(
            proof_hex,
            token0,
            pk0,
            ms_hash_bad,
        )
        print("  verifier result =", ok)
        if ok:
            print("  [DANGER] Forged master_seed_hash is accepted. The circuit is not binding MS and ms_hash.")
        else:
            print("  [OK] Verification failed, so the verifier does not accept a forged ms_hash.")
    except Exception as e:
        print("  [OK] Generator refused to build a proof:", repr(e))
        print("       This shows that in practice it is hard to fake ms_hash != Poseidon(master_seed).")


def main():
    print("========== ZK BlueApply MS/Token consistency tests ==========")
    run_case_good()
    run_case_bad_token()
    run_case_bad_ms_hash()


if __name__ == "__main__":
    main()
