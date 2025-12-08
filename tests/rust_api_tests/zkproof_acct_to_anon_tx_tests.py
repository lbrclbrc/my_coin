# tests/zkproof_for_acct_to_anon_tx_generator_tests.py
#
# Test suite for the acct_to_anon_tx zk proof circuit and its Python wrappers.
#
# This file exercises the following scenarios:
#
#   1) Honest proof with a single secret key (baseline correctness)
#      - Generate a random keypair (sk, pk).
#      - Derive addr = H(pk).
#      - Compute anon_commit = H(value, sk, nonce, addr).
#      - Call get_zkproof_for_acct_to_anon_tx(...) to generate a proof.
#      - Call verify_zkproof_for_acct_to_anon_tx(...) with matching public inputs.
#      - Expect the verifier to accept the proof.
#
#   2) Regression test with an "evil" proof where the commitment key and
#      address key differ
#      - Use two independent keypairs:
#          sk_commit drives anon_commit.
#          sk_addr drives addr.
#      - Use zkcrypto.zkproof_for_acct_to_anon_tx_evil_gen(...) to construct
#        a proof that *would* pass verification if the circuit forgot to link
#        addr and anon_commit to the same secret key.
#      - Run the verifier on this "evil" proof and confirm that:
#          The verifier REJECTS the proof (ok_evil == False).
#          A separate semantic check f_check_intended(...) shows what the
#          intended relation is ("addr and anon_commit share the same sk").
#      - If this test ever starts passing again (ok_evil == True), it means
#        we reintroduced the old bug and the circuit no longer enforces
#        the "same secret key" constraint between addr and anon_commit.
#
#   3) Negative tests for public input mismatches and tampering
#      - Wrong addr:
#          Replace addr with an unrelated address and verify the proof.
#          Expect the verifier to reject.
#      - Wrong anon_commit:
#          Flip one bit in anon_commit and verify the proof.
#          Expect the verifier to reject.
#      - anon_commit from another sk:
#          Recompute anon_commit using a different secret key but keep addr,
#            value, and nonce unchanged.
#          Expect the verifier to reject.
#      - Wrong value:
#          Change the public value by +1 and verify.
#          Expect the verifier to reject.
#      - Wrong nonce:
#          Change the public nonce by +1 and verify.
#          Expect the verifier to reject.
#      - Tampered proof:
#          Flip one bit in the proof bytes and verify.
#          Expect the verifier to reject.
#
# The goal of these tests is to:
#   - Confirm that the honest flow is accepted.
#   - Guard against regressions where "evil" proofs produced by a dedicated
#     helper would start passing (violating the intended "same sk" relation).
#   - Confirm that simple public-input or proof tampering is rejected.



import os, sys

# Add project root to sys.path
THIS_FILE = os.path.abspath(__file__)
THIS_DIR = os.path.dirname(THIS_FILE)
PROJECT_ROOT = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from wrappers.pasta_ecc_wrapper import EccKeypair
from wrappers.poseidon_hash_wrapper import get_poseidon_hash
from wrappers.zkproof_for_acct_to_anon_tx_wrapper import (
    get_zkproof_for_acct_to_anon_tx,
    verify_zkproof_for_acct_to_anon_tx,
)

import zkcrypto  # use the "evil" helper exposed by the zkcrypto pyo3 module


def flip_first_byte(b):
    """
    Flip the lowest bit of the first byte, keeping length unchanged.
    Used to tamper commitments / proofs in negative tests.
    """
    bb = bytearray(b)
    bb[0] = bb[0] ^ 1
    return bytes(bb)


def f_check_intended(sk_hex, val_bytes, nonce_bytes, addr_hex, anon_commit_hex):
    """
    Recompute the intended plaintext relation in Python:

      - addr is derived from the same secret key sk.
      - anon_commit = H(value, sk, nonce, addr).

    This does not affect the zk circuit itself. It is only used to
    interpret what the "evil" proof is actually doing from a semantic
    point of view (whether it respects the intended relation or not).
    """
    kp = EccKeypair()
    kp.set_sk(bytes.fromhex(sk_hex))

    derived_addr_hex = get_poseidon_hash(kp.get_pk_from_sk())
    if derived_addr_hex != addr_hex:
        return False

    right_commit_hex = get_poseidon_hash(
        val_bytes,
        bytes.fromhex(sk_hex),
        nonce_bytes,
        bytes.fromhex(addr_hex),
    )
    return right_commit_hex == anon_commit_hex


def main():
    # --------- correct case: honest proof with one secret key ----------

    kp = EccKeypair()
    sk_bytes = kp.get_sk()
    pk_bytes = kp.get_pk_from_sk()

    # addr / anon_commit are built in the same way as in the circuit:
    #   addr = H(pk)
    #   anon_commit = H(value, sk, nonce, addr)
    # get_poseidon_hash returns hex; we keep both hex for printing and bytes for the proof.
    addr_hex = get_poseidon_hash(pk_bytes)
    addr_bytes = bytes.fromhex(addr_hex)

    val_int = 10
    val_bytes = val_int.to_bytes(32, "big")

    nonce_int = 1
    nonce_bytes = nonce_int.to_bytes(32, "big")

    anon_commit_hex = get_poseidon_hash(val_bytes, sk_bytes, nonce_bytes, addr_bytes)
    anon_commit_bytes = bytes.fromhex(anon_commit_hex)

    # Generator: take all private/public inputs as bytes.
    proof_hex = get_zkproof_for_acct_to_anon_tx(
        sk_bytes,          # sin_sk
        val_bytes,         # pin_val
        nonce_bytes,       # pin_nonce
        addr_bytes,        # pin_addr
        anon_commit_bytes, # pin_anon_commit
    )

    # Verifier: use the same proof_hex and the same bytes inputs.
    ok = verify_zkproof_for_acct_to_anon_tx(
        proof_hex,          # proof (hex string)
        val_bytes,
        nonce_bytes,
        addr_bytes,
        anon_commit_bytes,
    )

    print("=== correct proof ===")
    print("sk_hex:", sk_bytes.hex())
    print("pk_hex:", pk_bytes.hex())
    print("addr_hex:", addr_hex)
    print("val_int:", val_int)
    print("nonce_int:", nonce_int)
    print("anon_commit_hex:", anon_commit_hex)
    print("zk_proof_hex:", proof_hex[0:20])
    print("verify(correct) ->", ok)
    print()

    # --------- EVIL CASE (regression): sk_commit != sk_addr; verifier must reject ----------

    # This case uses a helper from zkcrypto that intentionally builds
    # a proof where the commitment is driven by sk_commit, while the
    # address is driven by sk_addr.
    # In the old buggy version of the circuit, such a proof could still
    # pass verification (the "same secret key" link was missing).
    # After the fix, we expect the verifier to REJECT this proof.
    # If ok_evil ever becomes True again, it means we reintroduced the
    # old bug and the circuit no longer enforces "same secret key" for
    # addr and anon_commit.
    kp_commit = EccKeypair()
    sk_commit_bytes = kp_commit.get_sk()
    pk_commit_bytes = kp_commit.get_pk_from_sk()

    kp_addr = EccKeypair()
    sk_addr_bytes = kp_addr.get_sk()
    pk_addr_bytes = kp_addr.get_pk_from_sk()

    evil_addr_hex = get_poseidon_hash(pk_addr_bytes)
    evil_addr_bytes = bytes.fromhex(evil_addr_hex)

    evil_anon_commit_hex = get_poseidon_hash(
        val_bytes,
        sk_commit_bytes,
        nonce_bytes,
        evil_addr_bytes,
    )
    evil_anon_commit_bytes = bytes.fromhex(evil_anon_commit_hex)

    evil_proof_bytes = zkcrypto.get_evil_zkproof_for_acct_to_anon_tx(
        sk_commit_bytes,
        sk_addr_bytes,
        val_bytes,
        nonce_bytes,
    )
    evil_proof_hex = evil_proof_bytes.hex()

    ok_evil = verify_zkproof_for_acct_to_anon_tx(
        evil_proof_hex,
        val_bytes,
        nonce_bytes,
        evil_addr_bytes,
        evil_anon_commit_bytes,
    )

    intended_ok = f_check_intended(
        sk_commit_bytes.hex(),
        val_bytes,
        nonce_bytes,
        evil_addr_hex,
        evil_anon_commit_hex,
    )

    print("=== EVIL proof (sk_commit != sk_addr) ===")
    print("sk_commit_hex:", sk_commit_bytes.hex())
    print("pk_commit_hex:", pk_commit_bytes.hex())
    print("sk_addr_hex:", sk_addr_bytes.hex())
    print("pk_addr_hex:", pk_addr_bytes.hex())
    print("evil_addr_hex (from sk_addr):", evil_addr_hex)
    print("evil_anon_commit_hex (from sk_commit + evil_addr):", evil_anon_commit_hex)
    print("evil_proof_hex:", evil_proof_hex[0:20])
    print("verify(evil) ->", ok_evil)
    print("intended f(same sk) ->", intended_ok)
    print()
    # NOTE: ok_evil should be False after the fix; True would indicate a regression.


    # --------- negative test 1: wrong addr (public input mismatch) ----------

    kp2 = EccKeypair()
    sk2_bytes = kp2.get_sk()
    pk2_bytes = kp2.get_pk_from_sk()
    wrong_addr_hex = get_poseidon_hash(pk2_bytes)
    wrong_addr_bytes = bytes.fromhex(wrong_addr_hex)

    ok_wrong_addr = verify_zkproof_for_acct_to_anon_tx(
        proof_hex,
        val_bytes,
        nonce_bytes,
        wrong_addr_bytes,
        anon_commit_bytes,
    )

    print("=== negative test 1: wrong addr ===")
    print("wrong_addr_hex:", wrong_addr_hex)
    print("verify(wrong addr) ->", ok_wrong_addr)
    print()

    # --------- negative test 2: wrong anon_commit (public input mismatch) ----------

    wrong_anon_commit_bytes = flip_first_byte(anon_commit_bytes)
    wrong_anon_commit_hex = wrong_anon_commit_bytes.hex()

    ok_wrong_commit = verify_zkproof_for_acct_to_anon_tx(
        proof_hex,
        val_bytes,
        nonce_bytes,
        addr_bytes,
        wrong_anon_commit_bytes,
    )

    print("=== negative test 2: wrong anon_commit ===")
    print("wrong_anon_commit_hex:", wrong_anon_commit_hex)
    print("verify(wrong anon_commit) ->", ok_wrong_commit)
    print()

    # --------- negative test 3: anon_commit computed from another sk ----------

    anon_commit_from_sk2_hex = get_poseidon_hash(
        val_bytes,
        sk2_bytes,
        nonce_bytes,
        addr_bytes,
    )
    anon_commit_from_sk2_bytes = bytes.fromhex(anon_commit_from_sk2_hex)

    ok_commit_from_other_sk = verify_zkproof_for_acct_to_anon_tx(
        proof_hex,
        val_bytes,
        nonce_bytes,
        addr_bytes,
        anon_commit_from_sk2_bytes,
    )

    print("=== negative test 3: anon_commit from other sk ===")
    print("anon_commit_from_sk2_hex:", anon_commit_from_sk2_hex)
    print("verify(commit from other sk) ->", ok_commit_from_other_sk)
    print()

    # --------- negative test 4: wrong val ----------

    wrong_val_int = val_int + 1
    wrong_val_bytes = wrong_val_int.to_bytes(32, "big")

    ok_wrong_val = verify_zkproof_for_acct_to_anon_tx(
        proof_hex,
        wrong_val_bytes,
        nonce_bytes,
        addr_bytes,
        anon_commit_bytes,
    )

    print("=== negative test 4: wrong val ===")
    print("wrong_val_int:", wrong_val_int)
    print("verify(wrong val) ->", ok_wrong_val)
    print()

    # --------- negative test 5: wrong nonce ----------

    wrong_nonce_int = nonce_int + 1
    wrong_nonce_bytes = wrong_nonce_int.to_bytes(32, "big")

    ok_wrong_nonce = verify_zkproof_for_acct_to_anon_tx(
        proof_hex,
        val_bytes,
        wrong_nonce_bytes,
        addr_bytes,
        anon_commit_bytes,
    )

    print("=== negative test 5: wrong nonce ===")
    print("wrong_nonce_int:", wrong_nonce_int)
    print("verify(wrong nonce) ->", ok_wrong_nonce)
    print()

    # --------- negative test 6: tampered proof itself ----------

    proof_bytes = bytes.fromhex(proof_hex)
    tampered_proof_bytes = flip_first_byte(proof_bytes)
    tampered_proof_hex = tampered_proof_bytes.hex()

    ok_tampered_proof = verify_zkproof_for_acct_to_anon_tx(
        tampered_proof_hex,
        val_bytes,
        nonce_bytes,
        addr_bytes,
        anon_commit_bytes,
    )

    print("=== negative test 6: tampered proof ===")
    print("verify(tampered proof) ->", ok_tampered_proof)
    print()

    return 0


if __name__ == "__main__":
    main()
