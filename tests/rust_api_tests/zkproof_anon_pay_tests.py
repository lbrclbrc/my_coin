# tests/zkproof_anon_pay_tests.py
#
# Tests for the zk proof system used by AnonPay.
#
# These tests focus on:
#   - Verifying that valid proofs are accepted by the verifier.
#   - Rejecting "wraparound" attacks in the Pallas field.
#   - Rejecting incorrect public inputs (root / nullifier / commit_change / value_pay).
#   - Rejecting tampered or random proof bytes.
#   - Ensuring the proof generator fails when given inconsistent public inputs.


import os
import sys
import time

# Add project root to sys.path
THIS_FILE = os.path.abspath(__file__)
THIS_DIR = os.path.dirname(THIS_FILE)
PROJECT_ROOT = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from merkle_tree import MerkleTreeCommit
from wrappers.poseidon_hash_wrapper import get_poseidon_hash
from wrappers.pasta_ecc_wrapper import EccKeypair
from wrappers.zkproof_for_anon_pay_wrapper import (
    get_zkproof_for_anon_pay, ZERO32_HEX, verify_zkproof_for_anon_pay
)

import zkcrypto
from tools import PALLAS_P, short_hex

# ===== Basic helpers =====


def int_to_be32_bytes(i):
    """
    Encode an integer as a 32-byte big-endian value.
    """
    return int(i).to_bytes(32, "big")


def rand32_hex():
    """
    Return a random 32-byte value encoded as hex.
    """
    return os.urandom(32).hex()


def flip_one_bit_hex(h):
    """
    Flip the lowest bit of the first byte of a hex string.
    Used to create slightly corrupted inputs.
    """
    b = bytearray(bytes.fromhex(h))
    b[0] = b[0] ^ 1
    return bytes(b).hex()


def build_path_fixed_32(tree, index):
    """
    Normalize the Merkle path for a given leaf index into:
      - sibs: list of 32 sibling hex strings
      - dirs: list of 32 integers, 0 = right sibling, 1 = left sibling

    This matches the fixed-depth format expected by the AnonPay zk circuit.
    """
    proof = tree.gen_proof(index)
    sibs = []
    dirs = []
    idx = index
    h = 0
    while h < 32:
        sib_hex, direction = proof[h]
        sibs.append(sib_hex)
        if direction == "R":
            dirs.append(0)
        else:
            dirs.append(1)
        idx = idx // 2
        h += 1
    return sibs, dirs



# ===== Fixture builders: normal cases =====


def make_fixture(name, value_initial, value_pay):
    """
    Build a "normal" AnonPay fixture:

      - Choose a random secret key and source.
      - Compute:
          * value_change = value_initial - value_pay
          * old_commit    = H(value_initial, sk, nonce_initial, src)
          * nullifier     = H(sk, nonce_initial, src)
          * commit_change = H(value_change, sk, 0, nullifier)
      - Insert old_commit into a small Merkle tree and compute the root.
      - Generate a zk proof with these values and a fixed Merkle path.
      - Return all inputs and the proof in a single dict.
    """
    # private inputs (witness)
    value_change = value_initial - value_pay

    kp = EccKeypair()
    sk_bytes = kp.get_sk()
    sk_hex = sk_bytes.hex()

    nonce_initial_int = 5
    nonce_initial_bytes = int_to_be32_bytes(nonce_initial_int)
    nonce_initial_hex = nonce_initial_bytes.hex()

    src_bytes = os.urandom(32)
    src_hex = src_bytes.hex()

    # public inputs
    # pin_nullifier = H(sk, nonce_initial, src)
    nullifier_hex = get_poseidon_hash(sk_bytes, nonce_initial_bytes, src_bytes)

    # old_commit = H(value_initial, sk, nonce_initial, src)
    vinit_bytes = int_to_be32_bytes(value_initial)
    vinit_hex = vinit_bytes.hex()
    old_commit_hex = get_poseidon_hash(vinit_bytes, sk_bytes, nonce_initial_bytes, src_bytes)

    # Merkle tree over commitments (root is public)
    tree = MerkleTreeCommit()
    tree.append(rand32_hex())
    tree.append(old_commit_hex)
    tree.append(rand32_hex())
    tree.append(rand32_hex())
    root_hex = tree.root()

    # commit_change = H(value_change, sk, ZERO32, nullifier)
    vchange_bytes = int_to_be32_bytes(value_change)
    vchange_hex = vchange_bytes.hex()
    zero_bytes = bytes.fromhex(ZERO32_HEX)
    nullifier_bytes = bytes.fromhex(nullifier_hex)
    commit_change_hex = get_poseidon_hash(vchange_bytes, sk_bytes, zero_bytes, nullifier_bytes)

    # Merkle path inputs
    index = 1
    sibs, dirs = build_path_fixed_32(tree, index)

    # generate proof
    #   - public inputs (root/nullifier/commit_change) are passed as hex
    #   - secret inputs (sk/nonce/src) are passed as bytes
    t0 = time.time()
    proof_hex = get_zkproof_for_anon_pay(
        root_hex,            # public
        nullifier_hex,       # public
        commit_change_hex,   # public
        value_pay,           # public (int -> 32B field element)
        value_initial,       # secret
        value_change,        # secret
        sk_bytes,            # secret
        nonce_initial_bytes, # secret
        src_bytes,           # secret
        sibs,                # secret
        dirs,                # secret
    )
    t1 = time.time()

    return {
        "fixture_name": name,

        # public inputs (hex + int)
        "root_hex": root_hex,
        "nullifier_hex": nullifier_hex,
        "commit_change_hex": commit_change_hex,
        "value_pay": value_pay,

        # private inputs (also stored as hex when convenient)
        "value_initial": value_initial,
        "value_change": value_change,

        "sk_bytes": sk_bytes,
        "sk_hex": sk_hex,

        "nonce_initial_bytes": nonce_initial_bytes,
        "nonce_initial_hex": nonce_initial_hex,

        "src_bytes": src_bytes,
        "src_hex": src_hex,

        "old_commit_hex": old_commit_hex,

        # Merkle path
        "sibs": sibs,
        "dirs": dirs,

        # proof
        "proof_hex": proof_hex,
        "gen_seconds": t1 - t0,
        "fresh_gen": True,
    }


def make_wraparound_fixture(name):
    """
    Build a special fixture to test "wraparound" attacks in the Pallas field.

    We choose:
      value_initial = 1
      value_pay     = 2
      value_change  = p - 1

    In integer arithmetic:   1 != (p - 1) + 2
    In F_p arithmetic:       1  == (p - 1) + 2

    The verifier is required to enforce integer semantics for:
      value_initial = value_pay + value_change
    and therefore must reject this proof.
    """
    p = PALLAS_P

    value_initial = 1
    value_pay = 2
    value_change = p - 1

    kp = EccKeypair()
    sk_bytes = kp.get_sk()
    sk_hex = sk_bytes.hex()

    nonce_initial_int = 5
    nonce_initial_bytes = int_to_be32_bytes(nonce_initial_int)
    nonce_initial_hex = nonce_initial_bytes.hex()

    src_bytes = os.urandom(32)
    src_hex = src_bytes.hex()

    nullifier_hex = get_poseidon_hash(sk_bytes, nonce_initial_bytes, src_bytes)

    vinit_bytes = int_to_be32_bytes(value_initial)
    vinit_hex = vinit_bytes.hex()
    old_commit_hex = get_poseidon_hash(vinit_bytes, sk_bytes, nonce_initial_bytes, src_bytes)

    tree = MerkleTreeCommit()
    tree.append(rand32_hex())
    tree.append(old_commit_hex)
    tree.append(rand32_hex())
    tree.append(rand32_hex())
    root_hex = tree.root()

    vchange_bytes = int_to_be32_bytes(value_change)
    vchange_hex = vchange_bytes.hex()
    zero_bytes = bytes.fromhex(ZERO32_HEX)
    nullifier_bytes = bytes.fromhex(nullifier_hex)
    commit_change_hex = get_poseidon_hash(vchange_bytes, sk_bytes, zero_bytes, nullifier_bytes)

    index = 1
    sibs, dirs = build_path_fixed_32(tree, index)

    t0 = time.time()
    proof_hex = get_zkproof_for_anon_pay(
        root_hex,
        nullifier_hex,
        commit_change_hex,
        value_pay,           # public
        value_initial,       # secret
        value_change,        # secret (p-1)
        sk_bytes,
        nonce_initial_bytes,
        src_bytes,
        sibs,
        dirs,
    )
    t1 = time.time()

    return {
        "fixture_name": name,

        "root_hex": root_hex,
        "nullifier_hex": nullifier_hex,
        "commit_change_hex": commit_change_hex,
        "value_pay": value_pay,

        "value_initial": value_initial,
        "value_change": value_change,

        "sk_bytes": sk_bytes,
        "sk_hex": sk_hex,

        "nonce_initial_bytes": nonce_initial_bytes,
        "nonce_initial_hex": nonce_initial_bytes.hex(),

        "src_bytes": src_bytes,
        "src_hex": src_hex,

        "old_commit_hex": old_commit_hex,
        "sibs": sibs,
        "dirs": dirs,
        "proof_hex": proof_hex,
        "gen_seconds": t1 - t0,
        "fresh_gen": True,
    }


# ===== Fixture cache: proof generation is expensive =====

_FIXTURES = None


def get_fixtures():
    """
    Return a reusable fixture.

    The first call runs the proof generator.
    Later calls reuse cached fixtures and mark fresh_gen=False to indicate
    that the proof was not regenerated in this test run.
    """
    global _FIXTURES
    if _FIXTURES is None:
        fx_a = make_fixture("A", 100, 30)
        _FIXTURES = [fx_a]
        return _FIXTURES

    out = []
    for fx in _FIXTURES:
        fx2 = dict(fx)
        fx2["fresh_gen"] = False
        out.append(fx2)
    return out


# ===== Debug printing helpers (only for tests) =====


def debug_print_case(title, fx, verify_result):
    """
    Print a short summary of a verification attempt for a given fixture.
    """
    print("\n====", title, "fixture", fx["fixture_name"], "====")
    print("public root_hex:", short_hex(fx["root_hex"]))
    print("public nullifier_hex:", short_hex(fx["nullifier_hex"]))
    print("public commit_change_hex:", short_hex(fx["commit_change_hex"]))
    print("public value_pay:", fx["value_pay"])
    print("proof_hex prefix:", short_hex(fx["proof_hex"], 80))
    print("verifier result:", verify_result)
    if fx["fresh_gen"]:
        print("proof gen seconds:", fx["gen_seconds"])


def debug_print_gen_fail(title, fx, ok, err_msg):
    """
    Print a short summary for tests where proof generation is expected to fail.
    """
    print("\n----", title, "fixture", fx["fixture_name"], "----")
    print("gen should fail:", ok)
    if err_msg is not None:
        print("gen error:", err_msg)


# ===== Positive and negative test cases =====


def test_correct():
    """
    Valid fixtures must be accepted by the verifier when passing
    public inputs as hex strings.
    """
    fixtures = get_fixtures()
    for fx in fixtures:
        ok_hex = verify_zkproof_for_anon_pay(
            fx["root_hex"],
            fx["nullifier_hex"],
            fx["commit_change_hex"],
            fx["value_pay"],
            fx["proof_hex"],
        )
        debug_print_case("test_correct(hex)", fx, ok_hex)
        assert ok_hex is True


def test_wraparound_attack():
    """
    A wraparound attack in the Pallas field must be rejected
    (integer semantics for the balance equation must hold).
    """
    fx = make_wraparound_fixture("WRAP")
    ok = verify_zkproof_for_anon_pay(
        fx["root_hex"],
        fx["nullifier_hex"],
        fx["commit_change_hex"],
        fx["value_pay"],
        fx["proof_hex"],
    )
    debug_print_case("test_wraparound_attack", fx, ok)
    assert ok is False
    assert fx["value_initial"] != fx["value_change"] + fx["value_pay"]


def test_wrong_root():
    """
    If the Merkle root is wrong, the proof must be rejected.
    """
    fixtures = get_fixtures()
    for fx in fixtures:
        wrong_root = flip_one_bit_hex(fx["root_hex"])
        ok = verify_zkproof_for_anon_pay(
            wrong_root,
            fx["nullifier_hex"],
            fx["commit_change_hex"],
            fx["value_pay"],
            fx["proof_hex"],
        )
        fx2 = dict(fx)
        fx2["root_hex"] = wrong_root
        debug_print_case("test_wrong_root", fx2, ok)
        assert ok is False


def test_wrong_nullifier():
    """
    If the nullifier is wrong, the proof must be rejected.
    """
    fixtures = get_fixtures()
    for fx in fixtures:
        wrong_nullifier = flip_one_bit_hex(fx["nullifier_hex"])
        ok = verify_zkproof_for_anon_pay(
            fx["root_hex"],
            wrong_nullifier,
            fx["commit_change_hex"],
            fx["value_pay"],
            fx["proof_hex"],
        )
        fx2 = dict(fx)
        fx2["nullifier_hex"] = wrong_nullifier
        debug_print_case("test_wrong_nullifier", fx2, ok)
        assert ok is False


def test_wrong_commit_change():
    """
    If the change-commitment is wrong, the proof must be rejected.
    """
    fixtures = get_fixtures()
    for fx in fixtures:
        wrong_change = flip_one_bit_hex(fx["commit_change_hex"])
        ok = verify_zkproof_for_anon_pay(
            fx["root_hex"],
            fx["nullifier_hex"],
            wrong_change,
            fx["value_pay"],
            fx["proof_hex"],
        )
        fx2 = dict(fx)
        fx2["commit_change_hex"] = wrong_change
        debug_print_case("test_wrong_commit_change", fx2, ok)
        assert ok is False


def test_wrong_value_pay():
    """
    If the public pay amount is wrong, the proof must be rejected.
    """
    fixtures = get_fixtures()
    for fx in fixtures:
        wrong_value_pay = fx["value_pay"] + 1
        ok = verify_zkproof_for_anon_pay(
            fx["root_hex"],
            fx["nullifier_hex"],
            fx["commit_change_hex"],
            wrong_value_pay,
            fx["proof_hex"],
        )
        fx2 = dict(fx)
        fx2["value_pay"] = wrong_value_pay
        debug_print_case("test_wrong_value_pay", fx2, ok)
        assert ok is False


def test_tamper_proof_bytes():
    """
    Flipping a bit in the proof bytes must make the verifier reject it.
    """
    fixtures = get_fixtures()
    for fx in fixtures:
        b = bytearray(bytes.fromhex(fx["proof_hex"]))

        b[-1] = b[-1] ^ 1
        bad_proof_hex = bytes(b).hex()

        ok = verify_zkproof_for_anon_pay(
            fx["root_hex"],
            fx["nullifier_hex"],
            fx["commit_change_hex"],
            fx["value_pay"],
            bad_proof_hex,
        )
        fx2 = dict(fx)
        fx2["proof_hex"] = bad_proof_hex
        debug_print_case("test_tamper_proof_bytes", fx2, ok)
        assert ok is False


def test_random_proof():
    """
    A completely random proof must always be rejected.
    """
    fixtures = get_fixtures()
    for fx in fixtures:
        random_proof_hex = os.urandom(32).hex()
        ok = verify_zkproof_for_anon_pay(
            fx["root_hex"],
            fx["nullifier_hex"],
            fx["commit_change_hex"],
            fx["value_pay"],
            random_proof_hex,
        )
        fx2 = dict(fx)
        fx2["proof_hex"] = random_proof_hex
        debug_print_case("test_random_proof", fx2, ok)
        assert ok is False


# ---- Evil public inputs at generation time ----


def test_gen_wrong_nullifier_public():
    """
    Proof generation must fail when the public nullifier is inconsistent
    with the private witness.
    """
    fixtures = get_fixtures()
    for fx in fixtures:
        wrong_nullifier = flip_one_bit_hex(fx["nullifier_hex"])
        ok = False
        err_msg = None
        try:
            _ = get_zkproof_for_anon_pay(
                fx["root_hex"],
                wrong_nullifier,
                fx["commit_change_hex"],
                fx["value_pay"],
                fx["value_initial"],
                fx["value_change"],
                fx["sk_hex"],
                fx["nonce_initial_hex"],
                fx["src_hex"],
                fx["sibs"],
                fx["dirs"],
            )
        except Exception as e:
            ok = True
            err_msg = str(e)
        debug_print_gen_fail("test_gen_wrong_nullifier_public", fx, ok, err_msg)
        assert ok is True


def test_gen_wrong_root_public():
    """
    Proof generation must fail when the public Merkle root is inconsistent
    with the private witness.
    """
    fixtures = get_fixtures()
    for fx in fixtures:
        wrong_root = flip_one_bit_hex(fx["root_hex"])
        ok = False
        err_msg = None
        try:
            _ = get_zkproof_for_anon_pay(
                wrong_root,
                fx["nullifier_hex"],
                fx["commit_change_hex"],
                fx["value_pay"],
                fx["value_initial"],
                fx["value_change"],
                fx["sk_hex"],
                fx["nonce_initial_hex"],
                fx["src_hex"],
                fx["sibs"],
                fx["dirs"],
            )
        except Exception as e:
            ok = True
            err_msg = str(e)
        debug_print_gen_fail("test_gen_wrong_root_public", fx, ok, err_msg)
        assert ok is True


def test_gen_wrong_commit_change_public():
    """
    Proof generation must fail when the public change-commitment is
    inconsistent with the private witness.
    """
    fixtures = get_fixtures()
    for fx in fixtures:
        wrong_change = flip_one_bit_hex(fx["commit_change_hex"])
        ok = False
        err_msg = None
        try:
            _ = get_zkproof_for_anon_pay(
                fx["root_hex"],
                fx["nullifier_hex"],
                wrong_change,
                fx["value_pay"],
                fx["value_initial"],
                fx["value_change"],
                fx["sk_hex"],
                fx["nonce_initial_hex"],
                fx["src_hex"],
                fx["sibs"],
                fx["dirs"],
            )
        except Exception as e:
            ok = True
            err_msg = str(e)
        debug_print_gen_fail("test_gen_wrong_commit_change_public", fx, ok, err_msg)
        assert ok is True


if __name__ == "__main__":
    test_correct()
    test_wraparound_attack()
    test_wrong_root()
    test_wrong_nullifier()
    test_wrong_commit_change()
    test_wrong_value_pay()
    test_tamper_proof_bytes()
    test_random_proof()

    test_gen_wrong_nullifier_public()
    test_gen_wrong_root_public()
    test_gen_wrong_commit_change_public()

    print("\n=== all anon_pay tests finished ===")
