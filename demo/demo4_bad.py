#!/usr/bin/env python3
# demo/demo4_bad.py
#
# Demo 4 (BAD):
#   Several failure scenarios for AnonPay:
#     1) Broken value conservation: amount is modified in the envelope.
#     2) Forged commit_change using a wrong src (addr instead of nullifier).
#     3) Forged commit_change using a wrong sk (for example all-zero).
#     4) Double-spend with the same nullifier.
#     5) AnonPay with a wrong nullifier in the payload.
#
# Internal logs from Client / Node / Rust zk-verifier are hidden via run_silently.
# Only short [DEMO4-BAD] messages and node responses are printed.

import os
import sys

# Add project root to sys.path
THIS_FILE = os.path.abspath(__file__)
THIS_DIR = os.path.dirname(THIS_FILE)
PROJECT_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from client.core import Client
from node.core import Node
from tools import short_hex, run_silently, PALLAS_P
from demo.demo1_good import build_demo_cert_for_client, run_blue_apply1_flow
from demo.demo4_good import build_merkle_path_for_commit, run_acct_to_anon_simple
from wrappers.poseidon_hash_wrapper import get_poseidon_hash


def _looks_like_hex(s):
    """
    Return True if s looks like a long lowercase hex string.
    """
    if not isinstance(s, str):
        return False
    if len(s) < 16:
        return False
    i = 0
    while i < len(s):
        ch = s[i]
        if not (("0" <= ch <= "9") or ("a" <= ch <= "f")):
            return False
        i = i + 1
    return True


def _shorten_obj_for_print(obj):
    """
    Recursively shorten long hex strings inside dict / list / tuple
    using short_hex so that zk_proof and big hex fields are compact.
    """
    if isinstance(obj, dict):
        new_dict = {}
        for k in obj:
            new_dict[k] = _shorten_obj_for_print(obj[k])
        return new_dict

    if isinstance(obj, list):
        new_list = []
        i = 0
        while i < len(obj):
            new_list.append(_shorten_obj_for_print(obj[i]))
            i = i + 1
        return new_list

    if isinstance(obj, tuple):
        new_list = []
        i = 0
        while i < len(obj):
            new_list.append(_shorten_obj_for_print(obj[i]))
            i = i + 1
        return tuple(new_list)

    if isinstance(obj, str):
        if _looks_like_hex(obj):
            return short_hex(obj)
        return obj

    return obj


def _print_node_response(label, res):
    """
    Print a node response with long hex strings shortened.
    """
    short_res = _shorten_obj_for_print(res)
    print(label)
    print(f"  {short_res}")


def _random_addr_hex():
    """
    Generate a random address hex in the Poseidon field range [0, PALLAS_P).
    """
    raw_bytes = os.urandom(32)
    v = int.from_bytes(raw_bytes, "big")
    v_mod = v % PALLAS_P
    addr_bytes = v_mod.to_bytes(32, "big")
    return addr_bytes.hex()


def _setup_alice_and_note(node: Node, label_suffix: str, deposit_amount: int):
    """
    Create Alice client, blue account, and one anon note for this scenario.
    """
    print(f"[DEMO4-BAD] Setup Alice ({label_suffix})")

    alice = run_silently(Client, cert={})
    alice_pwd = "alice_password_demo4_bad_" + label_suffix
    run_silently(alice.set_master_seed_from_password, alice_pwd)
    run_silently(build_demo_cert_for_client, alice)

    alice_blue = run_silently(run_blue_apply1_flow, alice, node)
    alice.Dict_of_accts[alice_blue.addr] = alice_blue

    print(f"[DEMO4-BAD]   Alice blue addr  = {short_hex(alice_blue.addr)}")
    print(f"[DEMO4-BAD]   Alice balance    = {alice_blue.balance}")
    print(f"[DEMO4-BAD]   Alice color      = {alice_blue.IDCard['Color']} (1 means blue)")

    alice_blue, anon_commit, nonce_int = run_acct_to_anon_simple(
        alice,
        "Alice",
        alice_blue,
        deposit_amount,
        node,
    )

    print(f"[DEMO4-BAD]   Alice anon_commit = {short_hex(anon_commit)}")
    print(f"[DEMO4-BAD]   Alice acct nonce  = {nonce_int}\n")

    return alice, alice_blue, anon_commit, nonce_int


def _build_good_anonpay_envelope(
    node: Node,
    alice: Client,
    alice_blue,
    anon_commit_hex: str,
    nonce_int: int,
    pay_amount: int,
    note_value_initial: int,
    to_addr: str,
):
    """
    Build a valid AnonPay envelope from a single anon note.
    """
    note_nonce_bytes = nonce_int.to_bytes(32, "big")
    note_src_bytes = bytes.fromhex(alice_blue.addr)

    root_hex, siblings, dirs = build_merkle_path_for_commit(node, anon_commit_hex)

    print("[DEMO4-BAD] Building a valid AnonPay envelope:")
    print(f"  tree_root       = {short_hex(root_hex)}")
    print(f"  from_note_value = {note_value_initial}")
    print(f"  pay_amount      = {pay_amount}")
    print(f"  to_addr         = {short_hex(to_addr)}")

    envelope = run_silently(
        alice.apply_for_anon_pay,
        alice_blue,
        root_hex,
        to_addr,
        pay_amount,
        note_value_initial,
        note_nonce_bytes,
        note_src_bytes,
        siblings,
        dirs,
    )

    payload = envelope["payload"]
    print("[DEMO4-BAD]   payload short view:")
    print(f"    amount        = {payload['amount']}")
    print(f"    nullifier     = {short_hex(payload['nullifier'])}")
    print(f"    commit_change = {short_hex(payload['commit_change'])}")
    print(f"    zk_proof      = {short_hex(payload['zk_proof'])}\n")

    return envelope, root_hex, siblings, dirs


def scenario_bad_value_conservation():
    """
    Scenario 1: amount is forged to be larger than the proven value.
    """
    print("\n=== Scenario 1: Broken value conservation (amount modified) ===")

    node = run_silently(Node)
    deposit_amount = 300

    alice, alice_blue, anon_commit, nonce_int = _setup_alice_and_note(
        node,
        "bad_value_conservation",
        deposit_amount,
    )

    pay_amount = 100
    note_value_initial = deposit_amount
    to_addr = _random_addr_hex()

    good_envelope, _, _, _ = _build_good_anonpay_envelope(
        node,
        alice,
        alice_blue,
        anon_commit,
        nonce_int,
        pay_amount,
        note_value_initial,
        to_addr,
    )
    good_payload = good_envelope["payload"]

    forged_payload = dict(good_payload)
    forged_amount = good_payload["amount"] + 50
    forged_payload["amount"] = forged_amount

    print("[DEMO4-BAD] Forged payload with larger amount:")
    print(f"  original amount = {good_payload['amount']}")
    print(f"  forged   amount = {forged_payload['amount']}")

    forged_envelope = {
        "application_type": good_envelope["application_type"],
        "payload": forged_payload,
    }

    print("[DEMO4-BAD] Sending forged envelope to node...")
    res = run_silently(node.deal_with_request, forged_envelope)

    _print_node_response("[DEMO4-BAD] Node response:", res)
    print("[DEMO4-BAD] (Expected: rejected as bad zk proof)\n")


def scenario_forged_commit_change_wrong_src():
    """
    Scenario 2: commit_change is recomputed using addr instead of nullifier.
    """
    print("\n=== Scenario 2: Forged commit_change using wrong src ===")

    node = run_silently(Node)
    deposit_amount = 300

    alice, alice_blue, anon_commit, nonce_int = _setup_alice_and_note(
        node,
        "wrong_src",
        deposit_amount,
    )

    pay_amount = 100
    note_value_initial = deposit_amount
    to_addr = _random_addr_hex()

    good_envelope, _, _, _ = _build_good_anonpay_envelope(
        node,
        alice,
        alice_blue,
        anon_commit,
        nonce_int,
        pay_amount,
        note_value_initial,
        to_addr,
    )
    good_payload = good_envelope["payload"]

    value_change = note_value_initial - good_payload["amount"]
    val_change_bytes = value_change.to_bytes(32, "big")

    sk_bytes = alice_blue.ecc_keypair.get_sk()
    zero_bytes = bytes(32)
    addr_bytes = bytes.fromhex(alice_blue.addr)

    forged_commit_change_hex = get_poseidon_hash(
        val_change_bytes,
        sk_bytes,
        zero_bytes,
        addr_bytes,
    )

    forged_payload = dict(good_payload)
    forged_payload["commit_change"] = forged_commit_change_hex

    print("[DEMO4-BAD] Original vs forged commit_change (short):")
    print(f"  original = {short_hex(good_payload['commit_change'])}")
    print(f"  forged   = {short_hex(forged_commit_change_hex)}")

    forged_envelope = {
        "application_type": good_envelope["application_type"],
        "payload": forged_payload,
    }

    print("[DEMO4-BAD] Sending forged envelope to node...")
    res = run_silently(node.deal_with_request, forged_envelope)

    _print_node_response("[DEMO4-BAD] Node response:", res)
    print("[DEMO4-BAD] (Expected: rejected as bad zk proof)\n")


def scenario_forged_commit_change_wrong_sk():
    """
    Scenario 3: commit_change is recomputed with a wrong secret key.
    """
    print("\n=== Scenario 3: Forged commit_change using wrong sk ===")

    node = run_silently(Node)
    deposit_amount = 300

    alice, alice_blue, anon_commit, nonce_int = _setup_alice_and_note(
        node,
        "wrong_sk",
        deposit_amount,
    )

    pay_amount = 100
    note_value_initial = deposit_amount
    to_addr = _random_addr_hex()

    good_envelope, _, _, _ = _build_good_anonpay_envelope(
        node,
        alice,
        alice_blue,
        anon_commit,
        nonce_int,
        pay_amount,
        note_value_initial,
        to_addr,
    )
    good_payload = good_envelope["payload"]

    value_change = note_value_initial - good_payload["amount"]
    val_change_bytes = value_change.to_bytes(32, "big")

    fake_sk_bytes = bytes(32)
    zero_bytes = bytes(32)
    nullifier_bytes = bytes.fromhex(good_payload["nullifier"])

    forged_commit_change_hex = get_poseidon_hash(
        val_change_bytes,
        fake_sk_bytes,
        zero_bytes,
        nullifier_bytes,
    )

    forged_payload = dict(good_payload)
    forged_payload["commit_change"] = forged_commit_change_hex

    print("[DEMO4-BAD] Original vs forged commit_change (short):")
    print(f"  original = {short_hex(good_payload['commit_change'])}")
    print(f"  forged   = {short_hex(forged_commit_change_hex)}")

    forged_envelope = {
        "application_type": good_envelope["application_type"],
        "payload": forged_payload,
    }

    print("[DEMO4-BAD] Sending forged envelope to node...")
    res = run_silently(node.deal_with_request, forged_envelope)

    _print_node_response("[DEMO4-BAD] Node response:", res)
    print("[DEMO4-BAD] (Expected: rejected as bad zk proof)\n")


def scenario_double_spend():
    """
    Scenario 4: send the same valid AnonPay envelope twice.
    """
    print("\n=== Scenario 4: Double-spend with the same nullifier ===")

    node = run_silently(Node)
    deposit_amount = 300

    alice, alice_blue, anon_commit, nonce_int = _setup_alice_and_note(
        node,
        "double_spend",
        deposit_amount,
    )

    pay_amount = 100
    note_value_initial = deposit_amount
    to_addr = _random_addr_hex()

    good_envelope, _, _, _ = _build_good_anonpay_envelope(
        node,
        alice,
        alice_blue,
        anon_commit,
        nonce_int,
        pay_amount,
        note_value_initial,
        to_addr,
    )

    print("[DEMO4-BAD] Sending valid envelope (first time)...")
    res1 = run_silently(node.deal_with_request, good_envelope)
    _print_node_response("[DEMO4-BAD] Node response (first time):", res1)

    print("[DEMO4-BAD] Sending the same envelope again (double-spend)...")
    res2 = run_silently(node.deal_with_request, good_envelope)
    _print_node_response("[DEMO4-BAD] Node response (second time):", res2)
    print("[DEMO4-BAD] (Expected: second one is rejected due to used nullifier)\n")


def scenario_wrong_nullifier():
    """
    Scenario 5: nullifier is modified while proof and commit_change stay the same.
    """
    print("\n=== Scenario 5: AnonPay with wrong nullifier in payload ===")

    node = run_silently(Node)
    deposit_amount = 300

    alice, alice_blue, anon_commit, nonce_int = _setup_alice_and_note(
        node,
        "wrong_nullifier",
        deposit_amount,
    )

    pay_amount = 100
    note_value_initial = deposit_amount
    to_addr = _random_addr_hex()

    good_envelope, _, _, _ = _build_good_anonpay_envelope(
        node,
        alice,
        alice_blue,
        anon_commit,
        nonce_int,
        pay_amount,
        note_value_initial,
        to_addr,
    )
    good_payload = good_envelope["payload"]

    nullifier_bytes = bytearray(bytes.fromhex(good_payload["nullifier"]))
    nullifier_bytes[0] = nullifier_bytes[0] ^ 1
    forged_nullifier_hex = bytes(nullifier_bytes).hex()

    forged_payload = dict(good_payload)
    forged_payload["nullifier"] = forged_nullifier_hex

    print("[DEMO4-BAD] Original vs forged nullifier (short):")
    print(f"  original = {short_hex(good_payload['nullifier'])}")
    print(f"  forged   = {short_hex(forged_nullifier_hex)}")

    forged_envelope = {
        "application_type": good_envelope["application_type"],
        "payload": forged_payload,
    }

    print("[DEMO4-BAD] Sending forged envelope to node...")
    res = run_silently(node.deal_with_request, forged_envelope)

    _print_node_response("[DEMO4-BAD] Node response:", res)
    print("[DEMO4-BAD] (Expected: rejected as bad zk proof)\n")


def main() -> None:
    """
    Run all BAD scenarios for Demo 4 with a random receiver address.
    """
    chain_path = os.path.join(PROJECT_ROOT, "current_blockchain.txt")
    with open(chain_path, "w", encoding="utf-8") as f:
        f.write("")
    print("========== DEMO 4 (BAD): AnonPay failure scenarios ==========\n")
    print("[DEMO4-BAD] Cleared current_blockchain.txt\n")

    scenario_bad_value_conservation()
    scenario_forged_commit_change_wrong_src()
    scenario_forged_commit_change_wrong_sk()
    scenario_double_spend()
    scenario_wrong_nullifier()

    print("\n[DEMO4-BAD] Demo finished.")


if __name__ == "__main__":
    main()
