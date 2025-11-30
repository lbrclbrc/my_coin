#!/usr/bin/env python3
# demo/demo3_bad.py
#
# Demo 3 (BAD):
#   Scenario 1: AcctToAnon from a non-blue account (Color != 1).
#   Scenario 2: AcctToAnon with a forged anon_commit in the envelope.
#
# Internal logs from Client / Node / Rust zk-verifier are hidden via run_silently.
# The demo prints a short, human-readable story for each failing case.

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
from acct import Account
from tools import short_hex, run_silently
from demo.demo1_good import build_demo_cert_for_client, run_blue_apply1_flow
from demo.demo3_good import run_acct_to_anon
from wrappers.pasta_ecc_wrapper import EccKeypair
from wrappers.poseidon_hash_wrapper import get_poseidon_hash


def _build_alice_blue(node: Node, password_suffix: str):
    """
    Helper:
      - Create Alice client.
      - Set master seed from a password.
      - Build demo cert.
      - Run BlueApply1 and return (client, blue_account).
    """
    print(f"[DEMO3-BAD] Creating Alice client ({password_suffix})...")
    alice = run_silently(Client, cert={})

    password = "alice_password_demo3_bad_" + password_suffix
    run_silently(alice.set_master_seed_from_password, password)
    run_silently(build_demo_cert_for_client, alice)

    blue_acct = run_silently(run_blue_apply1_flow, alice, node)
    alice.Dict_of_accts[blue_acct.addr] = blue_acct

    print("[DEMO3-BAD] Alice blue account:")
    print(f"  addr    = {blue_acct.addr}")
    print(f"  balance = {blue_acct.balance}")
    print(f"  color   = {blue_acct.IDCard['Color']} (1 means blue)")
    return alice, blue_acct


def scenario_non_blue_acct_to_anon() -> None:
    """
    Scenario 1:
      1) Alice gets a blue account via BlueApply1.
      2) Alice sends some funds to a fresh address that has never run BlueApply1.
         This fresh address becomes a non-blue on-chain account (Color = 0).
      3) Try to run AcctToAnon from that non-blue account.
      Expected result: Node rejects the request because the account is not blue.
    """
    print("\n=== Scenario 1: AcctToAnon from a non-blue account ===")

    node = run_silently(Node)

    # Step 1: Alice blue account
    alice, alice_blue_acct = _build_alice_blue(node, "non_blue_scenario")
    alice_blue_addr = alice_blue_acct.addr

    # Step 2: construct a fresh non-blue account (never runs BlueApply1)
    red_kp = EccKeypair()
    # get_sk() both generates and stores the secret key inside the wrapper
    red_sk = red_kp.get_sk()
    red_pk = red_kp.get_pk_from_sk()
    red_addr_hex = get_poseidon_hash(red_pk)

    red_acct = Account()
    red_acct.addr = red_addr_hex
    red_acct.ecc_keypair = red_kp

    print("[DEMO3-BAD] Constructed a fresh non-blue account:")
    print(f"  addr    = {red_acct.addr}")
    print("  (it has never run BlueApply1, so it should stay Color = 0 on chain)")

    # Step 3: transfer some funds from Alice blue account to the non-blue account
    send_amount = 200
    print("\n[DEMO3-BAD] Transfer from Alice blue account to non-blue account:")
    print(f"  from_addr = {short_hex(alice_blue_addr)}")
    print(f"  to_addr   = {short_hex(red_acct.addr)}")
    print(f"  amount    = {send_amount}")

    tx = run_silently(
        alice.build_transfer_request,
        alice_blue_addr,
        red_acct.addr,
        send_amount,
    )

    transfer_envelope = {
        "application_type": "Transfer",
        "payload": tx["payload"],
    }

    transfer_res = run_silently(node.deal_with_request, transfer_envelope)
    print("[DEMO3-BAD] Node response for funding transfer:")
    print(f"  {transfer_res}")

    # Step 4: sync the non-blue account from the node
    red_onchain = run_silently(alice.fetch_account_from_node, node, red_acct.addr)
    if red_onchain is None:
        print("[DEMO3-BAD][WARN] Could not fetch non-blue account from node.")
        return

    red_onchain.ecc_keypair = red_acct.ecc_keypair
    alice.Dict_of_accts[red_onchain.addr] = red_onchain

    print("[DEMO3-BAD] On-chain non-blue account after funding:")
    print(f"  addr    = {red_onchain.addr}")
    print(f"  balance = {red_onchain.balance}")
    color_val = None
    if isinstance(red_onchain.IDCard, dict) and "Color" in red_onchain.IDCard:
        color_val = red_onchain.IDCard["Color"]
    print(f"  color   = {color_val} (expected 0 for non-blue)")

    # Step 5: try AcctToAnon from this non-blue account (quiet mode)
    deposit_amount = min(100, red_onchain.balance)
    print("\n[DEMO3-BAD] Trying AcctToAnon from non-blue account:")
    print(f"  deposit amount = {deposit_amount}")

    result = run_acct_to_anon(
        client=alice,
        owner_label="NonBlueAccount",
        acct=red_onchain,
        amount=deposit_amount,
        node=node,
        explain_proof=False,
        quiet=True,
    )

    res = result["res"]
    print("[DEMO3-BAD] Node response for AcctToAnon from non-blue account:")
    print(f"  {res}")
    if isinstance(res, dict) and "ok" in res and not res["ok"]:
        print("[DEMO3-BAD][OK] AcctToAnon from non-blue account was rejected as expected.")
    else:
        print("[DEMO3-BAD][WARN] Non-blue AcctToAnon was not rejected as expected.")


def scenario_forged_anon_commit() -> None:
    """
    Scenario 2:
      1) Alice gets a blue account via BlueApply1.
      2) Alice builds a valid AcctToAnon envelope with some amount.
      3) The zk proof and other fields stay unchanged, but payload['anon_commit']
         is replaced by a commitment built from a different secret key.
      Expected result: Node rejects the forged request as a bad zk proof.
    """
    print("\n=== Scenario 2: AcctToAnon with forged anon_commit ===")

    node = run_silently(Node)

    # Step 1: Alice blue account
    alice, alice_blue_acct = _build_alice_blue(node, "forged_commit_scenario")
    alice_blue_addr = alice_blue_acct.addr

    # Step 2: build a valid AcctToAnon envelope on Alice's side
    deposit_amount = 150
    alice.Dict_of_accts[alice_blue_addr] = alice_blue_acct

    print("[DEMO3-BAD] Building a valid AcctToAnon envelope:")
    print(f"  from_addr = {short_hex(alice_blue_addr)}")
    print(f"  amount    = {deposit_amount}")

    good_envelope = run_silently(
        alice.apply_for_acct2anon,
        alice_blue_acct,
        deposit_amount,
    )
    good_payload = good_envelope["payload"]

    print("[DEMO3-BAD] Original anon_commit (short):")
    print(f"  {short_hex(good_payload['anon_commit'])}")

    # Step 3: forge anon_commit using a different secret key
    # The zk_proof in the payload remains unchanged; only anon_commit is replaced.
    val_bytes = deposit_amount.to_bytes(32, "big")

    nonce_int = good_payload["nonce"]
    nonce_bytes = nonce_int.to_bytes(32, "big")

    from_addr_hex = good_payload["from_addr"]
    from_addr_bytes = bytes.fromhex(from_addr_hex)

    # New random secret key that is different from the key of alice_blue_acct
    evil_kp = EccKeypair()
    evil_sk_bytes = evil_kp.get_sk()

    evil_anon_commit_hex = get_poseidon_hash(
        val_bytes,
        evil_sk_bytes,
        nonce_bytes,
        from_addr_bytes,
    )

    print("[DEMO3-BAD] Forged anon_commit (short):")
    print(f"  {short_hex(evil_anon_commit_hex)}")

    bad_payload = dict(good_payload)
    bad_payload["anon_commit"] = evil_anon_commit_hex

    bad_envelope = {
        "application_type": good_envelope["application_type"],
        "payload": bad_payload,
    }

    # Step 4: send the forged envelope to the node
    print("[DEMO3-BAD] Sending forged AcctToAnon envelope to node (anon_commit changed)...")
    res = run_silently(node.deal_with_request, bad_envelope)

    print("[DEMO3-BAD] Node response for forged anon_commit:")
    print(f"  {res}")
    if isinstance(res, dict) and "ok" in res and not res["ok"]:
        print("[DEMO3-BAD][OK] Forged anon_commit was rejected as expected.")
    else:
        print("[DEMO3-BAD][WARN] Forged anon_commit was not rejected as expected.")


def main() -> None:
    """
    Run all BAD scenarios for Demo 3:
      - AcctToAnon from a non-blue account.
      - AcctToAnon with a forged anon_commit in the envelope.
    """
    print("========== DEMO 3 (BAD): AcctToAnon failure scenarios ==========\n")
    scenario_non_blue_acct_to_anon()
    scenario_forged_anon_commit()
    print("\n[DEMO3-BAD] Demo finished.")


if __name__ == "__main__":
    main()
