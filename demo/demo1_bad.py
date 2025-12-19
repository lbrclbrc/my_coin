#!/usr/bin/env python3
# demo/demo1_bad.py
#
# Demo 1 (BAD): examples of BlueApply2 failing on the node side.
#
# This file reuses the helpers from demo1_good and shows two typical
# failure stories around BlueApply2:
#
#   Scenario 1:
#     - The client never runs BlueApply1.
#     - It derives a "Type-1 style" account from the master seed,
#       but this account is still color = 0 on chain.
#     - The client then tries to call BlueApply2 using this non-blue
#       base account. The node rejects the request because the
#       master_seed_hash has never been registered by any BlueApply1.
#
#   Scenario 2:
#     - The client first runs a normal BlueApply1 so that the node
#       registers the master_seed_hash and the first blue account.
#     - Then the client builds a *valid* BlueApply2 envelope with
#       token = x using apply_for_blue_ii(...).
#     - Before sending it, the demo manually tampers payload["token"]
#       to some y != x, without recomputing the zk_proof.
#     - The node sees a mismatch between token and zk_proof and rejects
#       this forged BlueApply2.
#
# These two scenarios are meant to show how the protocol defends itself
# against missing setup (no BlueApply1) and against a forged public
# input in BlueApply2.

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

# Reuse helpers from the GOOD demo so that the code here stays short.
from demo.demo1_good import (
    build_demo_cert_for_client,
    create_local_account_for_blueapply1_from_masterseed,
    sync_account_from_node,
    run_blue_apply1_flow,
)


# ---------------------------------------------------
# Scenario 1: BlueApply2 without any BlueApply1
# ---------------------------------------------------
def demo_bad_blueapply2_without_blueapply1() -> None:
    """
    Scenario 1:
      - No BlueApply1 has been accepted yet.
      - The client still calls BlueApply2 using a base account that
        is not blue on chain. The node should reject this request.
    """
    print("========== DEMO 1 (BAD) Scenario 1: BlueApply2 without any BlueApply1 ==========\n")

    # 1) Initialize client and node (internal logs are muted).
    print("[BAD1] Initializing client and node...\n")
    alice = run_silently(Client, cert={})
    node = run_silently(Node)

    # 2) Set master seed and build a demo certificate for Alice.
    print("[BAD1] Setting master seed for Alice and building demo cert...\n")
    run_silently(alice.set_master_seed_from_password, "alice_password_demo1_bad_s1")
    build_demo_cert_for_client(alice)

    # 3) Derive a local Type-1 style account (token = 0) from the master seed.
    local_acct = create_local_account_for_blueapply1_from_masterseed(alice)
    print("[BAD1] Local Type-1 account derived from master seed:")
    print("  addr =", local_acct.addr)
    print()

    # 4) Ask the node for the on-chain view of this addr (it is not blue yet).
    synced_acct = sync_account_from_node(alice, node, local_acct.addr, local_acct)
    print("[BAD1] On-chain view BEFORE any BlueApply1:")
    print("  addr    =", short_hex(synced_acct.addr, 40))
    print("  color   =", synced_acct.IDCard["Color"])
    print("  ID      =", synced_acct.IDCard["ID"])
    print("  nonce   =", synced_acct.nonce)
    print("  balance =", synced_acct.balance)
    print("  (this is NOT a blue account yet)\n")

    # 5) Try to call BlueApply2 anyway, using this non-blue account as base.
    print("---------- BAD1 STEP: Send BlueApply2 using a non-blue base account ----------\n")

    bad_token_int = 123456789
    print(f"[BAD1] Preparing BlueApply2 envelope with token = {bad_token_int}")
    print("[BAD1] Base account addr (should be blue, but is not) =", short_hex(synced_acct.addr, 40))
    print()

    envelope2 = run_silently(alice.apply_for_blue_ii, synced_acct, bad_token_int)

    print("[BAD1] Sending BlueApply2 envelope to node...\n")
    result = run_silently(node.deal_with_request, envelope2)

    print("========== Node response for BAD1 BlueApply2 ==========\n")
    print(result)

    print("\n========== Blockchain state after BAD1 BlueApply2 ==========")
    print(node.blockchain)
    print("\n[BAD1] End of Scenario 1.\n\n")


# ---------------------------------------------------
# Scenario 2: BlueApply2 with inconsistent token
# ---------------------------------------------------
def demo_bad_blueapply2_with_wrong_token() -> None:
    """
    Scenario 2:
      - Run a normal BlueApply1 first so that the node knows the
        master_seed_hash and the first blue account.
      - Then build a valid BlueApply2 envelope with token = x.
      - Before sending, tamper payload["token"] to some y != x,
        without recomputing zk_proof.
      - The node should reject this forged BlueApply2.
    """
    print("========== DEMO 1 (BAD) Scenario 2: BlueApply2 with inconsistent token ==========\n")

    # 1) Initialize client and node, then run a GOOD BlueApply1.
    print("[BAD2] Initializing client and node...\n")
    alice = run_silently(Client, cert={})
    node = run_silently(Node)

    print("[BAD2] Setting master seed for Alice and building demo cert...\n")
    run_silently(alice.set_master_seed_from_password, "alice_password_demo1_bad_s2")
    build_demo_cert_for_client(alice)

    print("[BAD2] Running a normal BlueApply1 so that Alice gets her first blue account...\n")
    base_acct = run_silently(run_blue_apply1_flow, alice, node)

    # 2) Build a perfectly valid BlueApply2 envelope first.
    good_token_int = 123456789
    print(f"[BAD2] Building a NORMAL BlueApply2 envelope with token = {good_token_int}\n")
    good_envelope = run_silently(alice.apply_for_blue_ii, base_acct, good_token_int)
    good_payload = good_envelope["payload"]

    print("[BAD2]   original token (hex, short) =", short_hex(good_payload["token"]))
    print("[BAD2]   new_blue_pk (hex, short)    =", short_hex(good_payload["new_blue_pk"]))
    print()

    # 3) Forge a new envelope: only change payload["token"], keep zk_proof untouched.
    bad_payload = dict(good_payload)

    # Use a small field element as the forged token (different from good_token_int).
    forged_token_hex = "00" * 31 + "02"
    bad_payload["token"] = forged_token_hex

    print("[BAD2] Tampered payload token to a different value.")
    print("[BAD2]   forged token (hex, short)   =", short_hex(bad_payload["token"]))
    print()

    bad_envelope = {
        "application_type": good_envelope["application_type"],
        "payload": bad_payload,
    }

    # 4) Send the tampered envelope to the node.
    print("[BAD2] Sending tampered BlueApply2 envelope to node...\n")
    result = run_silently(node.deal_with_request, bad_envelope)

    print("========== Node response for BAD2 BlueApply2 ==========\n")
    print(result)

    print("\n========== Blockchain state after BAD2 BlueApply2 ==========")
    print(node.blockchain)
    print("\n[BAD2] End of Scenario 2.\n")


# ---------------------------------------------------
# Main entry point for all BAD demos
# ---------------------------------------------------
def main() -> None:
    """
    Run both BAD scenarios for Demo 1 so that a reader can see
    how BlueApply2 is rejected in two different ways.
    """
    demo_bad_blueapply2_without_blueapply1()
    demo_bad_blueapply2_with_wrong_token()


if __name__ == "__main__":
    main()
