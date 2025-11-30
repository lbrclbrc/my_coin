#!/usr/bin/env python3
# demo/demo2_good.py
#
# Demo 2 (GOOD):
#   1) Alice runs BlueApply1 and gets a blue account with initial balance.
#   2) Bob   runs BlueApply1 and also gets a blue account.
#   3) Alice -> Bob transfer 300.
#   4) Bob   -> Alice transfer 200.
#
# Internal logs from Node/Client/Rust zk-verifier are hidden in this demo.
# Only high-level steps and transfer summaries are printed with [DEMO2] prefix.

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
from tools import short_hex, run_silently
from demo.demo1_good import build_demo_cert_for_client, run_blue_apply1_flow


def run_regular_transfer(sender_client: Client,
                         sender_label: str,
                         receiver_label: str,
                         from_addr: str,
                         to_addr: str,
                         amount: int,
                         node: Node) -> dict:
    """
    Run a regular Transfer from `from_addr` to `to_addr` as `sender_client`.

    sender_label / receiver_label are only used for human-readable logs.
    All Node internal logs are hidden; only a short block summary is printed.
    """
    print("\n[DEMO2] Regular transfer: {} -> {}".format(sender_label, receiver_label))
    print("[DEMO2]   from_addr =", short_hex(from_addr))
    print("[DEMO2]   to_addr   =", short_hex(to_addr))
    print("[DEMO2]   amount    =", amount)

    # Build transfer request on the sender side.
    # This reads sender_client.Dict_of_accts[from_addr] and signs the tx.
    tx = run_silently(sender_client.build_transfer_request, from_addr, to_addr, amount)

    envelope = {
        "application_type": "Transfer",
        "payload": tx["payload"],
    }

    # Send to node with all internal logs hidden
    res = run_silently(node.deal_with_request, envelope)

    if "ok" in res and res["ok"] and "new_block" in res:
        nb = res["new_block"]
        print("[DEMO2][OK] Transfer accepted by node. Block summary:")
        print("  account_root =", short_hex(nb["account_root"]))
        print("  tx_root      =", short_hex(nb["tx_root"]))
        print("  commit_root  =", short_hex(nb["commit_root"]))
        print("  from_addr    =", short_hex(nb["from_addr"]))
        print("  to_addr      =", short_hex(nb["to_addr"]))
    else:
        print("[DEMO2][ERROR] Transfer rejected by node.")
        print("  raw response =", res)

    return res


def main() -> None:
    print("========== DEMO 2 (GOOD): BlueApply1 + Regular Transfers ==========\n")

    # 1. Initialize node (hide its own prints)
    node = run_silently(Node)
    print("[DEMO2] Node initialized.")

    # 2. Create clients for Alice and Bob (hide Client internal prints)
    print("\n[DEMO2] Creating Alice client...")
    alice = run_silently(Client, cert={})

    print("[DEMO2] Creating Bob client...")
    bob = run_silently(Client, cert={})

    # 3. Set master seeds (password-based)
    print("\n[DEMO2] Setting master seed for Alice (from password)...")
    run_silently(alice.set_master_seed_from_password, "alice_password_demo2_good")
    print("[DEMO2]   Alice MASTER_SEED (short) =", short_hex(alice.MASTER_SEED.hex()))

    print("\n[DEMO2] Setting master seed for Bob (from password)...")
    run_silently(bob.set_master_seed_from_password, "bob_password_demo2_good")
    print("[DEMO2]   Bob   MASTER_SEED (short) =", short_hex(bob.MASTER_SEED.hex()))

    # 4. Build demo certificates so both Alice and Bob can run BlueApply1
    print("\n[DEMO2] Building demo certificate for Alice (used by BlueApply1)...")
    run_silently(build_demo_cert_for_client, alice)

    print("[DEMO2] Building demo certificate for Bob (used by BlueApply1)...")
    run_silently(build_demo_cert_for_client, bob)

    # 5. Alice runs BlueApply1 (full details hidden; only final state shown)
    print("\n========== STEP 1: Alice BlueApply1 ==========")
    alice_blue_acct = run_silently(run_blue_apply1_flow, alice, node)
    alice_blue_addr = alice_blue_acct.addr
    print("[DEMO2] Alice blue account ready:")
    print("  addr    =", alice_blue_addr)
    print("  balance =", alice_blue_acct.balance)
    print("  color   =", alice_blue_acct.IDCard["Color"], " (1 means blue)")

    # 6. Bob runs BlueApply1
    print("\n========== STEP 2: Bob BlueApply1 ==========")
    bob_blue_acct = run_silently(run_blue_apply1_flow, bob, node)
    bob_blue_addr = bob_blue_acct.addr
    print("[DEMO2] Bob blue account ready:")
    print("  addr    =", bob_blue_addr)
    print("  balance =", bob_blue_acct.balance)
    print("  color   =", bob_blue_acct.IDCard["Color"], " (1 means blue)")

    # 7. Alice -> Bob transfer 300
    print("\n========== STEP 3: Alice -> Bob, amount = 300 ==========")

    # Sync Alice blue account from node before building transfer (silent)
    alice_onchain_1 = run_silently(alice.fetch_account_from_node, node, alice_blue_addr)
    if alice_onchain_1 is not None:
        alice_onchain_1.ecc_keypair = alice_blue_acct.ecc_keypair
        alice.Dict_of_accts[alice_blue_addr] = alice_onchain_1

    run_regular_transfer(
        sender_client=alice,
        sender_label="Alice",
        receiver_label="Bob",
        from_addr=alice_blue_addr,
        to_addr=bob_blue_addr,
        amount=300,
        node=node,
    )

    # For the second transfer, Bob must see the updated on-chain state.
    # This fetch is only for correctness; logs are hidden.
    bob_after_1 = run_silently(bob.fetch_account_from_node, node, bob_blue_addr)
    if bob_after_1 is not None:
        bob_after_1.ecc_keypair = bob_blue_acct.ecc_keypair
        bob.Dict_of_accts[bob_blue_addr] = bob_after_1

    # 8. Bob -> Alice transfer 200 (spend part of what he just received)
    print("\n========== STEP 4: Bob -> Alice, amount = 200 ==========")

    run_regular_transfer(
        sender_client=bob,
        sender_label="Bob",
        receiver_label="Alice",
        from_addr=bob_blue_addr,
        to_addr=alice_blue_addr,
        amount=200,
        node=node,
    )

    # At the very end, fetch both accounts once and print final balances
    print("\n[DEMO2] Fetch final on-chain state for Alice and Bob...")

    alice_after_2 = run_silently(alice.fetch_account_from_node, node, alice_blue_addr)
    bob_after_2 = run_silently(bob.fetch_account_from_node, node, bob_blue_addr)

    if alice_after_2 is not None:
        alice_after_2.ecc_keypair = alice_blue_acct.ecc_keypair
        alice.Dict_of_accts[alice_blue_addr] = alice_after_2

    if bob_after_2 is not None:
        bob_after_2.ecc_keypair = bob_blue_acct.ecc_keypair
        bob.Dict_of_accts[bob_blue_addr] = bob_after_2

    if alice_after_2 is not None and bob_after_2 is not None:
        print("[DEMO2] Final balances after both transfers:")
        print("  Alice: balance =", alice_after_2.balance, ", nonce =", alice_after_2.nonce)
        print("  Bob  : balance =", bob_after_2.balance, ", nonce =", bob_after_2.nonce)
    else:
        print("[DEMO2][WARN] Could not fetch final on-chain state for both accounts.")

    print("\n[DEMO2] Demo finished.")
    print("[DEMO2] Blocks in this scenario (conceptually):")
    print("  - Alice BlueApply1")
    print("  - Bob   BlueApply1")
    print("  - Transfer Alice -> Bob")
    print("  - Transfer Bob   -> Alice")


if __name__ == "__main__":
    main()
