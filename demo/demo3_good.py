#!/usr/bin/env python3
# demo/demo3_good.py
#
# Demo 3 (GOOD):
#   Scenario: Alice moves funds from a blue account into the anonymous pool.
#   Steps:
#     1) Alice obtains a blue account via BlueApply1.
#     2) Alice deposits 400 units from that account into the anon commitment pool.
#
# This demo hides low-level Node/Client/zk logs and prints a compact story with
# a short explanation of the zk proof used in AcctToAnon.

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


def run_acct_to_anon(
    client: Client,
    owner_label: str,
    acct,
    amount: int,
    node: Node,
    explain_proof: bool = True,
    quiet: bool = False,
) -> dict:
    """
    Run an AcctToAnon deposit from a blue account into the anon pool.

    This helper can be used in two ways:
      - Demo mode (explain_proof=True, quiet=False): print the zk story.
      - API mode (explain_proof=False, quiet=True): no prints, just return data.

    Returns a dict:
      {
        "res":          node response dict,
        "updated_acct": Account or None,
        "anon_commit":  Hex32,
        "nonce":        int,
      }
    """
    addr = acct.addr
    client.Dict_of_accts[addr] = acct

    header_msg = (
        f"[DEMO3] AcctToAnon deposit for {owner_label}\n"
        f"[DEMO3]   from_addr = {short_hex(addr)}\n"
        f"[DEMO3]   amount    = {amount}\n"
    )
    if not quiet:
        print(header_msg)

    # Build the AcctToAnon envelope on the client side (internal logs hidden).
    envelope = run_silently(client.apply_for_acct2anon, acct, amount)
    payload = envelope["payload"]

    # ZK proof explanation as one block of text.
    if explain_proof and not quiet:
        proof_msg = (
            "[DEMO3] ZK proof for AcctToAnon (informal statement):\n"
            f"[DEMO3]   Account owner = {owner_label}\n"
            "[DEMO3]   Public inputs (all encoded as 32-byte field elements):\n"
            f"[DEMO3]     val         = {payload['amount']} (deposited amount)\n"
            f"[DEMO3]     nonce       = {payload['nonce']}\n"
            f"[DEMO3]     addr        = {short_hex(payload['from_addr'])}\n"
            f"[DEMO3]     anon_commit = {short_hex(payload['anon_commit'])}\n"
            "[DEMO3]   Secret witness:\n"
            "[DEMO3]     sk such that Poseidon(pk(sk)) = addr.\n"
            "[DEMO3]   The circuit checks:\n"
            "[DEMO3]     1) addr is derived from sk via ECC + Poseidon.\n"
            "[DEMO3]     2) anon_commit = Poseidon(val, sk, nonce, addr).\n"
            f"[DEMO3]   Proof bytes (truncated) = {short_hex(payload['zk_proof'])}\n"
            "[DEMO3]   This proof is produced by get_zkproof_for_acct_to_anon_tx(...).\n"
            "[DEMO3]   It is verified on-chain by verify_zkproof_for_acct_to_anon_tx(...).\n"
        )
        print(proof_msg)

    # Send to node (internal logs hidden).
    res = run_silently(node.deal_with_request, envelope)

    if "ok" in res and res["ok"] and "new_block" in res:
        new_block = res["new_block"]

        if not quiet:
            block_msg = (
                "[DEMO3][OK] AcctToAnon accepted by node. Block summary:\n"
                f"  [DEMO3] account_root = {short_hex(new_block['account_root'])}\n"
                f"  [DEMO3] commit_root  = {short_hex(new_block['commit_root'])}\n"
                f"  [DEMO3] anon_commit  = {short_hex(new_block['anon_commit'])}\n"
                f"  [DEMO3] from_addr    = {short_hex(new_block['from_addr'])}\n"
                f"  [DEMO3] amount       = {new_block['amount']}\n"
            )
            print(block_msg)
    else:
        if not quiet:
            error_msg = (
                "[DEMO3][ERROR] AcctToAnon rejected by node.\n"
                f"[DEMO3]   raw response = {res}\n"
            )
            print(error_msg)

    # Refresh local view of the account for the final balance.
    updated = run_silently(client.fetch_account_from_node, node, addr)
    if updated is not None:
        updated.ecc_keypair = acct.ecc_keypair
        client.Dict_of_accts[addr] = updated

        if not quiet:
            color_val = None
            if isinstance(updated.IDCard, dict) and "Color" in updated.IDCard:
                color_val = updated.IDCard["Color"]

            acct_msg = (
                "[DEMO3] On-chain account after AcctToAnon:\n"
                f"  [DEMO3] addr    = {addr}\n"
                f"  [DEMO3] balance = {updated.balance}\n"
                f"  [DEMO3] color   = {color_val}\n"
            )
            print(acct_msg)
    else:
        if not quiet:
            print("[DEMO3][WARN] Could not fetch on-chain account after AcctToAnon.")

    return {
        "res": res,
        "updated_acct": updated,
        "anon_commit": payload["anon_commit"],
        "nonce": payload["nonce"],
    }


def main() -> None:
    print("========== DEMO 3 (GOOD): BlueApply1 then AcctToAnon ==========\n")

    # Clear current_blockchain.txt so this demo starts from a clean view on disk.
    chain_path = os.path.join(PROJECT_ROOT, "current_blockchain.txt")
    f = open(chain_path, "w", encoding="utf-8")
    f.write("")
    f.close()
    print("[DEMO3] Cleared current_blockchain.txt\n")

    # 1. Initialize node (internal logs hidden).
    node = run_silently(Node)
    print("[DEMO3] Node initialized.")

    # 2. Create Alice client (internal logs hidden).
    print("\n[DEMO3] Creating Alice client...")
    alice = run_silently(Client, cert={})

    # 3. Set master seed from a demo password.
    print("[DEMO3] Setting master seed for Alice (from password)...")
    run_silently(alice.set_master_seed_from_password, "alice_password_demo3_good")
    print(f"[DEMO3]   Alice MASTER_SEED (short) = {short_hex(alice.MASTER_SEED.hex())}")

    # 4. Build a demo certificate so Alice can run BlueApply1.
    print("\n[DEMO3] Building demo certificate for Alice (used by BlueApply1)...")
    run_silently(build_demo_cert_for_client, alice)

    # 5. Alice runs BlueApply1: obtain a blue account with default balance on chain.
    print("\n========== STEP 1: Alice BlueApply1 ==========")
    alice_blue_acct = run_silently(run_blue_apply1_flow, alice, node)
    alice_blue_addr = alice_blue_acct.addr

    blue_msg = (
        "[DEMO3] Alice blue account ready:\n"
        f"  [DEMO3] addr    = {alice_blue_addr}\n"
        f"  [DEMO3] balance = {alice_blue_acct.balance}\n"
        f"  [DEMO3] color   = {alice_blue_acct.IDCard['Color']} (1 means blue)\n"
    )
    print(blue_msg)

    # 6. Alice moves part of that balance into the anonymous pool.
    concept_msg = (
        "[DEMO3] Conceptual view of AcctToAnon:\n"
        "[DEMO3]   - Input: a blue on-chain account with enough balance.\n"
        "[DEMO3]   - Output: the account balance decreases, and an anonymous\n"
        "[DEMO3]     commitment is added to the anon pool.\n"
        "[DEMO3]   - The commitment itself is not anonymous.\n"
        "[DEMO3]     It is just a fixed on-chain value that can be secretly spent,\n"
        "[DEMO3]     so it is important for building an anonymous payment later.\n"
        "[DEMO3]   - The zk proof links the account and the commitment without\n"
        "[DEMO3]     revealing the secret key or the full (val, nonce, addr) tuple.\n"
    )

    print("\n========== STEP 2: Alice AcctToAnon deposit = 400 ==========")
    print(concept_msg)

    # Demo mode: explain_proof=True, quiet=False
    run_acct_to_anon(
        client=alice,
        owner_label="Alice",
        acct=alice_blue_acct,
        amount=400,
        node=node,
        explain_proof=True,
        quiet=False,
    )

    summary_msg = (
        "[DEMO3] Demo finished.\n"
        "[DEMO3] Blocks in this scenario (conceptually):\n"
        "  [DEMO3] - Alice BlueApply1\n"
        "  [DEMO3] - Alice AcctToAnon deposit 400\n"
    )
    print(summary_msg)


if __name__ == "__main__":
    main()
