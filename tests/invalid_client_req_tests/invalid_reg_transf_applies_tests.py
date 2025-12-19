#!/usr/bin/env python3
# This test file exercises malicious regular Transfer requests:
#   - Scenario 1: overspending (balance=500, tries to send 700).
#   - Scenario 2: tampered Transfer signature.
#
# Internal logs from Client / Node / Rust are hidden via run_silently.
# Only short, human-readable summaries are printed here.

import os
import sys

# Add project root to sys.path
THIS_FILE = os.path.abspath(__file__)
THIS_DIR = os.path.dirname(THIS_FILE)
PROJECT_ROOT = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from client.core import Client
from node.core import Node
from tools import run_silently, short_hex
from demo.demo1_good import build_demo_cert_for_client, run_blue_apply1_flow


def _build_blue_client(label: str, password: str, node: Node) -> Client:
    """
    Create a Client, set its master seed, build a demo cert,
    run BlueApply1, and return the client with a blue account in Dict_of_accts.
    """
    print(f"[REG-TEST] Creating client for {label}...")
    client = run_silently(Client, cert={})

    run_silently(client.set_master_seed_from_password, password)
    run_silently(build_demo_cert_for_client, client)

    blue_acct = run_silently(run_blue_apply1_flow, client, node)
    client.Dict_of_accts[blue_acct.addr] = blue_acct

    print(f"[REG-TEST] {label} blue account:")
    print(f"  addr    = {blue_acct.addr}")
    print(f"  balance = {blue_acct.balance}")
    print(f"  color   = {blue_acct.IDCard['Color']} (1 means blue)")
    return client


def _find_sig_key(payload: dict) -> str:
    """
    Return the first key in payload whose name contains 'sig'
    and whose value looks like a non-empty string.
    This is used to tamper a Transfer signature without relying
    on a hard-coded field name.
    """
    for name in payload:
        value = payload[name]
        if "sig" in name and isinstance(value, str) and len(value) > 1:
            return name
    return None


def scenario_overspend() -> None:
    """
    Scenario 1:
      - Alice and Bob both run BlueApply1 and get 500 each.
      - Alice then tries to send 700 to Bob from her blue account.
      - The node is expected to reject this overspending transfer.
    """
    print("\n=== Scenario 1: overspending regular Transfer ===")

    node = run_silently(Node)

    alice = _build_blue_client("Alice", "alice_password_regtest_overspend", node)
    bob = _build_blue_client("Bob", "bob_password_regtest_overspend", node)

    alice_acct = None
    for addr in alice.Dict_of_accts:
        alice_acct = alice.Dict_of_accts[addr]
        break

    bob_acct = None
    for addr in bob.Dict_of_accts:
        bob_acct = bob.Dict_of_accts[addr]
        break

    assert alice_acct is not None, "Alice must have a blue account"
    assert bob_acct is not None, "Bob must have a blue account"

    from_addr = alice_acct.addr
    to_addr = bob_acct.addr

    base_balance = alice_acct.balance
    overspend_amount = base_balance + 200

    print("[REG-TEST] Overspend setup:")
    print(f"  Alice balance before transfer = {base_balance}")
    print(f"  Alice tries to send           = {overspend_amount}")
    print(f"  from_addr = {short_hex(from_addr)}")
    print(f"  to_addr   = {short_hex(to_addr)}")

    # Build a Transfer request on Alice's side (internal logs are hidden).
    tx = run_silently(alice.build_transfer_request, from_addr, to_addr, overspend_amount)

    envelope = {
        "application_type": "Transfer",
        "payload": tx["payload"],
    }

    print("[REG-TEST] Sending overspend Transfer envelope to node (silent Node logs)...")
    res = run_silently(node.deal_with_request, envelope)

    print("[REG-TEST] Node response for overspend Transfer:")
    print(f"  {res}")
    if isinstance(res, dict) and "ok" in res and not res["ok"]:
        print("[REG-TEST][OK] Overspend Transfer was rejected as expected.")
    else:
        print("[REG-TEST][WARN] Overspend Transfer was not rejected as expected.")


def scenario_tampered_signature() -> None:
    """
    Scenario 2:
      - Alice and Bob both run BlueApply1 and get 500 each.
      - Alice builds a valid Transfer (amount within balance).
      - The test makes a copy of the payload, finds one signature-like field,
        and flips the last hex character in that field.
      - The node is expected to reject this tampered Transfer.
    """
    print("\n=== Scenario 2: tampered Transfer signature ===")

    node = run_silently(Node)

    alice = _build_blue_client("Alice", "alice_password_regtest_sig", node)
    bob = _build_blue_client("Bob", "bob_password_regtest_sig", node)

    alice_acct = None
    for addr in alice.Dict_of_accts:
        alice_acct = alice.Dict_of_accts[addr]
        break

    bob_acct = None
    for addr in bob.Dict_of_accts:
        bob_acct = bob.Dict_of_accts[addr]
        break

    assert alice_acct is not None, "Alice must have a blue account"
    assert bob_acct is not None, "Bob must have a blue account"

    from_addr = alice_acct.addr
    to_addr = bob_acct.addr

    # Use a safe amount strictly less than Alice's balance so the transfer itself is valid.
    amount = min(200, alice_acct.balance)
    print("[REG-TEST] Tampered-signature setup:")
    print(f"  Alice balance before transfer = {alice_acct.balance}")
    print(f"  Alice sends                   = {amount}")
    print(f"  from_addr = {short_hex(from_addr)}")
    print(f"  to_addr   = {short_hex(to_addr)}")

    tx = run_silently(alice.build_transfer_request, from_addr, to_addr, amount)
    good_payload = tx["payload"]

    # Make a shallow copy so we can tamper the payload without changing the original.
    bad_payload = dict(good_payload)

    sig_key = _find_sig_key(bad_payload)
    assert sig_key is not None, "Could not find any signature-like field in Transfer payload"

    original_sig = bad_payload[sig_key]
    last_char = original_sig[-1]
    if last_char != "0":
        new_last_char = "0"
    else:
        new_last_char = "1"
    tampered_sig = original_sig[:-1] + new_last_char
    bad_payload[sig_key] = tampered_sig

    print("[REG-TEST] Tampering signature field in payload:")
    print(f"  sig field name = {sig_key}")
    print(f"  original sig   = {original_sig[:32]}...")
    print(f"  tampered sig   = {tampered_sig[:32]}...")

    bad_envelope = {
        "application_type": "Transfer",
        "payload": bad_payload,
    }

    print("[REG-TEST] Sending tampered-signature Transfer envelope to node (silent Node logs)...")
    res = run_silently(node.deal_with_request, bad_envelope)

    print("[REG-TEST] Node response for tampered-signature Transfer:")
    print(f"  {res}")
    if isinstance(res, dict) and "ok" in res and not res["ok"]:
        print("[REG-TEST][OK] Tampered-signature Transfer was rejected as expected.")
    else:
        print("[REG-TEST][WARN] Tampered-signature Transfer was not rejected as expected.")


def main() -> None:
    """
    Run all malicious regular Transfer tests:
      - overspending
      - tampered signature
    """
    print("========== Regular Transfer request stress tests (malicious cases) ==========")
    scenario_overspend()
    scenario_tampered_signature()
    print("\n[REG-TEST] All scenarios finished.")


if __name__ == "__main__":
    main()
