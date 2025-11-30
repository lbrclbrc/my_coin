#!/usr/bin/env python3
# tests/invalid_blue_applies_tests.py
#
# BlueApply1 / BlueApply2 negative-path tests.
#
# Goals:
#   - Scenario 1: call BlueApply2 before any BlueApply1 has been accepted.
#   - Scenario 2: tamper the public token of BlueApply2 without recomputing zk_proof.
#   - Scenario 3: tamper clerk_id in BlueApply1 so that the clerk is not recognized.
#   - Scenario 4: tamper clerk_envelope_sig in BlueApply1 to simulate a bad clerk signature.

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
from tools import short_hex
from demo.demo1_good import (
    build_demo_cert_for_client,
    create_local_account_for_blueapply1_from_masterseed,
    sync_account_from_node,
    run_blue_apply1_flow,
)


def _flip_last_hex_char(h: str) -> str:
    """
    Return a new hex string with the last hex digit changed,
    keeping the same length and still valid hex.
    """
    s = str(h)
    if not s:
        return s
    last = s[-1].lower()
    # simple toggle between '0' and '1', or rotate among a few digits
    if last != "0":
        new_last = "0"
    else:
        new_last = "1"
    return s[:-1] + new_last


def test_blueapply2_without_blueapply1() -> None:
    """
    Scenario 1:
      - Client never runs BlueApply1.
      - It derives a Type-1-style account from MASTER_SEED (token = 0),
        which is still color = 0 on chain.
      - It then calls BlueApply2 using this non-blue base account.
        The node must reject this request.
    """
    print("=== Scenario 1: BlueApply2 without any BlueApply1 ===")

    alice = Client(cert={})
    node = Node()

    alice.set_master_seed_from_password("test_blueapply2_s1")
    build_demo_cert_for_client(alice)

    # Derive a local Type-1-style account (token = 0) from the master seed.
    local_acct = create_local_account_for_blueapply1_from_masterseed(alice)

    # Sync this account with the node; it should not be blue yet.
    synced_acct = sync_account_from_node(alice, node, local_acct.addr, local_acct)

    print(
        f"  on-chain before BlueApply1: addr={short_hex(synced_acct.addr, 40)} "
        f"color={synced_acct.IDCard['Color']} ID={synced_acct.IDCard['ID']} "
        f"nonce={synced_acct.nonce} balance={synced_acct.balance}"
    )

    # Call BlueApply2 anyway, using this non-blue account as base.
    token_int = 123456789
    print(f"  sending BlueApply2 with token={token_int} from a non-blue base account")

    envelope2 = alice.apply_for_blue_ii(synced_acct, token_int)
    result = node.deal_with_request(envelope2)

    print(f"  node response: {result}")

    # The node must reject: ok == False.
    assert isinstance(result, dict)
    assert "ok" in result
    assert result["ok"] is False

    print("  [OK] Scenario 1: BlueApply2 was rejected as expected.\n")


def test_blueapply2_with_inconsistent_token() -> None:
    """
    Scenario 2:
      - Run a normal BlueApply1 so that the node registers master_seed_hash
        and the first blue account.
      - Build a valid BlueApply2 envelope with token = x via apply_for_blue_ii.
      - Before sending, tamper payload['token'] to some y != x without
        recomputing zk_proof.
      - The node must reject this forged BlueApply2.
    """
    print("=== Scenario 2: BlueApply2 with inconsistent token ===")

    alice = Client(cert={})
    node = Node()

    alice.set_master_seed_from_password("test_blueapply2_s2")
    build_demo_cert_for_client(alice)

    # Run a normal BlueApply1 and get the first blue account.
    base_acct = run_blue_apply1_flow(alice, node)

    # Build a valid BlueApply2 envelope first.
    good_token_int = 123456789
    print(f"  building a valid BlueApply2 envelope with token={good_token_int}")
    good_envelope = alice.apply_for_blue_ii(base_acct, good_token_int)
    good_payload = good_envelope["payload"]

    original_token_hex = good_payload["token"]
    print(f"  original token (hex, short) = {short_hex(original_token_hex)}")
    print(f"  new_blue_pk (hex, short)    = {short_hex(good_payload['new_blue_pk'])}")

    # Forge a new payload: only change token, keep zk_proof untouched.
    bad_payload = dict(good_payload)
    forged_token_hex = "00" * 31 + "02"   # small field element, different from original
    bad_payload["token"] = forged_token_hex

    print(f"  forged token (hex, short)   = {short_hex(forged_token_hex)}")

    bad_envelope = {
        "application_type": good_envelope["application_type"],
        "payload": bad_payload,
    }

    # Send the tampered envelope.
    print("  sending tampered BlueApply2 envelope to node")
    result = node.deal_with_request(bad_envelope)

    print(f"  node response: {result}")

    # The node must reject: ok == False (likely with err = 'bad zk proof').
    assert isinstance(result, dict)
    assert "ok" in result
    assert result["ok"] is False

    print("  [OK] Scenario 2: forged BlueApply2 was rejected as expected.\n")


def test_blueapply1_with_unknown_clerk_id() -> None:
    """
    Scenario 3:
      - Run a normal client setup and build a BlueApply1 envelope.
      - Tamper payload['clerk_id'] so that the clerk is not recognized.
      - Keep all signatures unchanged (so they no longer match the payload).
      - The node must reject this BlueApply1.
    """
    print("=== Scenario 3: BlueApply1 with unknown clerk_id ===")

    alice = Client(cert={})
    node = Node()

    alice.set_master_seed_from_password("test_blueapply1_s3")
    build_demo_cert_for_client(alice)

    # Derive a Type-1-style account and sync with the node.
    local_acct = create_local_account_for_blueapply1_from_masterseed(alice)
    synced_acct = sync_account_from_node(alice, node, local_acct.addr, local_acct)

    # Build a valid BlueApply1 envelope first.
    print("  building a valid BlueApply1 envelope")
    good_envelope = alice.apply_for_blue_i(synced_acct)
    good_payload = good_envelope["payload"]

    print(f"  original clerk_id = {good_payload['clerk_id']}")

    # Forge a payload: replace clerk_id with an unknown one.
    bad_payload = dict(good_payload)
    bad_payload["clerk_id"] = "UnknownClerk"

    print(f"  forged clerk_id   = {bad_payload['clerk_id']}")

    bad_envelope = {
        "application_type": good_envelope["application_type"],
        "payload": bad_payload,
    }

    print("  sending BlueApply1 with unknown clerk_id to node")
    result = node.deal_with_request(bad_envelope)

    print(f"  node response: {result}")

    assert isinstance(result, dict)
    assert "ok" in result
    assert result["ok"] is False

    print("  [OK] Scenario 3: BlueApply1 with unknown clerk_id was rejected as expected.\n")


def test_blueapply1_with_bad_clerk_signature() -> None:
    """
    Scenario 4:
      - Run a normal client setup and build a BlueApply1 envelope.
      - Tamper payload['clerk_envelope_sig'] a little bit, keeping hex length.
      - The node should see a bad clerk signature and reject the request.
    """
    print("=== Scenario 4: BlueApply1 with bad clerk signature ===")

    alice = Client(cert={})
    node = Node()

    alice.set_master_seed_from_password("test_blueapply1_s4")
    build_demo_cert_for_client(alice)

    local_acct = create_local_account_for_blueapply1_from_masterseed(alice)
    synced_acct = sync_account_from_node(alice, node, local_acct.addr, local_acct)

    print("  building a valid BlueApply1 envelope")
    good_envelope = alice.apply_for_blue_i(synced_acct)
    good_payload = good_envelope["payload"]

    original_sig = good_payload["clerk_envelope_sig"]
    print(f"  original clerk_envelope_sig (short) = {short_hex(original_sig)}")

    # Forge the clerk signature by flipping the last hex digit.
    bad_payload = dict(good_payload)
    bad_payload["clerk_envelope_sig"] = _flip_last_hex_char(original_sig)

    print(f"  forged clerk_envelope_sig (short)   = {short_hex(bad_payload['clerk_envelope_sig'])}")

    bad_envelope = {
        "application_type": good_envelope["application_type"],
        "payload": bad_payload,
    }

    print("  sending BlueApply1 with bad clerk signature to node")
    result = node.deal_with_request(bad_envelope)

    print(f"  node response: {result}")

    assert isinstance(result, dict)
    assert "ok" in result
    assert result["ok"] is False

    print("  [OK] Scenario 4: BlueApply1 with bad clerk signature was rejected as expected.\n")


def main() -> None:
    """
    Convenience entry point so this file can be run directly from CLI.
    """
    test_blueapply2_without_blueapply1()
    test_blueapply2_with_inconsistent_token()
    test_blueapply1_with_unknown_clerk_id()
    test_blueapply1_with_bad_clerk_signature()
    print("=== all BlueApply BAD-path tests finished ===")


if __name__ == "__main__":
    main()
