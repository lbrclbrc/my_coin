#!/usr/bin/env python3
# demo/demo1_good.py
#
# Demo 1 (GOOD): BlueApply1 + BlueApply2
#
# Overview:
#   This demo shows how a client (Alice) talks to the node to obtain
#   a *blue* account in two steps:
#     1) BlueApply1: register the first blue account derived from
#        Alice's master seed with token = 0.
#     2) BlueApply2: derive a second blue account from the same
#        master seed (with another token) and register it on chain.
#
#   Along the way also show how the client:
#     - derives accounts from MASTER_SEED instead of using ad-hoc keys,
#     - asks the node for GetAccountInfo before sending applications,
#     - updates its local wallet view only via the public API
#       (Node.deal_with_request + fetch_account_from_node),
#     - prints the final on-chain state of both blue accounts.
#
#   You can run this file directly to see an end-to-end story for
#   "blue account enrollment" without needing to know the internal
#   details of Node or Client.

import os
import sys

# Add project root to sys.path
THIS_FILE = os.path.abspath(__file__)
THIS_DIR = os.path.dirname(THIS_FILE)
PROJECT_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Project imports
from client.core import Client, CA_SK_HEX
from node.core import Node
from wrappers.pasta_ecc_wrapper import EccKeypair
from acct import Account


# ---------------------------------------------------
# Helper: build a demo certificate for the client
# ---------------------------------------------------
def build_demo_cert_for_client(client: Client) -> None:
    """
    Build a simple demo certificate for the client using a fixed CA secret key.
    The Node will later verify this cert when processing BlueApply1.
    """
    ca_kp = EccKeypair()
    ca_sk_bytes = bytes.fromhex(CA_SK_HEX)
    ca_kp.set_sk(ca_sk_bytes)

    user_pk_hex = client.get_user_pk_hex()
    user_id = "01"

    ca_msg = (user_pk_hex + user_id).encode()
    r, s, raw_sig = ca_kp.sign(ca_msg)
    cert_sig_hex = raw_sig.hex()

    client.CERT = {
        "pk": user_pk_hex,
        "id": user_id,
        "signature": cert_sig_hex,
        "clerk_id": "DemoClerk01",
    }


# ---------------------------------------------------
# Helper: derive a Type-1 (token=0) blue account from master seed
# ---------------------------------------------------
def create_local_account_for_blueapply1_from_masterseed(client: Client) -> Account:
    """
    Derive a new public key from client.MASTER_SEED with token = 0 and build
    a local Account object.

    The returned Account:
      - has ecc_keypair.pk set to the derived pk (hex),
      - has addr filled via acct.fill_missing(),
      - is NOT inserted into client.Dict_of_accts yet.
    """
    if not client.has_master_seed():
        raise ValueError("Client has no MASTER_SEED; call set_master_seed_from_password first")

    token_bytes = (0).to_bytes(32, "big")
    new_pk_bytes = client._derive_new_pk_from_master_and_token(client.MASTER_SEED, token_bytes)
    new_pk_hex = new_pk_bytes.hex()

    acct = Account()
    acct.ecc_keypair.pk = new_pk_hex
    acct.fill_missing()  # fills addr and other defaults

    return acct


# ---------------------------------------------------
# Helper: sync one account entry with Node via GetAccountInfo
# ---------------------------------------------------
def sync_account_from_node(client: Client, node: Node, addr: str, local_acct: Account) -> Account:
    """
    Use Node's GetAccountInfo to sync a local Account.

    Behavior:
      - Send {"application_type": "GetAccountInfo", "payload": {"addr": addr}} to Node.
      - If Node says ok=True and found=True:
          * Use client.fetch_account_from_node(node, addr) (with Merkle checks).
          * If fetch succeeds (not None), replace local_acct with that on-chain account.
          * If fetch fails (None), treat as "not on chain".
      - In all "not on chain" cases:
          * If local_acct is None, create a new Account and set addr.
          * Call initialize_to_blockchain_default() on local_acct.
      - Finally, store local_acct into client.Dict_of_accts[addr] and return it.
    """
    get_req = {
        "application_type": "GetAccountInfo",
        "payload": {"addr": addr},
    }
    raw_resp = node.deal_with_request(get_req)

    onchain_acct = None

    if isinstance(raw_resp, dict):
        if "ok" in raw_resp and raw_resp["ok"]:
            if "found" in raw_resp and raw_resp["found"]:
                onchain_acct = client.fetch_account_from_node(node, addr)

    if onchain_acct is not None:
        acct = onchain_acct
    else:
        if local_acct is None:
            acct = Account()
            acct.addr = addr
        else:
            acct = local_acct
        acct.initialize_to_blockchain_default()

    client.Dict_of_accts[addr] = acct
    return acct


# ---------------------------------------------------
# Step 1: BlueApply1 flow
# ---------------------------------------------------
def run_blue_apply1_flow(alice: Client, node: Node) -> Account:
    print("========== STEP 1: BlueApply1 (first blue account) ==========")

    # 1) Derive a Type-1 account (token = 0) locally from master seed.
    acct = create_local_account_for_blueapply1_from_masterseed(alice)
    print("[STEP 1] Local Type-1 account derived from master seed; addr =", acct.addr)

    # 2) Sync this account with Node: either load on-chain state or init defaults.
    acct = sync_account_from_node(alice, node, acct.addr, acct)
    print("[STEP 1] After sync with Node: balance =", acct.balance,
          ", nonce =", acct.nonce,
          ", color =", acct.IDCard["Color"])

    # 3) Build BlueApply1 envelope and send to Node.
    print("[STEP 1] Building BlueApply1 envelope and sending to Node.deal_with_request...")
    envelope1 = alice.apply_for_blue_i(acct)
    result1 = node.deal_with_request(envelope1)

    if not isinstance(result1, dict) or "ok" not in result1 or not result1["ok"]:
        print("[STEP 1][ERROR] BlueApply1 failed; result =", result1)
        raise SystemExit(1)

    new_block_info = result1["new_block"]
    applied_addr = new_block_info["applied_addr"]
    print("[STEP 1][OK] BlueApply1 accepted by Node; applied_addr =", applied_addr)

    # 4) Fetch the on-chain account after BlueApply1.
    fetched_acct = alice.fetch_account_from_node(node, applied_addr)
    if fetched_acct is None:
        print("[STEP 1][ERROR] fetch_account_from_node returned None after BlueApply1.")
        raise SystemExit(1)

    alice.Dict_of_accts[applied_addr] = fetched_acct

    print("[STEP 1] On-chain account after BlueApply1: addr =", fetched_acct.addr,
          ", balance =", fetched_acct.balance,
          ", color =", fetched_acct.IDCard["Color"],
          ", ID =", fetched_acct.IDCard["ID"],
          ", nonce =", fetched_acct.nonce)

    return fetched_acct


# ---------------------------------------------------
# Step 2: BlueApply2 flow
# ---------------------------------------------------
def run_blue_apply2_flow(alice: Client, node: Node, base_acct: Account) -> None:
    print("\n========== STEP 2: BlueApply2 (non-first blue account) ==========")

    # 1) Choose a token and derive new pk / addr from the same master seed.
    blue2_token_int = 123456789
    print("[STEP 2] Using int token for BlueApply2:", blue2_token_int)

    token_bytes = blue2_token_int.to_bytes(32, "big")
    new_pk_bytes = alice._derive_new_pk_from_master_and_token(alice.MASTER_SEED, token_bytes)
    new_pk_hex = new_pk_bytes.hex()

    tmp_acct = Account()
    tmp_acct.ecc_keypair.pk = new_pk_hex
    tmp_acct.fill_missing()
    derived_addr = tmp_acct.addr

    print("[STEP 2] Derived new blue account addr for BlueApply2 =", derived_addr)

    # 2) Sync this derived addr with Node (it is normally "not on chain" yet).
    synced_acct = sync_account_from_node(alice, node, derived_addr, None)
    print("[STEP 2] After sync with Node: balance =", synced_acct.balance,
          ", nonce =", synced_acct.nonce,
          ", color =", synced_acct.IDCard["Color"])

    # 3) Build BlueApply2 envelope and send to Node.
    print("[STEP 2] Building BlueApply2 envelope and sending to Node.deal_with_request...")
    envelope2 = alice.apply_for_blue_ii(base_acct, blue2_token_int)
    result2 = node.deal_with_request(envelope2)

    if not isinstance(result2, dict) or "ok" not in result2 or not result2["ok"]:
        print("[STEP 2][ERROR] BlueApply2 failed; result =", result2)
        raise SystemExit(1)

    new_block_info_2 = result2["new_block"]
    applied_addr_2 = new_block_info_2["applied_addr"]
    print("[STEP 2][OK] BlueApply2 accepted by Node; applied_addr =", applied_addr_2)

    # 4) Fetch the on-chain account after BlueApply2.
    fetched_acct2 = alice.fetch_account_from_node(node, applied_addr_2)
    if fetched_acct2 is None:
        print("[STEP 2][ERROR] fetch_account_from_node returned None after BlueApply2.")
        raise SystemExit(1)

    alice.Dict_of_accts[applied_addr_2] = fetched_acct2

    print("[STEP 2] On-chain account after BlueApply2: addr =", fetched_acct2.addr,
          ", balance =", fetched_acct2.balance,
          ", color =", fetched_acct2.IDCard["Color"],
          ", ID =", fetched_acct2.IDCard["ID"],
          ", nonce =", fetched_acct2.nonce)


# ---------------------------------------------------
# Main
# ---------------------------------------------------
def demo_blue_apply_for_alice() -> None:
    print("========== DEMO 1 (GOOD): BlueApply1 + BlueApply2 ==========\n")

    # 1) Initialize Client and Node.
    alice = Client(cert={})
    node = Node()

    # 2) Set master seed for Alice from a password.
    alice.set_master_seed_from_password("alice_password_demo")

    # 3) Build a demo cert for Alice so Node can verify her BlueApply1.
    build_demo_cert_for_client(alice)

    # 4) Run BlueApply1 (first blue account for Alice).
    alice_first_blue_acct = run_blue_apply1_flow(alice, node)

    # 5) Run BlueApply2 (derive another blue account from the same master seed).
    run_blue_apply2_flow(alice, node, alice_first_blue_acct)

    # 6) Show final blockchain state from Node.
    print("\n========== FINAL BLOCKCHAIN STATE (from Node) ==========")
    print(node.blockchain)


if __name__ == "__main__":
    demo_blue_apply_for_alice()
