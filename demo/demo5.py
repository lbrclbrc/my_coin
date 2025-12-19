#!/usr/bin/env python3
# demo/demo5_trace_anon_for_sk.py
# Demo 5:
#   1) Run demo4_good_test silently to build blockchain + Alice MASTER_SEED.
#   2) Use MASTER_SEED to derive Alice's sk and trace all anonymous actions related to that sk.

import os
import sys

THIS_FILE = os.path.abspath(__file__)
THIS_DIR = os.path.dirname(THIS_FILE)
PROJECT_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from wrappers.poseidon_hash_wrapper import get_poseidon_hash
from acct import Account
from tools import short_hex, run_silently
from demo.demo4_good import demo4_good_test


def trace_blockchain_for_sk(blockchain, sk_bytes):
    print("\n========== DEMO 5: Trace for given SK ==========\n")

    # 1) Derive addr from sk (consistent with Account.fill_missing)
    tmp_acct = Account()
    tmp_acct.ecc_keypair.set_sk(sk_bytes)
    tmp_acct.fill_missing()
    addr = tmp_acct.addr

    print("[TRACE] Derived addr from sk =", short_hex(addr, 64))
    print("")

    # 2) Initialize trace structures
    regular_out = []       # Normal transfers: from == addr
    regular_in = []        # Normal transfers: to == addr
    acct2anon_notes = []   # Notes created by AcctToAnon from this address
    change_notes = []      # Change notes created by this sk (debug use)
    owned_commitments = [] # All commitments currently known to belong to this sk
    nullifier_to_note = {} # Expected nullifier -> note mapping
    anonpay_out = []       # AnonPayTx where this sk is the spender
    anonpay_in = []        # AnonPayTx where this addr is the receiver

    # 3) Scan blocks sequentially
    for height, blk in enumerate(blockchain.lst_of_blocks):
        lst_of_txs = blk.lst_of_txs
        if not lst_of_txs:
            continue

        print("[TRACE] --- scanning block %d (tx_count = %d) ---" % (height, len(lst_of_txs)))
        block_has_anonpay_out = False

        for tx_index, tx in enumerate(lst_of_txs):
            if not isinstance(tx, dict):
                continue

            tx_type = tx["tx_type"]
            payload = tx["payload"]

            # ---------- Normal transfers ----------
            if tx_type == "AcctToAcct":
                from_addr = payload["from_addr"]
                to_addr = payload["to_addr"]
                amount = int(payload["amount"])

                if from_addr == addr:
                    regular_out.append({
                        "block_height": height,
                        "tx_index": tx_index,
                        "from_addr": from_addr,
                        "to_addr": to_addr,
                        "amount": amount,
                    })
                if to_addr == addr:
                    regular_in.append({
                        "block_height": height,
                        "tx_index": tx_index,
                        "from_addr": from_addr,
                        "to_addr": to_addr,
                        "amount": amount,
                    })

            # ---------- AcctToAnon: account layer -> anonymous pool ----------
            if tx_type == "AcctToAnon":
                from_addr = payload["from_addr"]
                amount = int(payload["amount"])
                anon_commit = payload["anon_commit"]
                nonce_int = int(payload["nonce"])

                if from_addr == addr:
                    note = {
                        "commit": anon_commit,
                        "value": amount,
                        "nonce": nonce_int,
                        "src_addr": from_addr,
                        "origin": "AcctToAnon",
                        "created_block": height,
                        "created_tx_index": tx_index,
                        "spent": False,
                    }
                    acct2anon_notes.append(note)
                    owned_commitments.append({
                        "commit": anon_commit,
                        "value": amount,
                        "origin": "AcctToAnon",
                        "created_block": height,
                        "created_tx_index": tx_index,
                    })

                    nonce_bytes = nonce_int.to_bytes(32, "big")
                    src_bytes = bytes.fromhex(from_addr)
                    nullifier_hex = get_poseidon_hash(sk_bytes, nonce_bytes, src_bytes)
                    nullifier_to_note[nullifier_hex] = note

            # ---------- AnonPayTx: anonymous note -> public addr ----------
            if tx_type == "AnonPay" or tx_type == "AnonPayTx":
                to_addr = payload["to_addr"]
                amount = int(payload["amount"])
                nullifier = payload["nullifier"]
                commit_change = payload["commit_change"]

                # (1) This addr is receiver
                if to_addr == addr:
                    anonpay_in.append({
                        "block_height": height,
                        "tx_index": tx_index,
                        "amount": amount,
                        "from_nullifier": nullifier,
                        "commit_change": commit_change,
                    })

                # (2) Check if nullifier matches our expected nullifiers
                if nullifier in nullifier_to_note:
                    block_has_anonpay_out = True

                    note = nullifier_to_note[nullifier]
                    value_initial = int(note["value"])
                    value_change = value_initial - amount

                    note["spent"] = True

                    anonpay_out.append({
                        "note_commit": note["commit"],
                        "note_value": value_initial,
                        "spend_block_height": height,
                        "spend_tx_index": tx_index,
                        "spend_amount": amount,
                        "to_addr": to_addr,
                        "nullifier": nullifier,
                        "commit_change": commit_change,
                        "change_value": value_change,
                    })

                    owned_commitments.append({
                        "commit": commit_change,
                        "value": value_change,
                        "origin": "change_from_" + note["commit"],
                        "created_block": height,
                        "created_tx_index": tx_index,
                    })

                    change_note = {
                        "commit": commit_change,
                        "value": value_change,
                        "origin": "change_from_" + note["commit"],
                        "created_block": height,
                        "created_tx_index": tx_index,
                        "spent": False,
                    }
                    change_notes.append(change_note)

                    change_nonce_bytes = (0).to_bytes(32, "big")
                    change_src_bytes = bytes.fromhex(nullifier)
                    next_nullifier_hex = get_poseidon_hash(
                        sk_bytes,
                        change_nonce_bytes,
                        change_src_bytes,
                    )
                    nullifier_to_note[next_nullifier_hex] = change_note

        if block_has_anonpay_out:
            flag = "YES"
        else:
            flag = "NO"
        print("[TRACE]     has_anonpay_from_this_sk =", flag)
        print("")

    # 4) Print final trace result
    print("========== Trace Result ==========\n")
    print("[TRACE] SK  (hex, short) =", short_hex(sk_bytes.hex(), 64))
    print("[TRACE] Addr             =", addr)
    print("")

    print("---- Regular transfers FROM this addr ----")
    if len(regular_out) == 0:
        print("  (none)")
    else:
        for it in regular_out:
            print(
                "  Block %d, Tx %d: %s -> %s, amount = %d"
                % (
                    it["block_height"],
                    it["tx_index"],
                    short_hex(it["from_addr"], 24),
                    short_hex(it["to_addr"], 24),
                    it["amount"],
                )
            )
    print("")

    print("---- Regular transfers TO this addr ----")
    if len(regular_in) == 0:
        print("  (none)")
    else:
        for it in regular_in:
            print(
                "  Block %d, Tx %d: %s -> %s, amount = %d"
                % (
                    it["block_height"],
                    it["tx_index"],
                    short_hex(it["from_addr"], 24),
                    short_hex(it["to_addr"], 24),
                    it["amount"],
                )
            )
    print("")

    print("---- AcctToAnon (deposits from this addr into anon pool) ----")
    if len(acct2anon_notes) == 0:
        print("  (none)")
    else:
        for idx, note in enumerate(acct2anon_notes):
            if idx > 0:
                print("")
            spent_flag = "spent" if note["spent"] else "unspent"
            print(
                "  Block %d, Tx %d: addr %s -> commit %s, amount = %d, nonce = %d (%s)"
                % (
                    note["created_block"],
                    note["created_tx_index"],
                    short_hex(note["src_addr"], 24),
                    short_hex(note["commit"], 24),
                    note["value"],
                    note["nonce"],
                    spent_flag,
                )
            )
    print("")

    print("---- AnonPayTx where this SK is the spender ----")
    if len(anonpay_out) == 0:
        print("  (none)")
    else:
        for idx, sp in enumerate(anonpay_out):
            if idx > 0:
                print("")
            print(
                "  Block %d, Tx %d: note %s (value = %d) spent via nullifier %s"
                % (
                    sp["spend_block_height"],
                    sp["spend_tx_index"],
                    short_hex(sp["note_commit"], 24),
                    sp["note_value"],
                    short_hex(sp["nullifier"], 24),
                )
            )
            print(
                "    pay %d -> addr %s, change_value = %d, commit_change = %s"
                % (
                    sp["spend_amount"],
                    short_hex(sp["to_addr"], 24),
                    sp["change_value"],
                    short_hex(sp["commit_change"], 24),
                )
            )
    print("")

    print("---- AnonPayTx where this addr is the receiver ----")
    if len(anonpay_in) == 0:
        print("  (none)")
    else:
        for idx, it in enumerate(anonpay_in):
            if idx > 0:
                print("")
            print(
                "  Block %d, Tx %d: receive amount = %d, from nullifier = %s, commit_change = %s"
                % (
                    it["block_height"],
                    it["tx_index"],
                    it["amount"],
                    short_hex(it["from_nullifier"], 24),
                    short_hex(it["commit_change"], 24),
                )
            )
    print("")

    print("---- Commitments currently known to belong to this SK ----")
    if len(owned_commitments) == 0:
        print("  (none)")
    else:
        for idx, c in enumerate(owned_commitments):
            if idx > 0:
                print("")
            print(
                "  Block %d, Tx %d: commit = %s, value = %d, origin = %s"
                % (
                    c["created_block"],
                    c["created_tx_index"],
                    short_hex(c["commit"], 24),
                    c["value"],
                    c["origin"],
                )
            )

    print("\n========== End of Trace ==========\n")


def main():
    print("========== DEMO 5: Prepare and trace ==========\n")
    print("[DEMO5] This demo will run demo4_good_test silently to build a chain.")
    print("[DEMO5] This step may take time depending on CPU.")
    print("[DEMO5] Seeing no output for a while is normal; the logic is deterministic.\n")

    # Run demo4 silently to generate a chain with anonymous operations
    blockchain, alice_master_seed = run_silently(demo4_good_test)

    print("\n[DEMO5] demo4_good_test finished. Start tracing for Alice's SK...\n")

    # Derive Alice's sk:
    #   sk = Poseidon(MASTER_SEED, 0)
    sk_bytes = bytes.fromhex(
        get_poseidon_hash(
            alice_master_seed,
            (0).to_bytes(32, "big"),
        )
    )

    # Perform full trace on this chain
    trace_blockchain_for_sk(blockchain, sk_bytes)


if __name__ == "__main__":
    main()
