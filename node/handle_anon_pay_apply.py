# node/handle_anon_pay_apply.py
# Handle Anonymous Pay requests (AnonPay).
#
# Request payload:
#   {
#     "version":       1,
#     "to_addr":       Hex32,
#     "amount":        int,
#     "nullifier":     Hex32,
#     "commit_change": Hex32,
#     "zk_proof":      ZKProofHex
#   }

from wrappers.zkproof_for_anon_pay_wrapper import verify_zkproof_for_anon_pay
from tools import turn_hex_str_to_bytes, PALLAS_P
from acct import Account


def _make_bad_response(msg):
    return {"ok": False, "err": msg}


def _make_ok_response(new_block=None):
    if new_block is None:
        return {"ok": True}
    return {"ok": True, "new_block": new_block}


# Upper bound for FieldIntNonNeg (must match protocol spec)
_MAX_FIELD_INT = (1 << 96) - 1


def handle_anon_pay(node, payload):
    # ---------- Required fields ----------
    required_fields = ["version", "to_addr", "amount", "nullifier", "commit_change", "zk_proof"]
    i = 0
    while i < len(required_fields):
        f = required_fields[i]
        if f not in payload:
            return _make_bad_response("missing field in AnonPay payload: " + f)
        i = i + 1

    version = payload["version"]
    if version != 1:
        return _make_bad_response("unsupported version")

    to_addr = payload["to_addr"]
    amount = payload["amount"]
    nullifier = payload["nullifier"]
    commit_change = payload["commit_change"]
    zk_proof_hex = payload["zk_proof"]

    # ---------- to_addr: hex format and field range ----------
    if not isinstance(to_addr, str):
        return _make_bad_response("to_addr must be hex string")
    try:
        to_addr_bytes = turn_hex_str_to_bytes(to_addr)
    except Exception:
        return _make_bad_response("to_addr not valid hex")
    if len(to_addr_bytes) != 32:
        return _make_bad_response("to_addr must be 32 bytes")
    to_addr_int = int.from_bytes(to_addr_bytes, "big")
    if to_addr_int >= PALLAS_P:
        return _make_bad_response("to_addr out of field range")

    # ---------- nullifier: hex format ----------
    if not isinstance(nullifier, str):
        return _make_bad_response("nullifier must be hex string")
    try:
        nullifier_bytes = turn_hex_str_to_bytes(nullifier)
    except Exception:
        return _make_bad_response("nullifier not valid hex")
    if len(nullifier_bytes) != 32:
        return _make_bad_response("nullifier must be 32 bytes")
    nullifier = nullifier_bytes.hex()

    # ---------- commit_change: hex format ----------
    if not isinstance(commit_change, str):
        return _make_bad_response("commit_change must be hex string")
    try:
        commit_change_bytes = turn_hex_str_to_bytes(commit_change)
    except Exception:
        return _make_bad_response("commit_change not valid hex")
    if len(commit_change_bytes) != 32:
        return _make_bad_response("commit_change must be 32 bytes")

    # ---------- zk_proof: hex format ----------
    if not isinstance(zk_proof_hex, str):
        return _make_bad_response("zk_proof must be hex string")
    try:
        _ = turn_hex_str_to_bytes(zk_proof_hex)
    except Exception:
        return _make_bad_response("zk_proof not valid hex")

    # ---------- amount checks ----------
    if not isinstance(amount, int):
        return _make_bad_response("amount must be int")
    if amount <= 0:
        return _make_bad_response("amount must be positive")
    if amount > _MAX_FIELD_INT:
        return _make_bad_response("amount out of FieldIntNonNeg range")

    # ---------- Account / nullifier checks ----------
    # Receiver address may be a fresh address never seen on chain.
    # If the account does not exist yet, create a new Account and
    # initialize it to the default on-chain state.
    to_acct = node.get_account(to_addr)
    if to_acct is None:
        new_acct = Account()
        new_acct.addr = to_addr
        new_acct.initialize_to_blockchain_default()
        to_acct = new_acct

    if nullifier in node.nullifier_set:
        return _make_bad_response("nullifier already spent")

    # ---------- ZK proof verification ----------
    # Use the current anon-commitment tree root as public input.
    commit_root_before_hex = node.node_commitment_tree.root()

    ok_proof = verify_zkproof_for_anon_pay(
        commit_root_before_hex,  # root
        nullifier,               # nullifier
        commit_change,           # commit_change
        amount,                  # value_pay
        zk_proof_hex,            # proof
    )

    if not ok_proof:
        return _make_bad_response("zk proof and public input do not match")

    # ---------- State updates ----------
    # 1) Receiver balance: add amount. For a fresh account this starts from 0.
    if to_acct.balance is None:
        to_acct.balance = 0
    to_acct.balance = to_acct.balance + amount

    # Receiver nonce does not change when receiving funds.
    node._add_account(to_acct)

    # 2) Append change commitment to the anon pool.
    node.append_commit(commit_change)

    # 3) Mark nullifier as spent.
    node.nullifier_set.add(nullifier)

    # 4) Record tx_entry and update tx tree.
    tx_entry = {
        "tx_type": "AnonPayTx",
        "payload": payload,
    }
    node.append_tx(tx_entry)

    # ---------- Build new_block ----------
    account_root_hex = node.account_tree.root()
    tx_root_hex = node.tx_tree.root()
    commit_root_hex = node.node_commitment_tree.root()

    new_block = {
        "account_root": account_root_hex,
        "tx_root": tx_root_hex,
        "commit_root": commit_root_hex,
        "applied_addr": to_addr,
        "to_addr": to_addr,
        "amount": amount,
        "nullifier": nullifier,
        "commit_change": commit_change,
        "tx": tx_entry,
    }

    return _make_ok_response(new_block)
