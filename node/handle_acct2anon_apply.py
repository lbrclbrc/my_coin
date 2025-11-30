# node/handle_acct2anon_apply.py

import json

from wrappers.zkproof_for_acct_to_anon_tx_wrapper import verify_zkproof_for_acct_to_anon_tx

HEX_CHARS = set("0123456789abcdef")


def _is_valid_hex_str(s, length=None):
    if not isinstance(s, str):
        return False
    if length is not None and len(s) != length:
        return False
    for ch in s:
        if ch not in HEX_CHARS:
            return False
    return True


def _make_bad_response(msg):
    return {"ok": False, "err": msg}


def _make_ok_response(new_block=None):
    if new_block is None:
        return {"ok": True}
    return {"ok": True, "new_block": new_block}


_MAX_FIELD_INT = (1 << 96) - 1


def handle_acct2anon(node, payload):
    required_fields = ["version", "from_addr", "amount", "anon_commit", "zk_proof"]
    for f in required_fields:
        if f not in payload:
            return _make_bad_response(f"missing field in AcctToAnon payload: {f}")

    version = payload["version"]
    if version != 1:
        return _make_bad_response("unsupported version")

    from_addr = payload["from_addr"]
    amount = payload["amount"]
    anon_commit = payload["anon_commit"]
    zk_proof_hex = payload["zk_proof"]

    if not _is_valid_hex_str(from_addr, 64):
        return _make_bad_response("from_addr is not valid 64-char hex")
    if not _is_valid_hex_str(anon_commit, 64):
        return _make_bad_response("anon_commit is not valid 64-char hex")
    if not isinstance(zk_proof_hex, str):
        return _make_bad_response("zk_proof must be hex string")
    if len(zk_proof_hex) % 2 != 0:
        return _make_bad_response("zk_proof hex length invalid")
    if not _is_valid_hex_str(zk_proof_hex, None):
        return _make_bad_response("zk_proof not valid hex lowercase")

    if not isinstance(amount, int):
        return _make_bad_response("amount must be int")
    if amount <= 0:
        return _make_bad_response("amount must be positive")
    if amount > _MAX_FIELD_INT:
        return _make_bad_response("amount out of FieldIntNonNeg range")

    from_acct = node.get_account(from_addr)
    if from_acct is None:
        return _make_bad_response("from_addr not found on node")

    sender_color = 0
    if isinstance(from_acct.IDCard, dict) and "Color" in from_acct.IDCard:
        sender_color = from_acct.IDCard["Color"]
    if sender_color != 1:
        return _make_bad_response("sender Color != 1 not allowed for AcctToAnon")

    if from_acct.balance < amount:
        return _make_bad_response("insufficient balance")

    expected_nonce = from_acct.nonce + 1

    val_bytes = int(amount).to_bytes(32, "big")
    nonce_bytes = int(expected_nonce).to_bytes(32, "big")

    val_hex = val_bytes.hex()
    nonce_hex = nonce_bytes.hex()

    ok_proof = verify_zkproof_for_acct_to_anon_tx(
        zk_proof_hex,
        val_hex,
        nonce_hex,
        from_addr,
        anon_commit,
    )

    if not ok_proof:
        return _make_bad_response("zk proof and public input do not match")

    from_acct.balance = from_acct.balance - amount
    from_acct.nonce = expected_nonce

    if not isinstance(from_acct.lst_of_commits, list):
        from_acct.lst_of_commits = []
    from_acct.lst_of_commits.append(anon_commit)

    node._add_account(from_acct)
    node.append_commit(anon_commit)

    tx_entry = {
        "tx_type": "AcctToAnon",
        "payload": payload
    }
    node.append_tx(tx_entry)

    account_root_hex = node.account_tree.root()
    tx_root_hex = node.tx_tree.root()
    commit_root_hex = node.node_commitment_tree.root()

    new_block = {
        "account_root": account_root_hex,
        "tx_root": tx_root_hex,
        "commit_root": commit_root_hex,

        "applied_addr": from_addr,
        "from_addr": from_addr,
        "amount": amount,
        "anon_commit": anon_commit,

        "tx": tx_entry,
    }

    return _make_ok_response(new_block)
