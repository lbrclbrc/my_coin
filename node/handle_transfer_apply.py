# node/handle_transfer_apply.py
# Handle Transfer (transparent transfer) requests.
#
# Protocol summary:
#   - Payload fields:
#       version, from_addr, to_addr, amount, nonce, pk_sender, signature.
#   - Any address can receive funds; there is no Color check for the receiver.
#   - The relation pk_sender -> from_addr is enforced by Poseidon(pk_sender) = from_addr.
#   - The node verifies the ECC signature on a canonical JSON encoding of the payload.
#   - On success the node updates accounts, the account Merkle tree and the tx buffer,
#     and returns a new_block object for the caller to commit.
#
# Return values:
#   - On success: {"ok": True, "new_block": {...}}
#   - On failure: {"ok": False, "err": "<reason>"}

import json

from wrappers.poseidon_hash_wrapper import get_poseidon_hash
from wrappers.pasta_ecc_wrapper import EccKeypair

from tools import turn_hex_str_to_bytes, get_hash, PALLAS_P


def _make_bad_response(msg):
    return {"ok": False, "err": msg}


def _make_ok_response(new_block=None):
    if new_block is None:
        return {"ok": True}
    return {"ok": True, "new_block": new_block}


def _canonical_payload_bytes_for_signature(payload_dict, exclude_keys):
    """
    Build canonical JSON bytes for signature verification, excluding given keys.
    """
    payload_copy = {}
    for k in sorted(payload_dict.keys()):
        if k in exclude_keys:
            continue
        payload_copy[k] = payload_dict[k]
    bs = json.dumps(payload_copy, sort_keys=True, separators=(",", ":")).encode()
    return bs


def _decode_addr_32_in_field(addr_hex, field_name):
    """
    Decode a hex address, ensure it is exactly 32 bytes and < PALLAS_P.
    Returns (addr_bytes, err_dict_or_none).
    """
    if not isinstance(addr_hex, str):
        return None, _make_bad_response(field_name + " must be hex string")
    try:
        b = turn_hex_str_to_bytes(addr_hex)
    except Exception:
        return None, _make_bad_response(field_name + " not valid hex")
    if len(b) != 32:
        return None, _make_bad_response(field_name + " must be 32 bytes")
    v = int.from_bytes(b, "big")
    if v >= PALLAS_P:
        return None, _make_bad_response(field_name + " out of field range")
    return b, None


def handle_transfer(node, payload):
    """
    Handle a Transfer request on the node side.

    Required payload fields:
      - version (int, must be 1)
      - from_addr (Hex32, Pallas Fp element)
      - to_addr   (Hex32, Pallas Fp element)
      - amount    (int > 0)
      - nonce     (int)
      - pk_sender (Hex32, compressed public key bytes)
      - signature (hex-encoded signature bytes)

    Returns:
      {"ok": True, "new_block": {...}} or {"ok": False, "err": "..."}.
    """

    required_fields = ["version", "from_addr", "to_addr", "amount", "nonce", "pk_sender", "signature"]
    i = 0
    while i < len(required_fields):
        f = required_fields[i]
        if f not in payload:
            return _make_bad_response("missing field in Transfer payload: " + f)
        i = i + 1

    version = payload["version"]
    if version != 1:
        return _make_bad_response("unsupported version")

    from_addr = payload["from_addr"]
    to_addr = payload["to_addr"]
    amount = payload["amount"]
    nonce = payload["nonce"]
    pk_sender = payload["pk_sender"]
    signature_hex = payload["signature"]

    # -------- Basic type checks --------
    if not isinstance(amount, int):
        return _make_bad_response("amount must be int")
    if amount <= 0:
        return _make_bad_response("amount must be positive")
    if not isinstance(nonce, int):
        return _make_bad_response("nonce must be int")
    if not isinstance(pk_sender, str):
        return _make_bad_response("pk_sender must be hex string")
    if not isinstance(signature_hex, str):
        return _make_bad_response("signature must be hex string")
    if len(signature_hex) % 2 != 0:
        return _make_bad_response("signature hex length invalid")

    # -------- Address field-range checks (Pallas Fp) --------
    from_addr_bytes, err = _decode_addr_32_in_field(from_addr, "from_addr")
    if err is not None:
        return err

    to_addr_bytes, err = _decode_addr_32_in_field(to_addr, "to_addr")
    if err is not None:
        return err

    # -------- Decode pk_sender --------
    try:
        pk_bytes = turn_hex_str_to_bytes(pk_sender)
    except Exception:
        return _make_bad_response("pk_sender hex decode failed")
    if len(pk_bytes) != 32:
        return _make_bad_response("pk_sender must be 32 bytes")

    # -------- Decode signature --------
    try:
        sig_bytes = bytes.fromhex(signature_hex)
    except Exception:
        return _make_bad_response("signature not valid hex")

    # -------- Sender account lookup --------
    from_acct = node.get_account(from_addr)
    if from_acct is None:
        return _make_bad_response("from_addr not found on node")

    # Receiver account: may be fresh, any address within field range can receive funds.
    to_acct = node.get_account(to_addr)
    if to_acct is None:
        new_recv = from_acct.__class__()
        new_recv.addr = to_addr
        new_recv.initialize_to_blockchain_default()
        to_acct = new_recv

    # -------- Verify pk_sender -> from_addr relationship --------
    # Use bytes input for Poseidon to avoid string-hex ambiguity.
    addr_derived_from_pk = get_poseidon_hash(pk_bytes)
    if addr_derived_from_pk != from_addr:
        return _make_bad_response("pk_sender does not match from_addr (derived addr mismatch)")

    # -------- Rebuild canonical payload hash for signature verification --------
    canonical_bytes = _canonical_payload_bytes_for_signature(payload, exclude_keys=("signature",))
    digest_hex = get_hash(canonical_bytes)
    digest_bytes = bytes.fromhex(digest_hex)

    verifier_kp = EccKeypair()
    verifier_kp.set_pk(pk_bytes)

    try:
        ok_verify = verifier_kp.verify_signature(sig_bytes, digest_bytes)
    except AttributeError:
        try:
            ok_verify = verifier_kp.verify(sig_bytes, digest_bytes)
        except Exception:
            return _make_bad_response(
                "verifier API not present or failed (check wrapper EccKeypair interface)"
            )
    except Exception as e:
        return _make_bad_response("signature verification failed (error): " + repr(e))

    if not ok_verify:
        return _make_bad_response("bad signature")

    # -------- Nonce and balance checks --------
    expected_nonce = from_acct.nonce + 1
    if nonce != expected_nonce:
        return _make_bad_response("bad nonce")

    if from_acct.balance < amount:
        return _make_bad_response("insufficient balance")

    # -------- State updates --------
    from_acct.balance = from_acct.balance - amount
    from_acct.nonce = nonce

    to_acct.balance = to_acct.balance + amount
    node._add_account(to_acct)
    node._add_account(from_acct)

    # -------- Record tx and compute new roots --------
    tx_entry = {
        "tx_type": "Transfer",
        "payload": payload,
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
        "to_addr": to_addr,
        "tx": tx_entry,
    }

    return _make_ok_response(new_block)
