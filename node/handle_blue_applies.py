# node/handle_blue_applies.py

import json

from .utils import _truncate_long_hex_in_obj
from wrappers.poseidon_hash_wrapper import get_poseidon_hash
from wrappers.zkproof_for_ii_blue_apply_wrapper import verify_zkproof_for_ii_blue_apply
from wrappers.pasta_ecc_wrapper import EccKeypair

from acct import Account
from tools import turn_hex_str_to_bytes, PALLAS_P, get_hash, short_hex


def _prepare_account_and_check_nonce_for_blue(node, derived_addr_hex, new_pk_hex, nonce, log_tag):
    """
    Internal helper shared by BlueApply1/BlueApply2:

    - Load account by derived_addr_hex from node.
    - If not found, create a temporary Account with chain-default state
      and set addr/new pk (pk stored as hex, consistent with existing code path).
    - Check that account has nonce field.
    - Compute expected_nonce = acct.nonce + 1 and compare with given nonce.
    - Return (acct_obj, None) on success, or (None, error_dict) on failure.

    log_tag is a string prefix such as "[NODE][BlueApply1]" or "[NODE][BlueApply2]".
    """
    acct_obj = node.get_account(derived_addr_hex)
    if acct_obj is None:
        print(log_tag, "note: derived address not found on node; create temporary Account with chain-default state for verification.")
        acct_obj = Account()
        acct_obj.addr = derived_addr_hex
        acct_obj.ecc_keypair.pk = new_pk_hex
        acct_obj.initialize_to_blockchain_default()
    else:
        print(log_tag, "found existing Account, continue verification.")

    if not hasattr(acct_obj, "nonce"):
        print(log_tag, "ERROR: account has no nonce field.")
        return None, {"ok": False, "err": "account has no nonce field"}

    expected_nonce = acct_obj.nonce + 1
    print(log_tag, "current account nonce =", acct_obj.nonce, "expected nonce =", expected_nonce)

    if nonce != expected_nonce:
        print(log_tag, "ERROR: nonce mismatch.")
        return None, {"ok": False, "err": "nonce mismatch"}

    return acct_obj, None


def handle_blue_apply_type1(node, payload):
    """
    Type1 handler: server-side BlueApply1 handler (derive addr from new_blue_pk on node side).
    """
    print("[NODE][BlueApply1] start handling BlueApply1 request (derive addr from new_blue_pk).")

    # ---------------- parse fields (addr is derived on node side) ----------------
    try:
        version = payload["version"]
        ms_hex = payload["master_seed_hash"]
        new_pk_hex = payload["new_blue_pk"]
        user_id = payload["user_id"]
        clerk_id = payload["clerk_id"]
        cert = payload["cert"]
        nonce = payload["nonce"]
        applier_sig_hex = payload["applier_envelope_sig"]
        clerk_sig_hex = payload["clerk_envelope_sig"]
        zk_proof_hex = payload["zk_proof"]
    except Exception as e:
        print("[NODE][BlueApply1][ERROR] missing required field:", e)
        return {"ok": False, "err": f"missing field in BlueApply1 payload: {e}"}

    # derive address from new_pk_hex on node side (bytes semantics)
    try:
        new_pk_bytes_for_addr = turn_hex_str_to_bytes(new_pk_hex)
        derived_addr_hex = get_poseidon_hash(new_pk_bytes_for_addr)
    except Exception as e:
        print("[NODE][BlueApply1][ERROR] failed to derive address from new_blue_pk:", e)
        return {"ok": False, "err": "derive address from new_blue_pk error"}

    print("[NODE][BlueApply1] parsed payload. derived_addr =", derived_addr_hex, ", nonce =", nonce)
    print("[NODE][BlueApply1] master_seed_hash (short) =", short_hex(ms_hex))
    print("[NODE][BlueApply1] user_id =", user_id, ", clerk_id =", clerk_id)

    if version != 1:
        print("[NODE][BlueApply1][ERROR] version is not 1.")
        return {"ok": False, "err": "BlueApply1.version must be 1"}

    # certificate fields
    try:
        cert_pk_hex = cert["pk"]
        cert_sig_hex = cert["signature"]
        cert_id_str = cert["id"]
    except Exception as e:
        print("[NODE][BlueApply1][ERROR] cert missing field:", e)
        return {"ok": False, "err": f"missing field in cert: {e}"}

    # require user_id equals cert.id (bind identity)
    if user_id != cert_id_str:
        print("[NODE][BlueApply1][ERROR] user_id does not match cert.id.")
        return {"ok": False, "err": "user_id mismatch with cert.id"}

    # ---------------- type checks ----------------
    if not isinstance(nonce, int):
        print("[NODE][BlueApply1][ERROR] nonce is not int.")
        return {"ok": False, "err": "nonce must be int"}
    if not isinstance(derived_addr_hex, str):
        print("[NODE][BlueApply1][ERROR] derived addr is not str.")
        return {"ok": False, "err": "derived addr must be str"}

    # ---------------- account existence + nonce rule (using derived addr) ----------------
    acct_obj, err = _prepare_account_and_check_nonce_for_blue(
        node,
        derived_addr_hex,
        new_pk_hex,
        nonce,
        "[NODE][BlueApply1]"
    )
    if err is not None:
        return err

    # ---------------- hex -> bytes ----------------
    try:
        cert_pk_bytes = turn_hex_str_to_bytes(cert_pk_hex)
        cert_sig_bytes = turn_hex_str_to_bytes(cert_sig_hex)
        applier_sig_bytes = turn_hex_str_to_bytes(applier_sig_hex)
        clerk_sig_bytes = turn_hex_str_to_bytes(clerk_sig_hex)
        new_pk_bytes = turn_hex_str_to_bytes(new_pk_hex)
        ms_bytes = turn_hex_str_to_bytes(ms_hex)
        proof_bytes = turn_hex_str_to_bytes(zk_proof_hex)
    except Exception as e:
        print("[NODE][BlueApply1][ERROR] hex decode failed:", e)
        return {"ok": False, "err": f"hex decode error: {e}"}

    # ---------------- Step 1: verify CA signature on cert ----------------
    print("[NODE][BlueApply1] start verifying CA signature on cert...")
    ca_msg = (cert_pk_hex + cert_id_str).encode()
    try:
        if not node.ca_keypair.verify_signature(cert_sig_bytes, ca_msg):
            print("[NODE][BlueApply1][ERROR] CA cert signature verification failed.")
            return {"ok": False, "err": "bad CA cert signature"}
    except Exception:
        print("[NODE][BlueApply1][ERROR] exception while verifying CA cert signature.")
        return {"ok": False, "err": "bad CA cert signature (exception)"}
    print("[NODE][BlueApply1] CA cert signature verified.")

    # ---------------- Step 2: compute canonical payload hash for signatures ----------------
    print("[NODE][BlueApply1] start computing canonical payload hash for signature verification...")
    try:
        payload_no_sigs = {}
        for k in payload:
            if k != "applier_envelope_sig" and k != "clerk_envelope_sig":
                payload_no_sigs[k] = payload[k]
        canonical = json.dumps(
            payload_no_sigs,
            sort_keys=True,
            separators=(",", ":")
        ).encode()
        digest_hex = get_hash(canonical)
        digest = bytes.fromhex(digest_hex)
    except Exception as e:
        print("[NODE][BlueApply1][ERROR] payload canonicalization failed:", e)
        return {"ok": False, "err": f"payload canonicalization error: {e}"}

    # ---------------- Step 3: verify applier envelope signature ----------------
    print("[NODE][BlueApply1] start verifying applier envelope signature...")
    try:
        user_kp = EccKeypair()
        user_kp.set_pk(cert_pk_bytes)
        if not user_kp.verify_signature(applier_sig_bytes, digest):
            print("[NODE][BlueApply1][ERROR] applier_envelope_sig verification failed.")
            return {"ok": False, "err": "bad applier_envelope_sig"}
    except Exception:
        print("[NODE][BlueApply1][ERROR] exception while verifying applier_envelope_sig.")
        return {"ok": False, "err": "bad applier_envelope_sig (exception)"}
    print("[NODE][BlueApply1] applier_envelope_sig verified.")

    # ---------------- Step 4: verify clerk envelope signature ----------------
    print("[NODE][BlueApply1] start verifying clerk envelope signature...")
    try:
        if not node.clerk_keypair.verify_signature(clerk_sig_bytes, digest):
            print("[NODE][BlueApply1][ERROR] clerk_envelope_sig verification failed.")
            return {"ok": False, "err": "bad clerk_envelope_sig"}
    except Exception:
        print("[NODE][BlueApply1][ERROR] exception while verifying clerk_envelope_sig.")
        return {"ok": False, "err": "bad clerk_envelope_sig (exception)"}
    print("[NODE][BlueApply1] clerk_envelope_sig verified.")

    # ---------------- Step 5: check new_blue_pk length ----------------
    if not isinstance(new_pk_bytes, (bytes, bytearray)):
        print("[NODE][BlueApply1][ERROR] new_blue_pk has wrong type.")
        return {"ok": False, "err": "new_blue_pk must be bytes"}
    if len(new_pk_bytes) != 32:
        print("[NODE][BlueApply1][ERROR] new_blue_pk length is not 32 bytes.")
        return {"ok": False, "err": "new_blue_pk must be 32 bytes"}
    print("[NODE][BlueApply1] new_blue_pk length check passed.")

    # ---------------- Step 6: token = 0 for Type1 ----------------
    token_bytes = (0).to_bytes(32, "big")
    print("[NODE][BlueApply1] token is fixed to 0 (32 zero bytes).")

    # ---------------- Step 7: verify zk proof ----------------
    print("[NODE][BlueApply1] start verifying zk proof (not printing full proof)...")
    try:
        ok_proof = verify_zkproof_for_ii_blue_apply(proof_bytes, token_bytes, new_pk_bytes, ms_bytes)
    except Exception:
        print("[NODE][BlueApply1][ERROR] exception during zk proof verification.")
        return {"ok": False, "err": "zk proof verification error"}
    if not ok_proof:
        print("[NODE][BlueApply1][ERROR] zk proof does not match public input.")
        return {"ok": False, "err": "zk proof and public input do not match"}
    print("[NODE][BlueApply1] zk proof verified.")

    # ---------------- Step 8: update ms_hash -> user_id mapping and Account ----------------
    ms_key = ms_hex
    node.ms_hash_to_id[ms_key] = user_id
    print("[NODE][BlueApply1] recorded ms_hash -> user_id mapping.")

    try:
        acct_obj.IDCard["ID"] = int(user_id, 16)
    except Exception:
        try:
            acct_obj.IDCard["ID"] = int(user_id)
        except Exception:
            print("[NODE][BlueApply1][ERROR] user_id is neither hex nor decimal.")
            return {"ok": False, "err": "invalid user_id format"}
    acct_obj.IDCard["Color"] = 1

    acct_obj.nonce = nonce
    print("[NODE][BlueApply1] account IDCard updated, Color=1, nonce updated to", acct_obj.nonce)
    acct_obj.balance += 500
    print("[NODE][BlueApply1] account balance updated, increased by 500, current balance =", acct_obj.balance)

    if derived_addr_hex in node.account_map:
        node.update_account(derived_addr_hex, acct_obj)
    else:
        node._add_account(acct_obj)
    print("[NODE][BlueApply1] account MerkleTree updated, new account_root (short) =", short_hex(node.account_tree.root()))

    # ---------------- Step 9: record tx ----------------
    tx = {
        "tx_type": "BlueApply1",
        "payload": payload,
    }
    node.append_tx(tx)

    new_block = {
        "account_root": node.account_tree.root(),
        "tx_root": node.tx_tree.root(),
        "commit_root": node.node_commitment_tree.root(),
        "applied_addr": derived_addr_hex,
        "tx": tx,
    }

    print("[NODE][BlueApply1] processing finished, new_block generated.")

    new_block_for_return = _truncate_long_hex_in_obj(new_block)

    return {"ok": True, "new_block": new_block_for_return}


def handle_blue_apply_type2(node, payload):
    """
    Type2 handler: server-side BlueApply2 handler (derive addr from new_blue_pk on node side).
    """
    print("[NODE][BlueApply2] start handling BlueApply2 request (derive addr from new_blue_pk).")

    # ---------------- parse fields (addr is derived on node side) ----------------
    try:
        version = payload["version"]
        ms_hex = payload["master_seed_hash"]
        new_pk_hex = payload["new_blue_pk"]
        token_hex = payload["token"]
        nonce = payload["nonce"]
        zk_proof_hex = payload["zk_proof"]
    except Exception as e:
        print("[NODE][BlueApply2][ERROR] missing required field:", e)
        return {"ok": False, "err": f"missing field in BlueApply2 payload: {e}"}

    # derive address from new_pk_hex on node side (same semantics as Type1)
    try:
        new_pk_bytes_for_addr = turn_hex_str_to_bytes(new_pk_hex)
        derived_addr_hex = get_poseidon_hash(new_pk_bytes_for_addr)
    except Exception as e:
        print("[NODE][BlueApply2][ERROR] failed to derive address from new_blue_pk:", e)
        return {"ok": False, "err": "derive address from new_blue_pk error"}

    print("[NODE][BlueApply2] parsed payload. derived_addr =", derived_addr_hex, ", nonce =", nonce)
    print("[NODE][BlueApply2] master_seed_hash (short) =", short_hex(ms_hex))
    print("[NODE][BlueApply2] token (short) =", short_hex(token_hex))

    if version != 1:
        print("[NODE][BlueApply2][ERROR] version is not 1.")
        return {"ok": False, "err": "BlueApply2.version must be 1"}

    if not isinstance(nonce, int):
        print("[NODE][BlueApply2][ERROR] nonce is not int.")
        return {"ok": False, "err": "nonce must be int"}
    if not isinstance(derived_addr_hex, str):
        print("[NODE][BlueApply2][ERROR] derived addr is not str.")
        return {"ok": False, "err": "derived addr must be str"}

    # ---------------- account existence + nonce check (using derived addr) ----------------
    acct_obj, err = _prepare_account_and_check_nonce_for_blue(
        node,
        derived_addr_hex,
        new_pk_hex,
        nonce,
        "[NODE][BlueApply2]"
    )
    if err is not None:
        return err

    # ---------------- hex -> bytes ----------------
    try:
        token_bytes = turn_hex_str_to_bytes(token_hex)
        new_pk_bytes = turn_hex_str_to_bytes(new_pk_hex)
        ms_bytes = turn_hex_str_to_bytes(ms_hex)
        proof_bytes = turn_hex_str_to_bytes(zk_proof_hex)
    except Exception as e:
        print("[NODE][BlueApply2][ERROR] hex decode failed:", e)
        return {"ok": False, "err": f"hex decode error: {e}"}

    # ---------------- Step 1: token format and range check ----------------
    if not isinstance(token_bytes, (bytes, bytearray)):
        print("[NODE][BlueApply2][ERROR] token has wrong type.")
        return {"ok": False, "err": "token must be bytes"}
    if len(token_bytes) != 32:
        print("[NODE][BlueApply2][ERROR] token length is not 32 bytes.")
        return {"ok": False, "err": "token must be 32 bytes"}

    token_int = int.from_bytes(token_bytes, "big")
    if token_int >= PALLAS_P:
        print("[NODE][BlueApply2][ERROR] token out of field range.")
        return {"ok": False, "err": "token out of range"}
    print("[NODE][BlueApply2] token format and range check passed.")

    # ---------------- Step 2: lookup master_seed_hash -> ID mapping ----------------
    ms_key = ms_hex
    if ms_key not in node.ms_hash_to_id:
        print("[NODE][BlueApply2][ERROR] master_seed_hash is not registered.")
        return {"ok": False, "err": "master_seed_hash not registered"}

    mapped_id_str = node.ms_hash_to_id[ms_key]
    print("[NODE][BlueApply2] found registered ID =", mapped_id_str)

    # ---------------- Step 3: verify zk proof ----------------
    print("[NODE][BlueApply2] start verifying zk proof (not printing full proof)...")
    try:
        ok_proof = verify_zkproof_for_ii_blue_apply(proof_bytes, token_bytes, new_pk_bytes, ms_bytes)
    except Exception:
        print("[NODE][BlueApply2][ERROR] exception during zk proof verification.")
        return {"ok": False, "err": "zk proof verification error"}
    if not ok_proof:
        print("[NODE][BlueApply2][ERROR] zk proof does not match public input.")
        return {"ok": False, "err": "zk proof and public input do not match"}
    print("[NODE][BlueApply2] zk proof verified.")

    # ---------------- Step 4: update Account (ID + Color, nonce) ----------------
    try:
        acct_obj.IDCard["ID"] = int(mapped_id_str, 16)
    except Exception:
        try:
            acct_obj.IDCard["ID"] = int(mapped_id_str)
        except Exception:
            print("[NODE][BlueApply2][ERROR] mapped ID is neither hex nor decimal.")
            return {"ok": False, "err": "invalid mapped id format"}

    acct_obj.IDCard["Color"] = 1
    acct_obj.nonce = nonce
    print("[NODE][BlueApply2] account IDCard updated, Color=1, nonce updated to", acct_obj.nonce)

    if derived_addr_hex in node.account_map:
        node.update_account(derived_addr_hex, acct_obj)
    else:
        node._add_account(acct_obj)
    print("[NODE][BlueApply2] account MerkleTree updated, new account_root (short) =", short_hex(node.account_tree.root()))

    # ---------------- Step 5: record tx ----------------
    tx = {
        "tx_type": "BlueApply2",
        "payload": payload,
    }
    node.append_tx(tx)

    new_block = {
        "account_root": node.account_tree.root(),
        "tx_root": node.tx_tree.root(),
        "commit_root": node.node_commitment_tree.root(),
        "applied_addr": derived_addr_hex,
        "tx": tx,
    }

    print("[NODE][BlueApply2] processing finished, new_block generated.")

    new_block_for_return = _truncate_long_hex_in_obj(new_block)

    return {"ok": True, "new_block": new_block_for_return}
