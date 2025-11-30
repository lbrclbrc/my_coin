# node/handle_get_acct_info.py
# Handle GetAccountInfo requests on the node side.
#
# Design notes:
#   - If addr is missing -> return {"ok": False, "err": "..."}.
#   - If the node has no account for addr -> return {"ok": True, "found": False, "account_root": <root_hex>}.
#   - If the node has an account -> return {"ok": True, "account": {...}, "merkle_proof": {...}}.
#   - For existing accounts, replace None fields with safe on-chain defaults
#     so that callers do not crash on None.

from acct import Account
from merkle_tree import MerkleTree
from tools import short_hex


def handle_get_account_info(node, payload):
    """
    Handle a GetAccountInfo request (node, payload).

    Return semantics:
      - Missing addr field in payload:
          {"ok": False, "err": "..."}
      - Account found:
          {"ok": True, "account": {...}, "merkle_proof": {...}}
      - Account not found on node:
          {"ok": True, "found": False, "account_root": <root_hex>}

    Notes:
      - merkle_proof.siblings is an ordered Merkle path with direction:
          [ (sibling_hex, "L"/"R"), ... ]
        "L" means the sibling is on the left, "R" means the sibling is on the right.
    """
    print("[NODE][GetAccountInfo] start handling account info request.")

    # Check payload.addr
    try:
        addr_hex = payload["addr"]
    except Exception as e:
        print("[NODE][GetAccountInfo][ERROR] missing addr field:", e)
        return {"ok": False, "err": f"missing field in GetAccountInfo payload: {e}"}

    print("[NODE][GetAccountInfo] query addr =", addr_hex)

    # Lookup account in node state (may be None)
    acct = node.get_account(addr_hex)
    if acct is None:
        # This is not considered an error: query is valid but account is not on-chain.
        print("[NODE][GetAccountInfo] account not found in node state (not on-chain). Returning found=False.")
        # Return current account_root so caller can decide whether to sync further.
        try:
            account_root = node.account_tree.root()
            print("[NODE][GetAccountInfo] account_root (short) =", short_hex(account_root))
        except Exception:
            account_root = None
        return {"ok": True, "found": False, "account_root": account_root}

    # If we have an account, prepare a Merkle proof for the client.

    # Find index in list_of_accounts for Merkle proof generation.
    index = -1
    i = 0
    while i < len(node.list_of_accounts):
        a = node.list_of_accounts[i]
        if a.addr == addr_hex:
            index = i
            break
        i += 1

    siblings = []
    if index >= 0:
        try:
            # gen_proof returns [(sibling_hex, "L"/"R"), ...]
            siblings = node.account_tree.gen_proof(index)
        except Exception as e:
            print("[NODE][GetAccountInfo][WARN] error while generating Merkle proof:", e)
            siblings = []
    else:
        print("[NODE][GetAccountInfo][WARN] account_map hit but list_of_accounts does not contain this account (state may be inconsistent).")

    try:
        account_root = node.account_tree.root()
    except Exception:
        account_root = None

    if account_root:
        root_short = short_hex(account_root)
    else:
        root_short = account_root
    print(
        "[NODE][GetAccountInfo] Merkle proof prepared. index =",
        index,
        ", account_root (short) =",
        root_short,
    )

    # Handle pk: may be None / bytes / str
    pk_val = None
    try:
        pk_val = acct.ecc_keypair.pk
    except Exception:
        pk_val = None

    if pk_val is None:
        pk_hex = "0" * 64
    elif isinstance(pk_val, (bytes, bytearray)):
        pk_hex = bytes(pk_val).hex()
    else:
        s = str(pk_val).strip()
        if s.startswith(("0x", "0X")):
            s = s[2:]
        pk_hex = s.lower()

    # Defensively normalize account fields to avoid None at upper layers.

    # balance
    try:
        bal_val = acct.balance
        if bal_val is not None:
            balance = bal_val
        else:
            balance = 0
    except Exception:
        balance = 0

    # nonce (None or missing -> 0)
    try:
        nval = acct.nonce
        if nval is not None:
            nonce_val = nval
        else:
            nonce_val = 0
    except Exception:
        nonce_val = 0

    # IDCard: ensure Color / ID are ints (missing or None -> 0)
    try:
        idcard = acct.IDCard
        if not isinstance(idcard, dict):
            id_color = 0
            id_id = 0
        else:
            id_color = idcard.get("Color", 0) or 0
            id_id = idcard.get("ID", 0) or 0
    except Exception:
        id_color = 0
        id_id = 0

    # commits: ensure it is a list
    try:
        lst = acct.lst_of_commits
        if lst is not None:
            commits_list = list(lst)
        else:
            commits_list = []
    except Exception:
        commits_list = []

    account_dict = {
        "addr": acct.addr,
        "balance": balance,
        "nonce": nonce_val,
        "IDCard": {
            "Color": id_color,
            "ID": id_id,
        },
        "lst_of_commits": commits_list,
        "pk": pk_hex,
    }

    merkle_proof_dict = {
        "siblings": siblings,
        "account_root": account_root,
    }

    print("[NODE][GetAccountInfo] account info packed into dict, ready to return to client.")

    return {
        "ok": True,
        "account": account_dict,
        "merkle_proof": merkle_proof_dict,
    }
