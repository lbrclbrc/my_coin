#!/usr/bin/env python3
# client/apply_for_blue.py
# Build envelopes for BlueApply1 / BlueApply2.
# These helpers use a client instance and its methods/fields to construct
# request payloads; they only build envelopes and do not send them.

import os
import sys

THIS_FILE = os.path.abspath(__file__)
MODULE_DIR = os.path.dirname(THIS_FILE)
PROJECT_ROOT = os.path.abspath(os.path.join(MODULE_DIR, ".."))
WRAPPERS_DIR = os.path.join(PROJECT_ROOT, "wrappers")

for p in (WRAPPERS_DIR, PROJECT_ROOT):
    if p and os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

from tools import PALLAS_P, SCALAR_ORDER
from wrappers.zkproof_for_ii_blue_apply_wrapper import get_zkproof_for_ii_blue_apply
from wrappers.poseidon_hash_wrapper import get_poseidon_hash

from acct import Account


def build_apply_for_blue_i_envelope(client, acct):
    """
    Build a BlueApply1 envelope.

    The function:
      - checks that the client has a master seed;
      - derives a deterministic token = 0 and new_blue_pk from master seed + token;
      - derives the corresponding address via Poseidon(new_blue_pk);
      - creates or updates a local Account for that address (only addr and ECC keys);
      - computes nonce based on local cached nonce (or 1 if unknown -> 0 + 1);
      - computes master_seed_hash and the ZK proof;
      - signs the payload with both the client and the clerk keypair;
      - returns the envelope dict without sending it.
    """
    if not client.has_master_seed():
        raise ValueError("MasterSeed is not set; cannot apply for BlueApply1.")

    if acct.addr is None:
        acct.fill_missing()
    local_addr = acct.addr

    print("\n[CLIENT] [BlueApply1] preparing envelope.")
    print("[CLIENT] [BlueApply1] local target address =", local_addr)

    master_seed = client.MASTER_SEED
    token_bytes = (0).to_bytes(32, "big")
    print("[CLIENT] [BlueApply1] token is fixed to 0 (32 zero bytes).")

    # new_pk is deterministically derived by a core helper
    new_pk = client._derive_new_pk_from_master_and_token(master_seed, token_bytes)
    new_pk_hex = new_pk.hex()
    print("[CLIENT] [BlueApply1] derived new_blue_pk (hex prefix):", new_pk_hex[:16], "...")

    # derive address directly from the public key bytes
    derived_addr = get_poseidon_hash(new_pk)
    print("[CLIENT] [BlueApply1] derived address (derived_addr) =", derived_addr)

    # derive a deterministic secret key (must follow the same rule as the core helper)
    raw_hex = get_poseidon_hash(master_seed, token_bytes)
    digest_int = int(raw_hex, 16) % SCALAR_ORDER
    new_sk_hex = "%064x" % digest_int
    new_sk_bytes = bytes.fromhex(new_sk_hex)

    # create or update the local Account: only addr and ECC keys are set; other fields remain None
    if derived_addr in client.Dict_of_accts:
        derived_acct = client.Dict_of_accts[derived_addr]
        print("[CLIENT] [BlueApply1] using cached nonce =", derived_acct.nonce)
    else:
        print("[CLIENT] [BlueApply1] no cached account for derived_addr; initializing a new Account with unknown fields.")
        derived_acct = Account()
        derived_acct.addr = derived_addr

    # overwrite ECC keypair with the freshly derived keypair (true SK/PK)
    derived_acct.ecc_keypair.set_sk(new_sk_bytes)
    derived_acct.ecc_keypair.pk = new_pk

    client.Dict_of_accts[derived_addr] = derived_acct

    # payload.nonce uses only the locally known nonce; if unknown, treat base_nonce as 0 but do not backfill
    base_nonce = derived_acct.nonce
    if base_nonce is None:
        base_nonce = 0
    nonce = base_nonce + 1
    print("[CLIENT] [BlueApply1] payload.nonce =", nonce)

    ms_hash_bytes = client._compute_master_seed_hash_bytes(master_seed)
    print("[CLIENT] [BlueApply1] master_seed_hash =", ms_hash_bytes.hex()[:16], "...")

    proof_hex = get_zkproof_for_ii_blue_apply(master_seed, token_bytes, new_pk, ms_hash_bytes)
    print("[CLIENT] [BlueApply1] ZK proof generated (hex prefix):", proof_hex[:16], "...")

    payload = {
        "version": 1,
        "master_seed_hash": ms_hash_bytes.hex(),
        "new_blue_pk": new_pk_hex,
        "user_id": client.CERT["id"],
        "clerk_id": client.CERT["clerk_id"],
        "cert": client.CERT,
        "nonce": nonce,
        "zk_proof": proof_hex,
    }

    print("[CLIENT] [BlueApply1] payload (without signatures) constructed; signing payload.")

    applier_sig_hex = client._sign_payload_dict(payload)
    print("[CLIENT] [BlueApply1] applier_envelope_sig generated.")

    clerk_sig_hex = client._sign_payload_dict_with_kp(payload, client.clerk_keypair)
    print("[CLIENT] [BlueApply1] clerk_envelope_sig generated.")

    payload["applier_envelope_sig"] = applier_sig_hex
    payload["clerk_envelope_sig"] = clerk_sig_hex

    # only update the local nonce if it was already known; otherwise keep None to reflect unknown state
    if derived_acct.nonce is not None:
        derived_acct.nonce = nonce
        print("[CLIENT] [BlueApply1] local derived_addr nonce updated to", derived_acct.nonce)
    else:
        print("[CLIENT] [BlueApply1] local derived_addr nonce still unknown (kept as None).")

    client.Dict_of_accts[derived_acct.addr] = derived_acct

    envelope = {
        "application_type": "BlueApply1",
        "payload": payload,
    }
    print("[CLIENT] [BlueApply1] envelope constructed (no implicit Node query); caller is responsible for sending it.")
    return envelope


def build_apply_for_blue_ii_envelope(client, acct, token=None):
    """
    Build a BlueApply2 envelope.

    The function:
      - checks that the client has a master seed;
      - takes a token (None/int/hex-string) and normalizes it into a 32-byte field element;
      - derives new_blue_pk and derived_addr from master seed + token;
      - creates or updates a local Account for that address (only addr and ECC keys);
      - computes nonce based on local cached nonce (or 1 if unknown -> 0 + 1);
      - computes master_seed_hash and the ZK proof;
      - returns the envelope dict (Type 2 has no certificate or envelope signatures).
    """
    if not client.has_master_seed():
        raise ValueError("MasterSeed is not set; cannot apply for BlueApply2.")

    if acct.addr is None:
        acct.fill_missing()
    local_addr = acct.addr

    print("\n[CLIENT] [BlueApply2] preparing envelope.")
    print("[CLIENT] [BlueApply2] local target address =", local_addr)

    master_seed = client.MASTER_SEED

    if token is None:
        token_bytes = client._random_token_in_pallas()
    else:
        if isinstance(token, int):
            v = token % PALLAS_P
            token_bytes = v.to_bytes(32, "big")
            print("[CLIENT] [BlueApply2] using int token; reduced modulo P and encoded as 32-byte value.")
        elif isinstance(token, str):
            s = token.strip()
            if s.startswith(("0x", "0X")):
                s = s[2:]
            v = int(s, 16) % PALLAS_P
            token_bytes = v.to_bytes(32, "big")
            print("[CLIENT] [BlueApply2] using hex-string token; reduced modulo P and encoded as 32-byte value.")
        else:
            raise TypeError("token must be None, int or hex-string")

    new_pk = client._derive_new_pk_from_master_and_token(master_seed, token_bytes)
    new_pk_hex = new_pk.hex()
    print("[CLIENT] [BlueApply2] derived new_blue_pk (hex prefix):", new_pk_hex[:16], "...")

    # derive address directly from the public key bytes
    derived_addr = get_poseidon_hash(new_pk)
    print("[CLIENT] [BlueApply2] derived address (derived_addr) =", derived_addr)

    # derive a deterministic secret key (must follow the same rule as the core helper)
    raw_hex = get_poseidon_hash(master_seed, token_bytes)
    digest_int = int(raw_hex, 16) % SCALAR_ORDER
    new_sk_hex = "%064x" % digest_int
    new_sk_bytes = bytes.fromhex(new_sk_hex)

    # create or update the local Account: only addr and ECC keys are set; other fields remain None
    if derived_addr in client.Dict_of_accts:
        derived_acct = client.Dict_of_accts[derived_addr]
        print("[CLIENT] [BlueApply2] using cached nonce =", derived_acct.nonce)
    else:
        print("[CLIENT] [BlueApply2] no cached account for derived_addr; initializing a new Account with unknown fields.")
        derived_acct = Account()
        derived_acct.addr = derived_addr

    derived_acct.ecc_keypair.set_sk(new_sk_bytes)
    derived_acct.ecc_keypair.pk = new_pk

    client.Dict_of_accts[derived_addr] = derived_acct

    base_nonce = derived_acct.nonce
    if base_nonce is None:
        base_nonce = 0
    nonce = base_nonce + 1
    print("[CLIENT] [BlueApply2] payload.nonce =", nonce)

    ms_hash_bytes = client._compute_master_seed_hash_bytes(master_seed)
    print("[CLIENT] [BlueApply2] master_seed_hash =", ms_hash_bytes.hex()[:16], "...")

    proof_hex = get_zkproof_for_ii_blue_apply(master_seed, token_bytes, new_pk, ms_hash_bytes)
    print("[CLIENT] [BlueApply2] ZK proof generated (hex prefix):", proof_hex[:16], "...")

    payload = {
        "version": 1,
        "master_seed_hash": ms_hash_bytes.hex(),
        "new_blue_pk": new_pk_hex,
        "token": token_bytes.hex(),
        "nonce": nonce,
        "zk_proof": proof_hex,
    }

    print("[CLIENT] [BlueApply2] payload constructed (Type2 has no certificate or envelope signatures, and does not include addr).")

    if derived_acct.nonce is not None:
        derived_acct.nonce = nonce
        print("[CLIENT] [BlueApply2] local derived_addr nonce updated to", derived_acct.nonce)
    else:
        print("[CLIENT] [BlueApply2] local derived_addr nonce still unknown (kept as None).")

    client.Dict_of_accts[derived_acct.addr] = derived_acct

    envelope = {
        "application_type": "BlueApply2",
        "payload": payload,
    }
    print("[CLIENT] [BlueApply2] envelope constructed (no implicit Node query); caller is responsible for sending it.")
    return envelope
