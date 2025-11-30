#!/usr/bin/env python3
# client/core.py
# Main Client implementation (without the concrete apply_for_blue logic).
# The structure and style is kept close to the original client design.

import os
import sys
import json

# ---- ensure wrappers and project root are importable ----
THIS_FILE = os.path.abspath(__file__)
CLIENT_DIR = os.path.dirname(THIS_FILE)
PROJECT_ROOT = os.path.abspath(os.path.join(CLIENT_DIR, ".."))
WRAPPERS_DIR = os.path.join(PROJECT_ROOT, "wrappers")

for p in (WRAPPERS_DIR, PROJECT_ROOT):
    if p and os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)
# ---------------------------------------------------------

# === wrappers (Rust extensions) ===
from wrappers.zkproof_for_ii_blue_apply_wrapper import get_zkproof_for_ii_blue_apply
from wrappers.poseidon_hash_wrapper import get_poseidon_hash
import wrappers.pasta_ecc_wrapper as pasta_ecc_wrapper

# apply_for_blue module: contains concrete builders for BlueApply1/BlueApply2 envelopes
from .apply_for_blue import build_apply_for_blue_i_envelope, build_apply_for_blue_ii_envelope

# apply_for_acct2anon module
from .apply_for_acct2anon import build_apply_for_acct2anon_envelope

# apply_for_anon_pay module
from .apply_for_anon_pay import build_apply_for_anon_pay_envelope

# Account and tools
from acct import Account

from tools import (
    derive_master_seed_from_password,
    verify_account_merkle_proof,
    get_hash,
    PALLAS_P,
    SCALAR_ORDER,
    CA_SK_HEX,
    CA_PK_HEX,
    CLERK_SK_HEX,
    CLERK_PK_HEX,
)


class Client:
    """
    Simplified Client:

      - CERT must be provided from outside and set before use.
      - apply_for_blue_i / apply_for_blue_ii delegate to helper functions
        in client.apply_for_blue.
    """

    def __init__(self, cert):
        # CERT is provided externally (for example by a demo helper that builds a cert dict)
        self.CERT = cert
        self.MASTER_SEED = b""
        self.Dict_of_accts = {}

        # Local ECC keypair for the user identity (used for signing).
        # The wallet may manage multiple accounts; this keypair is for
        # "identity/certificate" usage only and is not exposed directly.
        self._user_keypair_cert = pasta_ecc_wrapper.EccKeypair()
        self._user_keypair_cert.get_sk()

        # Clerk ECC keypair, initialized from CLERK_SK_HEX.
        self.clerk_keypair = pasta_ecc_wrapper.EccKeypair()
        clerk_sk_bytes = bytes.fromhex(CLERK_SK_HEX)
        if len(clerk_sk_bytes) != 32:
            raise ValueError("CLERK_SK_HEX must represent 32 bytes")
        self.clerk_keypair.set_sk(clerk_sk_bytes)
        print("[CLIENT] Clerk keypair initialized from CLERK_SK_HEX.")

        print("[CLIENT] Client initialized (CERT is set).")

    # ---------------- MasterSeed ----------------
    def set_master_seed_from_password(self, password):
        new_seed = derive_master_seed_from_password(password)
        if not self.MASTER_SEED:
            print("[CLIENT] [INIT] MasterSeed created.")
        else:
            print("[CLIENT] [UPDATE] MasterSeed updated (old value overwritten).")
        self.MASTER_SEED = new_seed
        print("[CLIENT] [DEBUG] MasterSeed =", self.MASTER_SEED.hex())

    def has_master_seed(self):
        return bool(self.MASTER_SEED)

    def get_user_pk_hex(self):
        """Return the user identity public key as hex (for cert construction or display)."""
        pk_bytes = self._user_keypair_cert.get_pk_from_sk()
        return pk_bytes.hex()

    # ---------------- Account management (local dict) ----------------
    def create_rand_acct_and_add_to_dict(self):
        """
        Create a new Account object locally and fill its addr from the ECC key.
        This only affects local state; on-chain state must be aligned via
        fetch_account_from_node.
        """
        if not self.has_master_seed():
            raise ValueError("MasterSeed is not set; cannot create account.")
        acct = Account()
        acct.fill_missing()
        self.Dict_of_accts[acct.addr] = acct
        print("[CLIENT] [NEW ACCT] addr:", acct.addr[:12], "created locally.")
        return acct

    def list_accts(self):
        if not self.Dict_of_accts:
            print("[CLIENT] [INFO] no accounts in the current wallet.")
            return
        print("[CLIENT] accounts in current wallet:")
        for addr, acct in self.Dict_of_accts.items():
            lst = acct.lst_of_commits
            commits_len = len(lst) if lst is not None else 0
            print(
                "-",
                addr[:12],
                "| balance:", acct.balance,
                "| commits:", commits_len,
                "| nonce:", acct.nonce,
            )

    # ---------------- Talk to Node: query on-chain account state ----------------
    def fetch_account_from_node(self, node, addr_hex):
        """
        Follow the "How to Get ACCT Info" spec:

          - build an envelope with application_type="GetAccountInfo";
          - call node.deal_with_request(envelope);
          - Node returns account + merkle_proof;
          - verify the Merkle proof via verify_account_merkle_proof;
          - if verification passes, write chain-state fields into Dict_of_accts
            and return the Account object.

        Important points:

          - For an account that already exists locally: only update chain-state
            fields; never overwrite or create a new Account object for it.
          - Never change local ECC keypair SK/PK or addr using Node data.
          - Merkle proof is verified using a temporary Account constructed from
            Node output.
          - If no local Account exists, a new Account is created with SK/PK kept
            as None, because the client does not trust Node for private keys.
        """
        print("\n[CLIENT][GetAccountInfo] start querying account info from Node...")
        print("[CLIENT][GetAccountInfo] addr =", addr_hex)

        envelope = {
            "application_type": "GetAccountInfo",
            "payload": {
                "addr": addr_hex
            }
        }

        resp = node.deal_with_request(envelope)

        if not isinstance(resp, dict):
            print("[CLIENT][GetAccountInfo][ERROR] Node response is not a dict.")
            return None

        if "found" in resp and resp["found"] is False:
            print("[CLIENT][GetAccountInfo] Node returns found=False (account not on chain). Returning None without touching local dict.")
            return None

        if "ok" not in resp:
            print("[CLIENT][GetAccountInfo][ERROR] Node response missing 'ok' flag.")
            return None

        if not resp["ok"]:
            err_msg = "unknown error"
            if "err" in resp:
                err_msg = resp["err"]
            if isinstance(err_msg, str) and err_msg.lower() == "account not found":
                print("[CLIENT][GetAccountInfo] Node reports account not found on chain. Returning None.")
                return None
            else:
                print("[CLIENT][GetAccountInfo][ERROR] Node returns error:", err_msg)
                return None

        if "account" not in resp or "merkle_proof" not in resp:
            print("[CLIENT][GetAccountInfo][ERROR] Node response missing account or merkle_proof.")
            return None

        acc_data = resp["account"]
        proof_data = resp["merkle_proof"]

        # ===== build a temporary Account purely from Node data, for Merkle verification =====
        tmp_acct = Account()
        tmp_acct.initialize_to_blockchain_default()

        if "addr" in acc_data:
            tmp_acct.addr = acc_data["addr"]
        else:
            tmp_acct.addr = addr_hex

        if "balance" in acc_data:
            tmp_acct.balance = acc_data["balance"]
        else:
            tmp_acct.balance = 0

        if "nonce" in acc_data:
            tmp_acct.nonce = acc_data["nonce"]
        else:
            tmp_acct.nonce = 0

        idcard_data = {}
        if "IDCard" in acc_data:
            idcard_data = acc_data["IDCard"]
        elif "idcard" in acc_data:
            idcard_data = acc_data["idcard"]

        if isinstance(idcard_data, dict):
            if "Color" in idcard_data or "ID" in idcard_data:
                if "Color" in idcard_data:
                    tmp_acct.IDCard["Color"] = idcard_data["Color"]
                if "ID" in idcard_data:
                    tmp_acct.IDCard["ID"] = idcard_data["ID"]
            else:
                if "color" in idcard_data:
                    tmp_acct.IDCard["Color"] = idcard_data["color"]
                if "id" in idcard_data:
                    tmp_acct.IDCard["ID"] = idcard_data["id"]

        if "lst_of_commits" in acc_data and isinstance(acc_data["lst_of_commits"], list):
            tmp_acct.lst_of_commits = list(acc_data["lst_of_commits"])
        else:
            tmp_acct.lst_of_commits = []

        pk_hex = None
        if "pk" in acc_data:
            pk_hex = acc_data["pk"]
        elif "pk_hex" in acc_data:
            pk_hex = acc_data["pk_hex"]
        elif "public_key" in acc_data:
            pk_hex = acc_data["public_key"]

        if pk_hex:
            tmp_acct.ecc_keypair.pk = pk_hex

        siblings = []
        if "siblings" in proof_data and isinstance(proof_data["siblings"], list):
            siblings = proof_data["siblings"]

        account_root = None
        if "account_root" in proof_data:
            account_root = proof_data["account_root"]

        print("[CLIENT][GetAccountInfo] account info and Merkle proof received from Node, verifying locally...")

        ok = verify_account_merkle_proof(tmp_acct, siblings, account_root)

        if not ok:
            print("[CLIENT][GetAccountInfo][ERROR] Merkle proof verification failed; refusing to write to local dict.")
            return None

        print("[CLIENT][GetAccountInfo] Merkle proof verified, updating local Dict_of_accts with chain-state fields.")

        if addr_hex in self.Dict_of_accts:
            local_acct = self.Dict_of_accts[addr_hex]

            if local_acct.addr is None:
                local_acct.addr = tmp_acct.addr

            local_acct.balance = tmp_acct.balance
            local_acct.nonce = tmp_acct.nonce
            local_acct.IDCard = tmp_acct.IDCard
            local_acct.lst_of_commits = tmp_acct.lst_of_commits

            self.Dict_of_accts[addr_hex] = local_acct
            return local_acct

        new_acct = Account()
        new_acct.addr = tmp_acct.addr
        new_acct.balance = tmp_acct.balance
        new_acct.nonce = tmp_acct.nonce
        new_acct.IDCard = tmp_acct.IDCard
        new_acct.lst_of_commits = tmp_acct.lst_of_commits

        if hasattr(new_acct.ecc_keypair, "pk"):
            new_acct.ecc_keypair.pk = None
        if hasattr(new_acct.ecc_keypair, "sk"):
            new_acct.ecc_keypair.sk = None

        self.Dict_of_accts[new_acct.addr] = new_acct
        return new_acct

    # ---------------- internal helpers ----------------
    def _derive_new_pk_from_master_and_token(self, master_seed, token_bytes):
        """
        Derive new_sk and new_pk (compressed 32 bytes) from (master_seed, token).
        The scalar is reduced modulo SCALAR_ORDER.
        """
        raw_hex = get_poseidon_hash(master_seed, token_bytes)
        digest_int = int(raw_hex, 16) % SCALAR_ORDER
        new_sk_hex = "%064x" % digest_int
        new_sk_bytes = bytes.fromhex(new_sk_hex)
        kp = pasta_ecc_wrapper.EccKeypair()
        kp.set_sk(new_sk_bytes)
        return kp.get_pk_from_sk()

    def _compute_master_seed_hash_bytes(self, master_seed):
        """
        Compute Poseidon(master_seed) and return the digest as bytes.
        """
        ms_hash_hex = get_poseidon_hash(master_seed)
        return bytes.fromhex(ms_hash_hex)

    def _random_token_in_pallas(self):
        """
        Generate a random token as a 32-byte big-endian integer reduced modulo PALLAS_P.
        """
        import os as _os
        rv = int.from_bytes(_os.urandom(32), "big")
        v = rv % PALLAS_P
        token_bytes = v.to_bytes(32, "big")
        print("[CLIENT] [BlueApply2] random token generated in the Pallas field.")
        return token_bytes

    def _sign_payload_dict(self, payload):
        """
        Sign a payload dict with the internal user identity keypair, returning
        the raw signature as hex string.

        The signed message is:
          digest_bytes = SHA256(canonical_json(payload))

        where canonical_json uses sort_keys=True and compact separators.
        """
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        digest_hex = get_hash(canonical)
        digest_bytes = bytes.fromhex(digest_hex)
        r, s, raw = self._user_keypair_cert.sign(digest_bytes)
        return raw.hex()

    def _sign_payload_dict_with_kp(self, payload, keypair):
        """
        Sign a payload dict with a given keypair (same canonical encoding as _sign_payload_dict).
        """
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        digest_hex = get_hash(canonical)
        digest_bytes = bytes.fromhex(digest_hex)
        r, s, raw = keypair.sign(digest_bytes)
        return raw.hex()

    # ---------------- public API: BlueApply envelopes ----------------
    def apply_for_blue_i(self, acct):
        return build_apply_for_blue_i_envelope(self, acct)

    def apply_for_blue_ii(self, acct, token):
        return build_apply_for_blue_ii_envelope(self, acct, token)

    # ---------------- public API: AcctToAnon envelope ----------------
    def apply_for_acct2anon(self, acct, amount):
        return build_apply_for_acct2anon_envelope(self, acct, amount)

    # ---------------- public API: AnonPay envelope ----------------
    def apply_for_anon_pay(
        self,
        acct,
        commit_root_before_hex,
        to_addr_hex,
        amount,
        value_initial,
        nonce_initial_bytes,
        src_bytes,
        siblings,
        dirs,
    ):
        return build_apply_for_anon_pay_envelope(
            self,
            acct,
            commit_root_before_hex,
            to_addr_hex,
            amount,
            value_initial,
            nonce_initial_bytes,
            src_bytes,
            siblings,
            dirs,
        )

    # ---------------- build Transfer request ----------------
    def build_transfer_request(self, from_addr, to_addr, amount):
        """
        Build a Transfer tx_entry (not sent; returns a dict).

        If from_addr is not present in Dict_of_accts, the request is rejected
        and None is returned.
        """
        if from_addr not in self.Dict_of_accts:
            print("[CLIENT][Transfer] from_addr not found in local wallet; refusing to build transfer.")
            return None

        acct = self.Dict_of_accts[from_addr]

        pk_val = acct.ecc_keypair.pk
        if isinstance(pk_val, (bytes, bytearray)):
            pk_hex = bytes(pk_val).hex()
        else:
            pk_hex = str(pk_val)

        base_nonce = acct.nonce
        if base_nonce is None:
            base_nonce = 0
        payload = {
            "version": 1,
            "from_addr": from_addr,
            "to_addr": to_addr,
            "amount": int(amount),
            "nonce": int(base_nonce) + 1,
            "pk_sender": pk_hex,
        }

        sig_hex = self._sign_payload_dict_with_kp(payload, acct.ecc_keypair)
        payload["signature"] = sig_hex

        tx_entry = {
            "tx_type": "Transfer",
            "payload": payload,
        }

        print(
            "[CLIENT][Transfer] Transfer request built (not sent), from:",
            from_addr[:12],
            "-> to:",
            to_addr[:12],
            "amount:",
            amount,
        )
        return tx_entry

    # ---------------- batch update accounts from Node ----------------
    def update_all_accounts_from_node(self, node):
        addrs = list(self.Dict_of_accts.keys())
        print("[CLIENT] start syncing local accounts with chain state, count:", len(addrs))
        for addr in addrs:
            print("[CLIENT] syncing addr =", addr)
            onchain_acct = self.fetch_account_from_node(node, addr)
            if onchain_acct is None:
                local_acct = self.Dict_of_accts[addr]
                local_acct.initialize_to_blockchain_default()
                self.Dict_of_accts[addr] = local_acct
                print("[CLIENT] Node did not return on-chain data; local account reset to chain default. addr =", addr)
            else:
                print("[CLIENT] local account updated with on-chain data. addr =", addr)
