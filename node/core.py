# ================================
# node/core.py
# Core node implementation and request dispatching.
# Includes support for:
#   - BlueApply1 / BlueApply2
#   - GetAccountInfo
#   - Transfer
#   - AcctToAnon
#   - AnonPay
# ================================

from wrappers.poseidon_hash_wrapper import get_poseidon_hash
from wrappers.pasta_ecc_wrapper import EccKeypair

from tools import turn_hex_str_to_bytes, short_hex, CA_PK_HEX, CLERK_PK_HEX
from merkle_tree import MerkleTree, MerkleTreeCommit
from blockchain import Blockchain, Block

from .handle_get_acct_info import handle_get_account_info
from .handle_blue_applies import handle_blue_apply_type1, handle_blue_apply_type2
from .handle_transfer_apply import handle_transfer
from .handle_acct2anon_apply import handle_acct2anon
from .handle_anon_pay_apply import handle_anon_pay


class Node:
    """
    Node holds on-chain state for:
      - accounts and their Merkle tree,
      - transactions and their Merkle tree,
      - anonymous commitments and their Merkle tree,
      - nullifier set for anonymous pool,
      - mapping from master_seed_hash to user ID,
      - an internal blockchain of committed blocks.

    Requests are received as envelopes with an application_type and payload,
    and dispatched to dedicated handlers. State-changing handlers will return
    a new_block that is committed into the internal blockchain.
    """

    def __init__(self):
        print("[NODE] Initializing Node instance...")

        # Accounts
        self.account_map = {}
        self.list_of_accounts = []
        self.account_tree = MerkleTree()

        # Transactions
        self.list_of_tx = []
        self.tx_tree = MerkleTree()

        # Anonymous commitments
        self.list_of_note_commitments = []
        self.node_commitment_tree = MerkleTreeCommit()

        # Nullifiers for anonymous pool
        self.nullifier_set = set()

        # CA public key
        self.ca_keypair = EccKeypair()
        try:
            ca_pk_bytes = turn_hex_str_to_bytes(CA_PK_HEX)
            self.ca_keypair.set_pk(ca_pk_bytes)
            print("[NODE] CA public key has been set.")
        except Exception as e:
            print("[NODE][ERROR] Failed to initialize CA public key, check CA_PK_HEX:", e)

        # Clerk public key
        self.clerk_keypair = EccKeypair()
        try:
            clerk_pk_bytes = turn_hex_str_to_bytes(CLERK_PK_HEX)
            self.clerk_keypair.set_pk(clerk_pk_bytes)
            print("[NODE] Clerk public key has been set.")
        except Exception as e:
            print("[NODE][ERROR] Failed to initialize Clerk public key, check CLERK_PK_HEX:", e)

        # master_seed_hash -> user_id mapping
        self.ms_hash_to_id = {}

        # Internal blockchain
        self.blockchain = Blockchain()

        print("[NODE] Node initialization finished.")

    # -----------------------------------------------------------
    # Account operations
    # -----------------------------------------------------------
    def _add_account(self, acct):
        """
        Insert or update an account in the node state and update the account Merkle tree.
        Returns the account address (hex string).
        """
        addr_hex = acct.addr
        if not isinstance(addr_hex, str):
            raise TypeError("acct.addr must be a string")

        print("[NODE] _add_account called, addr =", addr_hex)

        if addr_hex in self.account_map:
            print("[NODE] Existing account found, updating entry.")
            self.account_map[addr_hex] = acct

            i = 0
            while i < len(self.list_of_accounts):
                a_addr = self.list_of_accounts[i].addr
                if a_addr == addr_hex:
                    self.list_of_accounts[i] = acct
                    self.account_tree.update(i, acct.get_self_poseidon_hash())
                    print("[NODE] Account list and Merkle tree updated (existing account).")
                    return addr_hex
                i += 1

        print("[NODE] New account, appending to list and Merkle tree.")
        self.account_map[addr_hex] = acct
        self.list_of_accounts.append(acct)
        self.account_tree.append(acct.get_self_poseidon_hash())
        print("[NODE] New account added, total accounts =", len(self.list_of_accounts))
        return addr_hex

    def update_account(self, addr_hex, acct):
        """
        Update an existing account by address and refresh the Merkle tree leaf.
        """
        if not isinstance(addr_hex, str):
            raise TypeError("addr_hex must be a string")

        print("[NODE] update_account called, addr =", addr_hex)

        self.account_map[addr_hex] = acct

        i = 0
        while i < len(self.list_of_accounts):
            a_addr = self.list_of_accounts[i].addr
            if a_addr == addr_hex:
                self.list_of_accounts[i] = acct
                self.account_tree.update(i, acct.get_self_poseidon_hash())
                print("[NODE] Account list and Merkle tree updated (update_account).")
                return
            i += 1
        print("[NODE][WARN] update_account did not find addr in list_of_accounts.")

    def get_account(self, addr_hex):
        """
        Look up an account by address in the local account map.
        """
        if not isinstance(addr_hex, str):
            raise TypeError("addr_hex must be a string")

        if addr_hex in self.account_map:
            print("[NODE] get_account hit, addr =", addr_hex)
            return self.account_map[addr_hex]
        print("[NODE] get_account miss, addr =", addr_hex)
        return None

    # -----------------------------------------------------------
    # Transaction and commitment operations
    # -----------------------------------------------------------
    def append_tx(self, tx):
        """
        Append a transaction to the in-memory buffer and update the tx Merkle tree.
        """
        print("[NODE] append_tx called.")
        dump_bytes = str(tx).encode()
        leaf_bytes = get_poseidon_hash(dump_bytes)
        tx["leaf"] = leaf_bytes
        print("[NODE]   leaf =", short_hex(leaf_bytes))

        self.list_of_tx.append(tx)
        self.tx_tree.append(leaf_bytes)
        print("[NODE]   tx appended to buffer, total tx count =", len(self.list_of_tx))
        print("[NODE]   current tx_root =", short_hex(self.tx_tree.root()))

    def append_commit(self, commit_hex):
        """
        Append an anonymous commitment and update the commitment Merkle tree.
        """
        if not isinstance(commit_hex, str):
            raise TypeError("commit_hex must be a string")
        c = commit_hex.strip()
        print("[NODE] append_commit called =", short_hex(c))
        self.list_of_note_commitments.append(c)
        self.node_commitment_tree.append(c)
        print("[NODE]   commit_root =", short_hex(self.node_commitment_tree.root()))

    # -----------------------------------------------------------
    # Commit a new block into the internal blockchain
    # -----------------------------------------------------------
    def _commit_new_block(self, blk_dict):
        """
        Convert a block dict into a Block object and append it to the internal blockchain.
        """
        print("[NODE] Committing new_block into Node.blockchain...")

        blk = Block(
            account_root=blk_dict["account_root"],
            tx_root=blk_dict["tx_root"],
            commit_root=blk_dict["commit_root"],
            lst_of_txs=[blk_dict["tx"]],
        )

        self.blockchain.append_block(blk)
        self.blockchain.dump_to_file()

        print("[NODE] new_block committed, current_blockchain.txt updated.")

    # -----------------------------------------------------------
    # Helper to dispatch handlers and commit blocks when appropriate
    # -----------------------------------------------------------
    def _dispatch_and_commit_if_ok(self, handler, payload):
        """
        Call a handler, and commit new_block if the handler returns {"ok": True, "new_block": {...}}.
        """
        res = handler(payload)
        if isinstance(res, dict):
            if "ok" in res and res["ok"]:
                if "new_block" in res:
                    self._commit_new_block(res["new_block"])
        return res

    # -----------------------------------------------------------
    # Request dispatcher
    # -----------------------------------------------------------
    def deal_with_request(self, envelope):
        """
        Dispatch an incoming request envelope based on application_type.
        """
        app_type = envelope["application_type"]
        payload = envelope["payload"]

        print("\n[NODE] New request received, application_type =", app_type)

        if app_type == "BlueApply1":
            return self._dispatch_and_commit_if_ok(self._handle_blue_apply_type1, payload)

        if app_type == "BlueApply2":
            return self._dispatch_and_commit_if_ok(self._handle_blue_apply_type2, payload)

        if app_type == "GetAccountInfo":
            return self._handle_get_account_info(payload)

        if app_type == "Transfer":
            return self._dispatch_and_commit_if_ok(self._handle_transfer, payload)

        if app_type == "AcctToAnon":
            return self._dispatch_and_commit_if_ok(self._handle_acct2anon, payload)

        if app_type == "AnonPay":
            return self._dispatch_and_commit_if_ok(self._handle_anon_pay, payload)

        print("[NODE][ERROR] Unknown application_type:", app_type)
        return {"ok": False, "err": "unknown application_type"}

    # -----------------------------------------------------------
    # Delegate handlers
    # -----------------------------------------------------------
    def _handle_get_account_info(self, payload):
        return handle_get_account_info(self, payload)

    def _handle_blue_apply_type1(self, payload):
        return handle_blue_apply_type1(self, payload)

    def _handle_blue_apply_type2(self, payload):
        return handle_blue_apply_type2(self, payload)

    def _handle_transfer(self, payload):
        return handle_transfer(self, payload)

    def _handle_acct2anon(self, payload):
        return handle_acct2anon(self, payload)

    def _handle_anon_pay(self, payload):
        return handle_anon_pay(self, payload)
