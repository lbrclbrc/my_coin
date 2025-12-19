# acct.py
# Account class definition 
from wrappers.pasta_ecc_wrapper import EccKeypair
from wrappers.poseidon_hash_wrapper import get_poseidon_hash
from tools import short_hex


class Account:
    """
    Account (MVP version)

    Design notes:
      - Unknown/unsynced fields use None instead of 0 or empty lists.
      - fill_missing() only fills addr based on ECC key; does not modify balance/nonce/IDCard.
      - initialize_to_blockchain_default() sets the account to default chain state:
          nonce=0, balance=0, IDCard={"Color":0,"ID":0}, lst_of_commits=[].
      - get_self_poseidon_hash() assumes required fields are present.
      - add_commit initializes lst_of_commits lazily when first used.
      - debug_print(tag) prints the account state for debugging/demo use.
    """
    
    def __init__(self):
        self.balance = None
        self.lst_of_commits = None
        self.ecc_keypair = EccKeypair()
        self.addr = None
        self.IDCard = {"Color": None, "ID": None}
        self.nonce = None

    def fill_missing(self) -> bool:
        """
        Try to fill addr using local ECC key.
        - If addr exists, return True.
        - If sk exists, derive pk and then derive addr.
        - If sk missing but pk exists, derive addr from pk.
        - If neither exists, return False.
        """
        if self.addr:
            return True

        if hasattr(self.ecc_keypair, "sk") and self.ecc_keypair.sk:
            pk_bytes = self.ecc_keypair.get_pk_from_sk()
            self.ecc_keypair.pk = pk_bytes
            self.addr = get_poseidon_hash(pk_bytes)
            return True

        if hasattr(self.ecc_keypair, "pk") and self.ecc_keypair.pk:
            pk_val = self.ecc_keypair.pk
            if isinstance(pk_val, (bytes, bytearray)):
                pk_bytes = bytes(pk_val)
            else:
                pk_str = str(pk_val).strip()
                pk_bytes = bytes.fromhex(pk_str)
            self.ecc_keypair.pk = pk_bytes
            self.addr = get_poseidon_hash(pk_bytes)
            return True

        return False

    def initialize_to_blockchain_default(self) -> None:
        """
        Initialize account to default chain state:
          - nonce = 0
          - balance = 0
          - IDCard = {"Color":0, "ID":0}
          - lst_of_commits = []
        Does not modify addr or ECC keys.
        """
        if self.nonce is None:
            self.nonce = 0

        if self.balance is None:
            self.balance = 0

        if not isinstance(self.IDCard, dict):
            self.IDCard = {"Color": 0, "ID": 0}
        else:
            if "Color" not in self.IDCard or self.IDCard["Color"] is None:
                self.IDCard["Color"] = 0
            if "ID" not in self.IDCard or self.IDCard["ID"] is None:
                self.IDCard["ID"] = 0

        if self.lst_of_commits is None:
            self.lst_of_commits = []

    def get_self_poseidon_hash(self):
        """
        Build a bytes message from key account fields and compute Poseidon hash.
        Required fields:
          - addr: hex string (32 bytes)
          - IDCard["Color"], IDCard["ID"]: int
          - balance: int
          - lst_of_commits: list of hex strings (optional)
        """
        parts = []

        parts.append(bytes.fromhex(self.addr))
        color = self.IDCard["Color"]
        id_val = self.IDCard["ID"]

        parts.append(color.to_bytes(32, "big"))
        parts.append(id_val.to_bytes(32, "big"))
        parts.append(self.balance.to_bytes(32, "big"))

        if self.lst_of_commits is not None:
            i = 0
            while i < len(self.lst_of_commits):
                cm = self.lst_of_commits[i]
                parts.append(bytes.fromhex(cm))
                i += 1

        msg = b"".join(parts)
        return get_poseidon_hash(msg)

    def add_commit(self, cm_hex):
        """
        Add a commit.
        - cm_hex is treated as hex string; invalid hex raises from bytes.fromhex.
        - If lst_of_commits is None, initialize it to [].
        """
        s = str(cm_hex).strip()
        _ = bytes.fromhex(s)

        if self.lst_of_commits is None:
            self.lst_of_commits = []
        self.lst_of_commits.append(s.lower())

    def list_commits(self):
        """
        Return a copy of the commits list and print each entry.
        If lst_of_commits is None, return [].
        """
        if self.lst_of_commits is None:
            return []

        i = 0
        while i < len(self.lst_of_commits):
            c = self.lst_of_commits[i]
            print(f"[commit {i}] {c}")
            i += 1
        return list(self.lst_of_commits)

    def remove_commit(self, cm_hex):
        """
        Remove all commits equal to cm_hex (case-insensitive).
        If lst_of_commits is None, do nothing.
        """
        if self.lst_of_commits is None:
            return

        s = str(cm_hex).strip()
        _ = bytes.fromhex(s)
        target = s.lower()

        new_list = []
        i = 0
        while i < len(self.lst_of_commits):
            c = self.lst_of_commits[i]
            if c != target:
                new_list.append(c)
            i += 1
        self.lst_of_commits = new_list

    def debug_print(self, tag: str = "[ACCT]") -> None:
        """
        Print the current account state for debug/demo use.
        """
        if self.addr is None:
            addr_s = "None"
        else:
            addr_s = short_hex(self.addr)

        sk_val = None
        pk_val = None

        if hasattr(self.ecc_keypair, "sk"):
            sk_val = self.ecc_keypair.sk
        if hasattr(self.ecc_keypair, "pk"):
            pk_val = self.ecc_keypair.pk

        if sk_val is None:
            sk_s = "None"
        else:
            if isinstance(sk_val, (bytes, bytearray)):
                sk_s = short_hex(bytes(sk_val).hex())
            else:
                sk_s = short_hex(str(sk_val))

        if pk_val is None:
            pk_s = "None"
        else:
            if isinstance(pk_val, (bytes, bytearray)):
                pk_s = short_hex(bytes(pk_val).hex())
            else:
                pk_s = short_hex(str(pk_val))

        nonce_s = self.nonce
        bal_s = self.balance

        color_s = None
        id_s = None

        if isinstance(self.IDCard, dict):
            if "Color" in self.IDCard:
                color_s = self.IDCard["Color"]
            if "ID" in self.IDCard:
                id_s = self.IDCard["ID"]

        if self.lst_of_commits is None:
            commits_cnt = "None"
        else:
            commits_cnt = len(self.lst_of_commits)

        print(tag)
        print(f"  addr         = {addr_s}")
        print(f"  sk           = {sk_s}")
        print(f"  pk           = {pk_s}")
        print(f"  nonce        = {nonce_s}")
        print(f"  balance      = {bal_s}")
        print(f"  Color        = {color_s}")
        print(f"  ID           = {id_s}")
        print(f"  commits_cnt  = {commits_cnt}")
