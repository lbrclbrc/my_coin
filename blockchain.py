# blockchain.py

import os
import json

from tools import get_hash


class Block:
    """
    A minimal block structure for a simple one-way chain.

    Fields:
      - height: int, block height (set by Blockchain.append_block)
      - previous_block_hash: hex string of the previous block's hash
      - block_hash: hex string of this block's hash
      - account_root: hex string of account Merkle root
      - tx_root: hex string of transaction Merkle root
      - commit_root: hex string of note/commit Merkle root
      - lst_of_txs: list[dict], transactions included in this block
    """

    def __init__(self, account_root, tx_root, commit_root, lst_of_txs):
        # Filled by Blockchain
        self.height = None
        self.previous_block_hash = None
        self.block_hash = None

        # Passed in when creating a block
        self.account_root = account_root
        self.tx_root = tx_root
        self.commit_root = commit_root

        self.lst_of_txs = lst_of_txs

    def _compute_block_header_hash(self):
        """
        Compute the hash of the block header only.
        Use tools.get_hash(canonical_header_bytes) to derive block_hash.
        """
        header = {
            "height": self.height,
            "previous_block_hash": self.previous_block_hash,
            "account_root": self.account_root,
            "tx_root": self.tx_root,
            "commit_root": self.commit_root,
        }
        canonical = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
        sha_hex = get_hash(canonical)
        return sha_hex

    def to_dict(self):
        """
        Convert the block into a plain dictionary for printing or serialization.
        """
        return {
            "height": self.height,
            "previous_block_hash": self.previous_block_hash,
            "block_hash": self.block_hash,
            "account_root": self.account_root,
            "tx_root": self.tx_root,
            "commit_root": self.commit_root,
            "lst_of_txs": self.lst_of_txs,
        }


class Blockchain:
    """
    A minimal one-way blockchain:
    - lst_of_blocks: [Block, Block, ...]
    - dict_block_by_hash: block_hash -> Block
    """

    def __init__(self):
        self.lst_of_blocks = []
        self.dict_block_by_hash = {}
        print("[BLOCKCHAIN] New empty blockchain created.")

    # ---------------- Internal utilities ----------------
    def _get_prev_hash_for_new_block(self):
        """
        Return the previous_block_hash for a new block.
        If the chain is empty, return 64 zeros.
        Otherwise return the last block's block_hash.
        """
        if len(self.lst_of_blocks) == 0:
            return "0" * 64
        return self.lst_of_blocks[-1].block_hash

    # ---------------- Public interface ----------------
    def append_block(self, block):
        """
        Append a new block to the chain:
        - Set height / previous_block_hash / block_hash
        - Add block into lst_of_blocks and dict_block_by_hash
        """
        height = len(self.lst_of_blocks)
        previous_block_hash = self._get_prev_hash_for_new_block()

        block.height = height
        block.previous_block_hash = previous_block_hash
        block.block_hash = block._compute_block_header_hash()

        self.lst_of_blocks.append(block)
        self.dict_block_by_hash[block.block_hash] = block

        print(
            "[BLOCKCHAIN] append_block: height =",
            block.height,
            ", block_hash =",
            block.block_hash[:16],
            "..."
        )

        return block

    def get_newest_block(self):
        """
        Return the newest block, or None if chain is empty.
        """
        if len(self.lst_of_blocks) == 0:
            return None
        return self.lst_of_blocks[-1]

    def get_block_by_height(self, height):
        """
        Return block by height, or None if out of range.
        """
        if height < 0 or height >= len(self.lst_of_blocks):
            return None
        return self.lst_of_blocks[height]

    def get_block_by_hash(self, block_hash_hex):
        """
        Return block by block_hash, or None if not found.
        """
        if block_hash_hex in self.dict_block_by_hash:
            return self.dict_block_by_hash[block_hash_hex]
        return None

    def verify_chain(self):
        """
        Verify the entire chain:
          - block.height matches its index
          - previous_block_hash matches the block before it
          - block_hash matches recomputed header hash
        """
        print("[BLOCKCHAIN] Verifying entire chain...")

        i = 0
        while i < len(self.lst_of_blocks):
            blk = self.lst_of_blocks[i]

            # height check
            if blk.height != i:
                print("[BLOCKCHAIN][ERROR] Height mismatch: index =", i, "block.height =", blk.height)
                return False

            # previous_block_hash check
            if i == 0:
                expected_prev = "0" * 64
            else:
                expected_prev = self.lst_of_blocks[i - 1].block_hash

            if blk.previous_block_hash != expected_prev:
                print(
                    "[BLOCKCHAIN][ERROR] previous_block_hash mismatch: index =",
                    i,
                    "expected_prev =",
                    expected_prev,
                    "got =",
                    blk.previous_block_hash,
                )
                return False

            # block_hash check
            recomputed = blk._compute_block_header_hash()
            if blk.block_hash != recomputed:
                print(
                    "[BLOCKCHAIN][ERROR] block_hash mismatch: index =",
                    i,
                    "stored =",
                    blk.block_hash,
                    "recomputed =",
                    recomputed,
                )
                return False

            i += 1

        print("[BLOCKCHAIN] Chain verification passed.")
        return True

    def __str__(self):
        """
        Return a short overview string of the blockchain.
        Full block details are written by dump_to_file().
        """
        lines = []
        lines.append("=== Blockchain Overview ===")
        lines.append("number_of_blocks: %d" % len(self.lst_of_blocks))

        is_valid = self.verify_chain()
        lines.append("verify_chain: %s" % ("OK" if is_valid else "FAIL"))
        lines.append("")
        lines.append("(Full block details written to current_blockchain.txt)")

        return "\n".join(lines)

    def dump_to_file(self, filepath=None, reverse=False):
        """
        Write the entire chain into a readable txt file:
          - Default file name: current_blockchain.txt (same dir as blockchain.py)
          - Each block is written with a '=== Block <height> ===' header
          - reverse=False => from oldest to newest
          - reverse=True  => from newest to oldest
          - File is overwritten each time
        """
        if filepath is None:
            base_dir = os.path.dirname(__file__)
            filepath = os.path.join(base_dir, "current_blockchain.txt")

        # Keep verify_chain output as-is
        self.verify_chain()

        blocks = self.lst_of_blocks[:]  # shallow copy
        if reverse:
            blocks = list(reversed(blocks))

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                header = {
                    "description": "Blockchain dump - one block per section",
                    "num_blocks": len(self.lst_of_blocks),
                    "order": "newest->oldest" if reverse else "oldest->newest"
                }
                f.write("# Blockchain dump\n")
                f.write("# Summary: " + json.dumps(header, ensure_ascii=False) + "\n\n")

                for blk in blocks:
                    blk_dict = blk.to_dict()
                    title = "=== Block %d ===\n" % blk_dict.get("height", -1)
                    f.write(title)
                    json_text = json.dumps(blk_dict, indent=2, sort_keys=True, ensure_ascii=False)
                    f.write(json_text)
                    f.write("\n\n")

            print("[BLOCKCHAIN] Blockchain written to file:", filepath)
        except Exception as e:
            print("[BLOCKCHAIN][ERROR] Failed to write file:", e)
