blockchain_header_specs.md

Scope
- This document specifies:
  (a) the full Block data structure (for context),
  (b) the consensus header fields,
  (c) canonical header encoding,
  (d) block_hash and chain hashing/validation rules.
- Transaction list (lst_of_txs) semantics, formats, and validity rules are out of scope here.
  They are committed by tx_root and specified in the transaction specs.

Notation
- Hex32:
    a 32-byte value encoded as a lowercase hex string
    length = 64 hex characters
    no "0x" prefix
- get_hash(x):
    the project’s canonical hash function implemented in tools.get_hash
    algorithm = SHA-256
    input = raw bytes x
    output = Hex32 (lowercase hex of 32-byte digest)

Whole Block Structure (Context)

A Block is a dictionary-like object with these fields:

block := {
  "height": height,
  "previous_block_hash": previous_block_hash,
  "block_hash": block_hash,
  "account_root": account_root,
  "tx_root": tx_root,
  "commit_root": commit_root,
  "lst_of_txs": lst_of_txs
}

Consensus header fields are:
  height
  previous_block_hash
  account_root
  tx_root
  commit_root
The remaining fields are non-header:
  block_hash (derived from header)
  lst_of_txs (committed by tx_root, specified elsewhere)

Header Fields (Consensus)

1) height
- Meaning: block height (position in the chain).
- Type: non-negative integer.
- Rule: in a valid chain, height equals the block’s index in the chain list.
  Genesis block has height = 0.

2) previous_block_hash
- Meaning: hash of the previous block’s header.
- Type: Hex32.
- Rule:
    if height == 0:
        previous_block_hash = "0"*64
    else:
        previous_block_hash = chain[height-1].block_hash

3) account_root
- Meaning: Merkle root of the account state tree after applying this block.
- Type: Hex32.
- Notes: account tree and hashing rules are specified in the account/merkle specs.

4) tx_root
- Meaning: Merkle root committing to the ordered transaction list of this block.
- Type: Hex32.
- Notes: tx list format and Merkle rules are specified in the transaction specs.

5) commit_root
- Meaning: Merkle root of the global note/commitment tree after applying this block.
- Type: Hex32.
- Notes: commitment tree rules are specified in the anonymous-pool specs.

Canonical Header Encoding

To compute block_hash, first construct a JSON object with exactly these keys
and exactly these values:

header := {
  "height": height,
  "previous_block_hash": previous_block_hash,
  "account_root": account_root,
  "tx_root": tx_root,
  "commit_root": commit_root
}

Then serialize canonically:

canonical_header_string :=
  json.dumps(
    header,
    sort_keys = True,
    separators = (",", ":")
  )

canonical_header_bytes :=
  canonical_header_string encoded as UTF-8 bytes

Important:
- Only the five header keys above are included.
- block_hash itself is not included in header when hashing.
- lst_of_txs is not included here (it is committed by tx_root).

Block Hash Computation

block_hash := get_hash(canonical_header_bytes)

Expanded meaning of this call:
- Input to get_hash is exactly one byte string:
    canonical_header_bytes
- The header bytes already include all header fields,
  ordered by JSON key sorting (sort_keys=True).
- Output is a 32-byte SHA-256 digest rendered as Hex32.

Block Validity Rules (Header Level)

Given a block B at height h:

1) Height rule
    B.height == h

2) Previous hash rule
    if h == 0:
        B.previous_block_hash == "0"*64
    else:
        B.previous_block_hash == chain[h-1].block_hash

3) Block hash rule
    recompute canonical_header_bytes from B’s header fields
    recomputed_hash := get_hash(canonical_header_bytes)
    B.block_hash must equal recomputed_hash

4) Root formatting rule
    account_root, tx_root, commit_root must each be valid Hex32 strings

Chain Validity Rules (Header Level)

A chain is header-valid iff:

- Blocks are ordered by height starting from 0 with no gaps.
- Every block satisfies the Block Validity Rules above.
- For all h > 0:
    chain[h].previous_block_hash == chain[h-1].block_hash

Non-Header Fields

- lst_of_txs exists in every block as a list of transaction objects.
- lst_of_txs is not hashed directly into block_hash.
- Its integrity and ordering are committed by tx_root.
- Detailed transaction formats and validity checks are defined in the transaction specs.

End.

