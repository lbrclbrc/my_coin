transfer_in_blocks_v1

Scope
- Specify the v1 "Transfer" transaction format allowed inside lst_of_txs.
- Block header hashing and tx_root Merkle rules are specified elsewhere.

Notation
- Hex32 = string, lowercase hex, length 64, no "0x", representing exactly 32 bytes.
- HexField = string, lowercase hex, even length, no "0x". Exact byte-length is field-specific.
- int = JSON number interpreted as non-negative integer unless stated otherwise.
- get_hash(x) = SHA-256 over bytes x, output Hex32.
- EccKeypair = project Schnorr(Pallas) ECC wrapper; see its dedicated spec.

Block Transaction List Baseline (applies here)
lst_of_txs = [ tx_entry_0, tx_entry_1, ... tx_entry_{n-1} ]

tx_entry = {
  "tx_type": string,
  "payload": object
}

Baseline rules
- lst_of_txs is ordered; ordering is consensus-relevant via tx_root.
- payload.version must be 1.
- Hex32 and HexField must already be properly formatted; nodes/verifiers must not auto-correct.

Transaction Definition

tx_type = "Transfer"

Purpose
- Transparent transfer between two on-chain addresses.

payload = {
  "version": 1,

  "from_addr": Hex32,
  "to_addr": Hex32,

  "amount": int,
  "nonce": int,

  "pk_sender": Hex32,
  "signature": HexField
}

Consensus checks (summary)
- Required keys exist and types match; version == 1.

End
