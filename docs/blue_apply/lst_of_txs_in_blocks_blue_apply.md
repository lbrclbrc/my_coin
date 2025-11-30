lst_of_txs_in_blocks_blue_apply_v1

Scope
- Specify the in-block transaction list lst_of_txs, restricted to BlueApply transactions.
- This document defines only v1 BlueApply formats allowed inside blocks.
- Validation semantics (nonce, signatures, zk proofs, registrations, token range, state updates) are specified in their dedicated specs.

Notation
- Hex32 := string, lowercase hex, length 64, no "0x", representing exactly 32 bytes.
- HexField := string, lowercase hex, even length, no "0x". Exact byte-length is field-specific.
- int := JSON number interpreted as non-negative integer unless stated otherwise.

Block Transaction List Structure (baseline)
lst_of_txs = [ tx_entry_0, tx_entry_1, ... tx_entry_{n-1} ]

Baseline rules

1. Ordering
- lst_of_txs is an ordered list.
- The order is consensus-relevant because tx_root commits to this ordered list.

2. Entry shape
tx_entry = {
  "tx_type": string,
  "payload": object
}
- Only "tx_type" and "payload" are consensus-defined in v1.
- Any extra top-level keys, if present, are non-consensus and must be ignored.

3. Versioning
- Every payload contains a "version" field.
- This spec accepts version == 1 only.

Supported tx_type values in blocks (v1, BlueApply only)
- "BlueApply1"
- "BlueApply2"

Any other tx_type in this file’s scope is invalid unless a future spec adds it.

Transaction payload formats

tx_type = "BlueApply1"

payload = {
  "version": 1,

  "master_seed_hash": Hex32,
  "new_blue_pk":      Hex32,

  "user_id":          string,
  "clerk_id":         string,

  "cert": {
    "pk":        Hex32,
    "id":        string,
    "signature": HexField
  },

  "nonce": int,

  "applier_envelope_sig": HexField,
  "clerk_envelope_sig":   HexField,

  "zk_proof": HexField
}

tx_type = "BlueApply2"

payload = {
  "version": 1,

  "master_seed_hash": Hex32,
  "new_blue_pk":      Hex32,
  "token":            Hex32,

  "nonce": int,

  "zk_proof": HexField
}

Non-block requests
- "GetAccountInfo" is a request/response API and must not appear in lst_of_txs.

End
