acct_to_anon_in_blocks_v1

Scope
- Specify the v1 "AcctToAnon" transaction format allowed inside lst_of_txs.
- Header hashing and tx_root Merkle rules are specified elsewhere.

Notation
- Hex32 := string, lowercase hex, length 64, no "0x", representing exactly 32 bytes.
- HexField := string, lowercase hex, even length, no "0x".
- int := JSON number interpreted as non-negative integer unless stated otherwise.
- get_poseidon_hash(...) := project Poseidon hash wrapper.
- get_zkproof_for_acct_to_anon_tx / verify_zkproof_for_acct_to_anon_tx := internal HALO2 APIs.

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

tx_type = "AcctToAnon"

Purpose
- Move a public account balance amount into the anonymous commitment pool.
- Amount is public; resulting commitment is public; ownership is proven by ZK.

payload = {
  "version": 1,

  "from_addr": Hex32,
  "amount":    int,

  "anon_commit": Hex32,
  "zk_proof":   HexField
}

Field meaning
- anon_commit  
  Poseidon(amount_bytes, sender_sk_bytes, nonce_bytes, from_addr_bytes)  
  produced by Client and verified by ZK.
- zk_proof  
  proof bytes from get_zkproof_for_acct_to_anon_tx(...), hex encoded.

Consensus checks (summary)
- Required keys exist and types match; version == 1.
- amount is a positive integer in the FieldIntNonNeg range  
  (1 ≤ amount ≤ 2^96 − 1, matching node-side checks).
- verify_zkproof_for_acct_to_anon_tx(zk_proof, amount, nonce, from_addr, anon_commit) must pass,
  where nonce is the sender account nonce at apply time plus 1 (encoded as required by the verifier).

End
