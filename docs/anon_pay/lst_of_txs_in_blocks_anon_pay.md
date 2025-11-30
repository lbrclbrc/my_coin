anon_pay_in_blocks

Scope
- Specify the v1 "AnonPayTx" transaction format allowed inside lst_of_txs.
- Header hashing and tx_root Merkle rules are specified elsewhere.

Notation
- Hex32 := string, lowercase hex, length 64, no "0x", representing exactly 32 bytes.
- HexField := string, lowercase hex, even length, no "0x".
- int := JSON number interpreted as non-negative integer unless stated otherwise.
- get_poseidon_hash(...) := project Poseidon hash wrapper.
- get_zkproof_for_anon_pay / verify_zkproof_for_anon_pay := internal HALO2 APIs.

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

tx_type = "AnonPayTx"

Purpose
- Spend one anonymous note from the commitment pool.
- Pay a public amount to a public account address.
- Optionally create a change note back into the anonymous pool.
- Amount is public; anonymity only hides which note was spent.

payload = {
  "version": 1,

  "to_addr":       Hex32,
  "amount":        int,

  "nullifier":     Hex32,
  "commit_change": Hex32,

  "zk_proof":      HexField
}

Field meaning
- to_addr  
  public account address credited by amount.
- amount  
  public payment value; positive integer in the FieldIntNonNeg range (1 ≤ amount ≤ 2^96 − 1).
- nullifier  
  identifies the spent anonymous note; must be globally unique.
- commit_change  
  Poseidon(value_change_bytes, sender_sk_bytes, ZERO32_bytes, nullifier_bytes)  
  produced by Client and verified by ZK for the remaining change note.
- zk_proof  
  proof bytes from get_zkproof_for_anon_pay(...), hex encoded.

Consensus checks (summary)
- Required keys exist and types match; version == 1.
- amount is a positive integer in the FieldIntNonNeg range (1 ≤ amount ≤ 2^96 − 1, matching node-side checks).
- nullifier has not been used in any previous block.
- verify_zkproof_for_anon_pay(commit_root_before, nullifier, commit_change, amount, zk_proof) must pass,
  where commit_root_before is the anonymous commitment Merkle root at apply time before this transaction.

End
