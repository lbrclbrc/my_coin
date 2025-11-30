Client ↔ Node Protocol  Apply for NewBlueACCT

Scope
- Client request formats for BlueApply1 and BlueApply2.
- Node response formats for these requests.
- No Node-side processing rules here.

Common JSON rules
- Envelope always has two keys:
  { "application_type": string, "payload": dict }
- All hex fields are JSON strings:
  lowercase hex, no "0x" prefix.
- version and nonce are JSON integers.
- payload never includes addr.

Type aliases used below
- Hex32        string hex for 32 bytes, 64 chars.
- PKHex32      Hex32 compressed Pallas public key.
- SigHex64     string hex for 64 bytes Schnorr signature.
- ZKProofHex   string hex of bytes from the zk proof generator.

Preconditions on Client
- Client has MASTER_SEED already set.
- Client has CERT already set at init.
  CERT keys come from an external issuer and are stored in client.CERT.

1. BlueApply1  first blue account

Request envelope
{
  "application_type": "BlueApply1",
  "payload": {
    "version":              1,
    "master_seed_hash":     Hex32,
    "new_blue_pk":          PKHex32,
    "user_id":              string,
    "clerk_id":             string,
    "cert": {
      "pk":                 PKHex32,
      "id":                 string,
      "signature":          SigHex64
    },
    "nonce":                int,
    "zk_proof":             ZKProofHex,
    "applier_envelope_sig": SigHex64,
    "clerk_envelope_sig":   SigHex64
  }
}

How Client fills each field
- version  
  constant 1.
- token not sent  
  token_bytes = 32-byte zero.
- new_blue_pk  
  new_pk_bytes = DeriveNewPK(master_seed, token_bytes)  
  new_blue_pk = new_pk_bytes.hex()  
  DeriveNewPK uses a client-internal function that calls get_poseidon_hash.
- derived addr not sent  
  derived_addr = get_poseidon_hash(new_blue_pk)  
  used only for local nonce lookup.
- nonce  
  if derived_addr in client.Dict_of_accts:  
    nonce = cached_acct.nonce + 1  
  else:  
    nonce = 0 + 1  
  BlueApply1 does not implicitly query the Node for nonce.
- master_seed_hash  
  ms_hash_hex = get_poseidon_hash([master_seed])  
  master_seed_hash = ms_hash_hex.
- user_id  
  user_id = client.CERT["id"].
- clerk_id  
  clerk_id = client.CERT["clerk_id"].
- cert  
  cert = client.CERT; cert.pk, cert.id, cert.signature are copied as-is.
- zk_proof  
  proof_hex = get_zkproof_for_ii_blue_apply(
    master_seed,
    token_bytes,
    new_pk_bytes,
    bytes.fromhex(master_seed_hash),
  )  
  zk_proof = proof_hex.
- applier_envelope_sig  
  applier_envelope_sig = SignCanonicalPayload(payload, client user cert keypair).
- clerk_envelope_sig  
  clerk_envelope_sig = SignCanonicalPayload(payload, client.clerk_keypair).

Canonical payload signing used by both sigs
- Start from payload without the two sig fields.
- canonical_bytes = json.dumps(
    payload_no_sigs,
    sort_keys=True,
    separators=(",", ":"),
  ).encode()
- digest_bytes = bytes.fromhex(get_hash(canonical_bytes))
- SigHex64 = SchnorrSign(sk, digest_bytes).raw.hex()

Expected Node response

Success
{
  "ok": True,
  "new_block": {
    "account_root": Hex32,
    "tx_root":      Hex32,
    "commit_root":  Hex32,
    "applied_addr": Hex32,
    "tx": {
      "tx_type": "BlueApply1",
      "payload": dict,
      "leaf":    Hex32
    }
  }
}

Note: new_block may truncate long hex strings for display.

Failure
{
  "ok":  False,
  "err": string
}

2. BlueApply2  non-first blue account

Request envelope
{
  "application_type": "BlueApply2",
  "payload": {
    "version":          1,
    "master_seed_hash": Hex32,
    "new_blue_pk":      PKHex32,
    "token":            Hex32,
    "nonce":            int,
    "zk_proof":         ZKProofHex
  }
}

How Client fills each field
- version  
  constant 1.
- token  
  if token is None:  
    token_bytes = RandomTokenInPallasField()  
  if token is int:  
    token_bytes = (token mod PALLAS_P).to_bytes(32, "big")  
  if token is hex string:  
    token_bytes = (int(token_hex, 16) mod PALLAS_P).to_bytes(32, "big")  
  token = token_bytes.hex().
- new_blue_pk  
  new_pk_bytes = DeriveNewPK(master_seed, token_bytes)  
  new_blue_pk = new_pk_bytes.hex().
- derived addr not sent  
  derived_addr = get_poseidon_hash(new_blue_pk).
- nonce  
  if derived_addr in client.Dict_of_accts:  
    nonce = cached_acct.nonce + 1  
  else:  
    nonce = 0 + 1  
  BlueApply2 does not implicitly query the Node for nonce.
- master_seed_hash  
  master_seed_hash = get_poseidon_hash([master_seed]).
- zk_proof  
  zk_proof = get_zkproof_for_ii_blue_apply(
    master_seed,
    token_bytes,
    new_pk_bytes,
    bytes.fromhex(master_seed_hash),
  ).

Expected Node response

Success
{
  "ok": True,
  "new_block": {
    "account_root": Hex32,
    "tx_root":      Hex32,
    "commit_root":  Hex32,
    "applied_addr": Hex32,
    "tx": {
      "tx_type": "BlueApply2",
      "payload": dict,
      "leaf":    Hex32
    }
  }
}

Failure
{
  "ok":  False,
  "err": string
}

End
