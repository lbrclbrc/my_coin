Client ↔ Node Protocol  Regular Transfer

Scope
- Wire format for a normal transparent Transfer.
- No commitments no notes no ZK.

0. JSON value types
- Hex32 PKHex32 SigHex64 are JSON strings.
- version nonce amount are JSON integers.

Canonical encodings
- Hex32
  string hex for 32 bytes 64 chars lowercase no 0x
- PKHex32
  Hex32 compressed Pallas public key
- SigHex64
  string hex for 64 bytes Schnorr raw signature

1. Request envelope
{
  "application_type" string
  "payload" dict
}

2. Transfer request

Request envelope
{
  "application_type" "Transfer"
  "payload" {
    "version"   1
    "from_addr" Hex32
    "to_addr"   Hex32
    "amount"    int
    "nonce"     int
    "pk_sender" PKHex32
    "signature" SigHex64
  }
}

How Client fills payload
- version
  constant 1
- from_addr
  chosen sender address in local wallet
  must exist in client.Dict_of_accts
- to_addr
  destination address hex32
  client does not restrict the destination
- amount
  positive integer chosen by user
- pk_sender
  sender acct public key in hex
  pk_bytes = acct.ecc_keypair.pk or acct.ecc_keypair.get_pk_from_sk()
  pk_sender = pk_bytes.hex()
- nonce
  base_nonce = acct.nonce if present else 0
  nonce = base_nonce + 1
  client uses local cached nonce only
- signature
  sender Schnorr signature over canonical payload without signature field
  signature = SignCanonicalPayload(payload_no_sig, acct.ecc_keypair).raw.hex()

Canonical payload signing for Transfer
- payload_no_sig
  payload without key "signature"
- canonical_bytes
  json.dumps(payload_no_sig, sort_keys True, separators (",", ":")).encode()
- digest_bytes
  bytes.fromhex(get_hash(canonical_bytes))
- signature
  SchnorrSign(sender_sk, digest_bytes) raw 64 bytes then hex

Notes for Client
- If from_addr not in local wallet client should not build the request.
- payload is sent as-is inside the envelope.

3. Node response

Success
{
  "ok" True
  "new_block" {
    "account_root" Hex32
    "tx_root"      Hex32
    "commit_root"  Hex32
    "applied_addr" Hex32
    "from_addr"    Hex32
    "to_addr"      Hex32
    "tx" {
      "tx_type" "Transfer"
      "payload" dict
    }
  }
}

Failure
{
  "ok"  False
  "err" string
}

Client handling rule
- If ok False log err and treat the transfer as not accepted.
