get_account_info_specs_v1

Scope
- Defines the public GetAccountInfo request/response between Client and Node.
- Behavior follows node/handle_get_acct_info.py.

Types
- Hex32 = string, lowercase hex, length 64, no "0x".
- int   = JSON integer.
- bool  = JSON true/false.
- siblings_proof = [ (Hex32, "L" or "R"), ... ] ordered from leaf level upward.

Request (Client → Node)
request = {
  "application_type": "GetAccountInfo",
  "payload": {
    "addr": Hex32
  }
}

Node rules
1) Payload must contain an "addr" field.
   If the "addr" field is missing:
   response = { "ok": false, "err": string }

2) Lookup:
   acct = node.get_account(payload.addr)

3) If acct not found in node state:
   response = {
     "ok": true,
     "found": false,
     "account_root": Hex32 or None
   }
   (This is NOT an error in v1.)

4) If acct found:
   Node returns ok=true with:
   - account: public account snapshot
   - merkle_proof: proof against current account_root

Success response (found)
response_found = {
  "ok": true,
  "account": {
    "addr": Hex32,
    "balance": int,
    "nonce": int,
    "IDCard": { "Color": int, "ID": int },
    "lst_of_commits": [ Hex32, ... ],
    "pk": Hex32
  },
  "merkle_proof": {
    "siblings": siblings_proof,
    "account_root": Hex32 or None
  }
}

Field filling conventions (Node-side, for response_found)
- pk:
  if acct.ecc_keypair.pk is None => "0"*64
  else pk is bytes-like => pk.hex()
  else pk is string => lowercase hex with any leading "0x" removed
- balance:
  if acct.balance is None => 0
- nonce:
  if acct.nonce is None => 0
- IDCard:
  if missing / None => Color=0, ID=0
- lst_of_commits:
  if None => []

Success response (not found)
response_not_found = {
  "ok": true,
  "found": false,
  "account_root": Hex32 or None
}

Error response
response_error = {
  "ok": false,
  "err": string
}

Client minimal expectations
- If ok=true and found=false:
  treat as "not on chain"; do not auto-create on-chain state.
- If ok=true and account exists:
  client may verify merkle_proof under Poseidon Merkle rules,
  then update local cache if verification passes.
- If ok=false:
  do not update local cache.
