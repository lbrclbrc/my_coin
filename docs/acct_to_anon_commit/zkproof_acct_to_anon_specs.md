ZKProof Spec  AcctToAnonTx  Generator and Verifier

Scope
- External API and proved statement for zkproof_for_acct_to_anon_tx.
- Circuit file in zkcrypto/src/.
- Backend uses HALO2.

API names
- generator wrapper
  get_zkproof_for_acct_to_anon_tx
- verifier wrapper
  verify_zkproof_for_acct_to_anon_tx

0. Byte / hex conventions

- All account/nonce/address/commitment inputs are conceptually 32-byte blobs.
- Wrappers accept either:
  - Bytes32: bytes/bytearray length 32
  - Hex32:   hex string length 64, with or without prefix, any case
- Internally, strings are normalized by stripping, removing prefix, then bytes.fromhex.
- Generator returns proof as hex string; verifier accepts proof as bytes or hex string.

Type aliases

- Bytes32    = Python bytes length 32
- Hex32      = hex string for 32 bytes (64 chars)
- ZKProofHex = hex string for proof bytes

Field bounds

- PALLAS_P
  0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
- SCALAR_ORDER
  0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001

- Public inputs pin_val, pin_nonce, pin_addr, pin_anon_commit are canonical Fp encodings:
  int.from_bytes(x, "big") < PALLAS_P.
- Secret sin_sk may be any 32 bytes; ECC uses sin_sk mod SCALAR_ORDER, Poseidon uses
  sin_sk as bytes mapped into Fp.

1. Generator API

Call

proof_hex = get_zkproof_for_acct_to_anon_tx(
  sin_sk,          # Bytes32 or Hex32
  pin_val,         # Bytes32 or Hex32
  pin_nonce,       # Bytes32 or Hex32
  pin_addr,        # Bytes32 or Hex32
  pin_anon_commit, # Bytes32 or Hex32
)

All five arguments are normalized into 32-byte big-endian bytes, then passed into the Rust-side generator.

Output

- proof_hex: ZKProofHex  
  HALO2 proof bytes encoded as a hex string (lowercase, no prefix).

2. Verifier API

Call

ok_bool = verify_zkproof_for_acct_to_anon_tx(
  proof,        # bytes or hex string
  val,          # Bytes32 or Hex32
  nonce,        # Bytes32 or Hex32
  addr,         # Bytes32 or Hex32
  anon_commit,  # Bytes32 or Hex32
)

All inputs are normalized into bytes before being passed into the Rust verifier.

Output

- ok_bool: bool  
  True iff proof verifies for the given public inputs.

3. Proved statement (black-box)

Public inputs (32B canonical < PALLAS_P)
  pin_val
  pin_nonce
  pin_addr
  pin_anon_commit

Secret input
  sin_sk (32B)

The proof attests existence of sin_sk such that:

f(sin_sk, pin_val, pin_nonce, pin_addr, pin_anon_commit):

  kp = EccKeypair()
  kp.set_sk(sin_sk)                    # internally uses sin_sk mod SCALAR_ORDER
  derived_addr = get_poseidon_hash(kp.get_pk_from_sk())

  a = (derived_addr == pin_addr)

  right_commit = get_poseidon_hash(
    pin_val,
    sin_sk,
    pin_nonce,
    pin_addr,
  )

  b = (right_commit == pin_anon_commit)

  return a and b

Equality here is equality of 32-byte canonical Fp encodings (equivalent to equality of Fp elements).

4. Minimal usage example

kp = EccKeypair()
sk_bytes = kp.get_sk()
pk_bytes = kp.get_pk_from_sk()

addr_hex   = get_poseidon_hash(pk_bytes)
addr_bytes = bytes.fromhex(addr_hex)

val_bytes   = (10).to_bytes(32, "big")
nonce_bytes = (1).to_bytes(32, "big")

anon_commit_hex = get_poseidon_hash(
  val_bytes,
  sk_bytes,
  nonce_bytes,
  addr_bytes,
)
anon_commit_bytes = bytes.fromhex(anon_commit_hex)

# generator: recommend using bytes
proof_hex = get_zkproof_for_acct_to_anon_tx(
  sk_bytes,
  val_bytes,
  nonce_bytes,
  addr_bytes,
  anon_commit_bytes,
)

# verifier: bytes or hex can be mixed; here hex is used
ok = verify_zkproof_for_acct_to_anon_tx(
  proof_hex,             # proof: hex
  val_bytes,             # or val_bytes.hex()
  nonce_bytes,
  addr_bytes,
  anon_commit_bytes,
)
