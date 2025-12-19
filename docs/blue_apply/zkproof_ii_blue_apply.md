ZKProof Spec  BlueApply-II  Generator and Verifier

Scope
- External API and proved statement for zkproof_for_ii_blue_apply.
- Circuits live in zkcrypto/src/, backend uses HALO2.
- This proof is used for second-and-later BlueApply:
  given a master_seed and token, prove that
    (1) master_seed_hash = Poseidon(master_seed)
    (2) new_pk is derived from (master_seed, token)
  using one and the same master_seed.

API names
- generator wrapper
  get_zkproof_for_ii_blue_apply
- verifier wrapper
  verify_zkproof_for_ii_blue_apply

0. Byte / hex conventions

- All data (except the proof) is conceptually 32-byte blobs on the Python side.
- Wrappers accept either:
  - Bytes32: bytes/bytearray of length 32
  - Hex32:   hex string of length 64, with or without prefix, any case
- Internally, hex strings are stripped, optional prefix removed, then bytes.fromhex applied.
- Proof:
  - generator returns proof_hex: str (hex, lowercase, no prefix)
  - verifier accepts the proof as either hex string or raw bytes.

Type aliases

- Bytes32    = Python bytes length 32
- Hex32      = hex string for 32 bytes (64 chars, case-insensitive, canonical form has no prefix)
- ZKProofHex = hex string for proof bytes

Field and scalar bounds

- PALLAS_P (base field Fp modulus)
  0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
- SCALAR_ORDER (scalar field Fr order)
  0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001

- master_seed and master_seed_hash are canonical Fp encodings:
  int.from_bytes(x, "big") < PALLAS_P.
- token is a 32-byte value; where needed it is mapped into Fp/Fr.
- new_pk is a 32-byte compressed Pallas public key, same format as EccKeypair.get_pk_from_sk().

1. Generator API

Call

proof_hex = get_zkproof_for_ii_blue_apply(
  master_seed,       # Bytes32 or Hex32 (secret)
  token,             # Bytes32 or Hex32 (public)
  new_pk,            # Bytes32 or Hex32 (public, compressed pk)
  master_seed_hash,  # Bytes32 or Hex32 (public)
)

Output

- proof_hex: ZKProofHex  
  HALO2 proof bytes encoded as hex (lowercase, no prefix).

2. Verifier API

Call

ok_bool = verify_zkproof_for_ii_blue_apply(
  proof,            # bytes or hex string (same proof as above)
  token,            # Bytes32 or Hex32
  new_pk,           # Bytes32 or Hex32
  master_seed_hash, # Bytes32 or Hex32
)

Output

- ok_bool: bool  
  True iff proof verifies for the given public inputs.

3. How to compute public inputs

master_seed (Bytes32)
  Secret master seed controlling this address family.

master_seed_hash (Bytes32)

  ms_hash_hex  = get_poseidon_hash(master_seed_bytes)
  master_seed_hash = bytes.fromhex(ms_hash_hex)

token (Bytes32)
  Public token for this derived address, e.g.:

  token = (0).to_bytes(32, "big")  # first address
  token = (1).to_bytes(32, "big")  # second address
  # or any other 32-byte index

new_pk (Bytes32)
  Derived outside the circuit by:

  digest_hex = get_poseidon_hash(master_seed_bytes, token_bytes)
  digest_int = int(digest_hex, 16) % SCALAR_ORDER
  sk_bytes   = digest_int.to_bytes(32, "big")

  kp = EccKeypair()
  kp.set_sk(sk_bytes)
  new_pk_bytes = kp.get_pk_from_sk()

4. Proved statement (black-box)

Public inputs
  token             : Bytes32 (Fp/Fr interpreted inside the circuit)
  new_pk            : compressed pk (Bytes32)
  master_seed_hash  : Bytes32

Secret input
  sin_master_seed   : Bytes32

The proof attests existence of sin_master_seed such that:

f(token, new_pk, master_seed_hash, sin_master_seed):

  # Interpret master seed in Fp (base field)
  ms_bytes = sin_master_seed
  ms_int   = int.from_bytes(ms_bytes, "big")
  ms_fp    = ms_int mod PALLAS_P

  # (A) master_seed_hash correctness
  ms_hash_expected_hex   = PoseidonFp_as_hex([ms_bytes])
  ms_hash_expected_bytes = bytes.fromhex(ms_hash_expected_hex)
  Require: ms_hash_expected_bytes == master_seed_hash

  # (B) new_pk derivation correctness
  digest_hex = PoseidonFp_as_hex([ms_bytes, token])
  digest_int = int(digest_hex, 16)
  sk_int     = digest_int mod SCALAR_ORDER
  sk_bytes   = sk_int.to_bytes(32, "big")

  pk_expected        = ScalarMulBase(sk_int)
  pk_expected_bytes  = EncodePkCompressed(pk_expected)

  Require: pk_expected_bytes == new_pk

  # (C) single master_seed
  The same witness ms_bytes is used in (A) and (B).

  return True

5. Minimal usage example

master_seed = os.urandom(32)
token0 = (0).to_bytes(32, "big")

ms_hash_hex  = get_poseidon_hash(master_seed)
ms_hash      = bytes.fromhex(ms_hash_hex)

digest_hex   = get_poseidon_hash(master_seed, token0)
digest_int   = int(digest_hex, 16) % SCALAR_ORDER
sk_bytes     = digest_int.to_bytes(32, "big")

kp = EccKeypair()
kp.set_sk(sk_bytes)
pk_bytes = kp.get_pk_from_sk()

# generator: pass bytes directly
proof_hex = get_zkproof_for_ii_blue_apply(
  master_seed,
  token0,
  pk_bytes,
  ms_hash,
)

# verifier: proof in hex, others may be bytes or hex
ok = verify_zkproof_for_ii_blue_apply(
  proof_hex,
  token0,
  pk_bytes,
  ms_hash,
)
