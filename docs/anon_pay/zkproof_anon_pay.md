ZKProof Spec  AnonPay  Generator and Verifier

Scope
- External API and proved statement for zkproof_for_anon_pay.
- Circuit files are in zkcrypto/src/.
- Backend uses HALO2.
- This proof spends one old anon note and creates a change note.
  (Receiver-side ciphertexts are NOT part of this circuit.)

API names
- generator wrapper: get_zkproof_for_anon_pay
- verifier wrapper:  verify_zkproof_for_anon_pay

0. Byte / hex conventions

Wrappers are deliberately flexible and accept both bytes and hex-strings
for all 32-byte values.

- Bytes32OrHex:
  - python bytes / bytearray of length 32; OR
  - hex string that decodes to 32 bytes, with or without "0x" prefix.
- Int32:
  - python int, converted in the wrapper as `int(i).to_bytes(32, "big")`.
- ZKProofHex:
  - hex string for arbitrary-length proof bytes (lowercase, no 0x when printed).

Internally wrappers use `tools.turn_hex_str_to_bytes(x)`:

- if `x` is bytes / bytearray:
    - return `bytes(x)` unchanged.
- if `x` is str:
    - strip whitespace;
    - drop leading `"0x"` / `"0X"` if present;
    - require even length;
    - parse as hex → bytes.
- invalid hex raises `ValueError`.

Poseidon hash wrapper:
- input: bytes (or list of bytes)
- output: 32-byte digest as hex string (lowercase, no 0x).

Field / scalar bounds (circuit side, not enforced by wrappers):
- PALLAS_P (Fp modulus)
  0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
- SCALAR_ORDER (Fr order)
  0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
- All public 32-byte inputs are interpreted as canonical Fp elements
  (big-endian < PALLAS_P).
- Secret sk may be any 32 bytes:
  ECC uses sk mod SCALAR_ORDER,
  hashing treats sk_bytes as Fp element mod PALLAS_P.

Type aliases
- Hex32          64-char hex for 32 bytes
- Bytes32OrHex   bytes(32) or Hex32 string
- ZKProofHex     hex for proof bytes
- DirBit         int in {0,1} (or bool)
- Siblings32     list[32] Bytes32OrHex
- Dirs32         list[32] DirBit

1. Generator API

Call

  proof_hex = get_zkproof_for_anon_pay(
    pin_root,            # Bytes32OrHex
    pin_nullifier,       # Bytes32OrHex
    pin_commit_change,   # Bytes32OrHex
    pin_value_pay,       # Int32

    sin_value_initial,   # Int32
    sin_value_change,    # Int32
    sin_sk,              # Bytes32OrHex
    sin_nonce_initial,   # Bytes32OrHex
    sin_src,             # Bytes32OrHex
    sin_siblings,        # Siblings32
    sin_dirs,            # Dirs32
  )

Wrapper behavior (high level):

- `pin_root`, `pin_nullifier`, `pin_commit_change`,
  `sin_sk`, `sin_nonce_initial`, `sin_src`, each element in `sin_siblings`:
    - if bytes → used as-is;
    - if str → parsed via `turn_hex_str_to_bytes` (must decode to 32 bytes).
- `pin_value_pay`, `sin_value_initial`, `sin_value_change`:
    - converted to 32-byte big-endian.
- `sin_dirs`:
    - each element coerced via `int(d)`, passed as 0/1 to Rust.

Output
- `proof_hex` (ZKProofHex):
  - HALO2 proof bytes encoded as lowercase hex string (no 0x).

2. Verifier API

Call

  ok_bool = verify_zkproof_for_anon_pay(
    root,            # Bytes32OrHex
    nullifier,       # Bytes32OrHex
    commit_change,   # Bytes32OrHex
    value_pay,       # Int32
    proof,           # ZKProofHex or bytes
  )

Wrapper behavior:

- `root`, `nullifier`, `commit_change`:
    - Bytes32OrHex → converted into 32-byte raw bytes using the same rule (bytes used directly; strings parsed via `turn_hex_str_to_bytes`).
- `value_pay`:
    - int → 32-byte big-endian.
- `proof`:
    - bytes/bytearray: used directly;
    - str: parsed as hex via `turn_hex_str_to_bytes`.

Output
- `ok_bool`: True iff proof verifies for the supplied public inputs.

3. Merkle path inputs

`sin_siblings`  (Siblings32)
- Fixed-length list of 32 sibling node hashes on the Merkle path
  from the old note leaf up to the tree root.
- Each element is Bytes32OrHex.

`sin_dirs`  (Dirs32)
- Fixed-length list of 32 direction bits aligned with siblings.
- Each bit tells the circuit whether, at that tree level,
  the sibling is on the right or on the left of the running hash.

Convention:

  dir = 0  ⇒ sibling on RIGHT, parent = H(cur, sib)
  dir = 1  ⇒ sibling on LEFT,  parent = H(sib, cur)

Difference:
- siblings: the values to hash with;
- dirs: which side the sibling is on, i.e. hash order at each level.

Why fixed length:
- MerkleTreeCommit depth is fixed to 32.
- So both lists are always length 32 (not variable).

Typical construction:

  proof_pairs = tree.gen_proof(index)
  sibs = []
  dirs = []
  for sib_hex, direction in proof_pairs:
      sibs.append(sib_hex)              # Hex32; wrapper will accept it
      dirs.append(0 if direction == "R" else 1)

4. Public inputs: meaning and how to compute

`pin_root`
- Merkle root of current anon commitment tree.
- E.g. `MerkleTreeCommit.root()`.

`pin_nullifier`
- Nullifier for the old note being spent.
- Computed as:

    nullifier = Poseidon(
      sk_bytes,
      nonce_initial_bytes,
      src_bytes,
    )

`pin_commit_change`
- Commitment for the change note that remains after paying.
- Computed as:

    commit_change = Poseidon(
      value_change_bytes,
      sk_bytes,
      ZERO32_bytes,
      nullifier_bytes,
    )

`pin_value_pay`
- Public amount to pay to the receiver (python int).
- Circuit constrains this value into an integer range and uses
  integer semantics (see Section 6).

5. Secret inputs: meaning and how to compute

`sin_value_initial`
- Integer value of the old note.

`sin_value_change`
- Integer value of the change note.

  value_change = value_initial - value_pay    (integer semantics)

`sin_sk`
- Secret key controlling the old note (32-byte value).

`sin_nonce_initial`
- Nonce of the old note (32-byte value).

`sin_src`
- Source tag of the old note (32-byte value).

`sin_siblings`, `sin_dirs`
- Merkle inclusion path for `old_commit` under `pin_root`
  as explained in Section 3.

6. Proved statement (black box, matching circuit)

Public
- `pin_root`
- `pin_nullifier`
- `pin_commit_change`
- `pin_value_pay`

Secret
- `sin_value_initial`
- `sin_value_change`
- `sin_sk`
- `sin_nonce_initial`
- `sin_src`
- `sin_siblings`
- `sin_dirs`

Conceptually, the proof attests that there exist secrets such that:

  decode32(x):
      # conceptual helper; wrapper + circuit together implement this
      # via turn_hex_str_to_bytes + field canonicalization.
      return 32-byte canonical Fp encoding of x

  sk_bytes    = decode32(sin_sk)
  nonce_bytes = decode32(sin_nonce_initial)
  src_bytes   = decode32(sin_src)

  # --- (A) nullifier correctness ---
  nullifier_expected = Poseidon(sk_bytes, nonce_bytes, src_bytes)
  nullifier_expected == pin_nullifier   # equality as canonical Fp bytes

  # --- (B) old leaf correctness + Merkle inclusion ---
  old_commit = Poseidon(
    BE32(sin_value_initial),  # 32-byte big-endian integer -> Fp
    sk_bytes,
    nonce_bytes,
    src_bytes,
  )

  MerkleVerifyFixedDepth32(
    leaf     = old_commit,
    root     = pin_root,
    siblings = sin_siblings,
    dirs     = sin_dirs,
  ) == True

  # --- (C) value conservation with NON-WRAP integer semantics ---
  # Inside the circuit, values live in Fp but are additionally
  # range-constrained to a fixed unsigned range R, and comparison /
  # equality are done as integers in R. This prevents mod-P wraparound.

  sin_value_initial in R
  pin_value_pay     in R
  sin_value_change  in R

  sin_value_initial >= pin_value_pay
  sin_value_initial == pin_value_pay + sin_value_change

  # --- (D) change commitment correctness ---
  commit_change_expected = Poseidon(
    BE32(sin_value_change),
    sk_bytes,
    ZERO32_bytes,
    decode32(pin_nullifier),
  )
  commit_change_expected == pin_commit_change

  return True

Notes on mod-P:
- All Poseidon hashes and equality checks are done in Fp (mod PALLAS_P).
- The “no wraparound” property is enforced by range / comparison
  constraints, not by field arithmetic alone.

7. Minimal usage example (end-to-end)

from merkle_tree import MerkleTreeCommit
from wrappers.poseidon_hash_wrapper import get_poseidon_hash
from wrappers.pasta_ecc_wrapper import EccKeypair
from wrappers.zkproof_for_anon_pay_gen_wrapper import get_zkproof_for_anon_pay, ZERO32_HEX
from wrappers.zkproof_for_anon_pay_verify_wrapper import verify_zkproof_for_anon_pay
import os

# --- keys and note parameters ---
kp = EccKeypair()
sk_bytes = kp.get_sk()                # bytes(32)
sk_hex = sk_bytes.hex()

nonce_initial_bytes = (5).to_bytes(32, "big")
nonce_initial_hex = nonce_initial_bytes.hex()

src_bytes = os.urandom(32)
src_hex = src_bytes.hex()

value_initial = 100
value_pay = 30
value_change = value_initial - value_pay

# --- public values derived from secrets ---
nullifier_hex = get_poseidon_hash(
  sk_bytes,
  nonce_initial_bytes,
  src_bytes,
)

old_commit_hex = get_poseidon_hash(
  value_initial.to_bytes(32, "big"),
  sk_bytes,
  nonce_initial_bytes,
  src_bytes,
)

tree = MerkleTreeCommit()
tree.append(os.urandom(32).hex())
tree.append(old_commit_hex)
tree.append(os.urandom(32).hex())
tree.append(os.urandom(32).hex())

root_hex = tree.root()

commit_change_hex = get_poseidon_hash(
  value_change.to_bytes(32, "big"),
  sk_bytes,
  bytes.fromhex(ZERO32_HEX),
  bytes.fromhex(nullifier_hex),
)

index = 1
proof_pairs = tree.gen_proof(index)
sibs = []
dirs = []
for sib_hex, direction in proof_pairs:
  sibs.append(sib_hex)               # Hex32, wrapper will accept
  dirs.append(0 if direction == "R" else 1)

# --- generator: mix bytes and hex on purpose ---
proof_hex = get_zkproof_for_anon_pay(
  root_hex,            # public root (hex)
  nullifier_hex,       # public nullifier (hex)
  commit_change_hex,   # public change commit (hex)
  value_pay,           # public int

  value_initial,       # secret int
  value_change,        # secret int
  sk_bytes,            # secret sk (bytes)
  nonce_initial_hex,   # secret nonce (hex)
  src_hex,             # secret src (hex)
  sibs,                # secret siblings (list of hex)
  dirs,                # secret dirs (list of 0/1)
)

# --- verifier: also free to use hex or bytes ---
ok = verify_zkproof_for_anon_pay(
  root_hex,
  nullifier_hex,
  commit_change_hex,
  value_pay,
  proof_hex,           # proof as hex string
)
assert ok is True
