get_poseidon_hash (Internal API) — How to Use

What this function is
- get_poseidon_hash is the project’s Poseidon hash entrypoint on the Python side.
- It hashes data using Poseidon in Rust over the Pallas base field (Fp).
- It is SNARK-friendly Poseidon, not SHA-256.

Input types you may pass
- Each input item must be one of:
  - bytes
  - bytearray
  - memoryview
  - str
- Two calling styles (equivalent):
  style_A_variadic:
    get_poseidon_hash(x0, x1, x2, ...)
  style_B_legacy_list_or_tuple:
    get_poseidon_hash([x0, x1, x2, ...])
- The order of items matters.
- Recommended: pass bytes-like items directly.
  str and list/tuple are supported but discouraged.

Canonical byte / field semantics
- All items are converted to bytes, then concatenated in order:
    message = to_bytes(x0) || to_bytes(x1) || ...
- message is split into 32-byte blocks (big-endian).
- last block shorter than 32 bytes is right-padded with 0x00.
- each 32-byte block is interpreted as big-endian unsigned integer v,
  then reduced into Pallas Fp:
    v_reduced = v mod p
  where:
    p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
- each reduced value is re-encoded to exactly 32 bytes big-endian.
- these 32-byte blocks are sent to Rust poseidon_hash_blocks,
  producing a 32-byte digest.

str -> bytes rule (new standard)
def to_bytes(x):
    if x is bytes:
        return x
    if x is bytearray:
        return bytes(x)
    if x is memoryview:
        return x.tobytes()
    if x is str:
        s = x.strip().lower()
        if s startswith "0x":
            s = s[2:]
        if s is nonempty and len(s) is even and all chars in hex_set:
            b = bytes.fromhex(s)
            if len(b) % 32 == 0:
                return b
        return x.encode("utf-8")
    raise TypeError

Meaning:
- str is auto-treated as raw hex bytes only when:
  it is valid hex AND decoded length is a multiple of 32 bytes.
- otherwise str is treated as UTF-8 text bytes.
- because of this auto-rule, str inputs are less stable than bytes.

Return value
- returns digest_hex : str (lowercase hex)
- normally len(bytes.fromhex(digest_hex)) == 32.

Endianness summary
- input blocks are big-endian integers.
- reduction is mod p on those big-endian integers.
- output hex is a 32-byte big-endian field element.

Error / edge behavior
- must provide at least one item and concatenated bytes must be non-empty.
- any item not in (str, bytes, bytearray, memoryview) raises TypeError.
- any Rust failure raises RuntimeError.

Common usage patterns (recommended first)
pattern_A_bytes_only:
    h = get_poseidon_hash(elem0_bytes32, elem1_bytes32)

pattern_B_multiple_bytes_pieces:
    h = get_poseidon_hash(b"\x01\x02", b"hello", b"\xff")

pattern_C_hex_string_only_if_you_intend_raw_hex:
    pk_bytes = bytes.fromhex(pk_hex_64)
    h = get_poseidon_hash(pk_bytes)

legacy_or_discouraged_patterns
pattern_D_legacy_list_form:
    h = get_poseidon_hash([b"a", b"b", b"c"])

pattern_E_str_inputs:
    h1 = get_poseidon_hash("abc")          # UTF-8 bytes
    h2 = get_poseidon_hash("00" * 32)      # raw hex bytes (32B)

Notes for correct use
- Best practice: always pass bytes-like items.
  this avoids any ambiguity and matches “raw-bytes” expectation.
- list/tuple form is only for backward compatibility; avoid in new code.
- str form may be interpreted as hex-bytes or UTF-8 depending on content;
  avoid unless you are 100% sure.
- if you want raw hex bytes, do bytes.fromhex(...) yourself and pass bytes.
- right-padding only happens on the last partial block.
- mod p reduction is intended; different blocks differing by multiples of p
  map to the same field element.
