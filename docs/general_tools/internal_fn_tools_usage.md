# Internal Tools API Usage Guide

This document describes the available utility functions in `tools.py` and the rules for how to use them.  
All functions listed here are stable internal APIs and should be reused instead of re-implementing logic in other files.

---

## 1. turn_hex_str_to_bytes(x) -> bytes
Convert input into bytes.

Behavior:
- If `x` is already of type `bytes`, return it unchanged.
- If `x` is a hex string (with or without `0x` prefix), convert it to bytes.
- Raises `ValueError` if the string is not valid hex.
- Raises `TypeError` if input is not `str` or `bytes`.

Use this function whenever converting user-supplied hex values into raw bytes.

Example:
```python
b = turn_hex_str_to_bytes("0a1b2c")
```

---

## 2. turn_bytes_to_hex_str(b) -> str
Convert a `bytes` object into a lowercase hex string without any prefix.

Example:
```python
h = turn_bytes_to_hex_str(b"\x01\x02")
# => "0102"
```

---

## 3. derive_master_seed_from_password(password: str) -> bytes
Derive a 32-byte master seed from a password.

Behavior:
- `password` must be a `str`.
- Internally runs SHA-256 and reduces modulo the curve field modulus.
- Always returns exactly 32 bytes.

Example:
```python
seed = derive_master_seed_from_password("mypassword")
```

---

## 4. get_hash(data: Union[str, bytes]) -> str
Compute SHA-256 and return a lowercase hex string.

Behavior:
- If input is `str`, it is encoded as UTF-8.
- If input is `bytes`, it is hashed directly.

Example:
```python
digest = get_hash("hello")
digest2 = get_hash(b"abc")
```

---

## 5. verify_account_merkle_proof(account, lst_of_siblings, account_root) -> bool
Verify an account's Merkle proof using Poseidon hashing.

Behavior:
- `lst_of_siblings` must be an ordered list of `(sibling_hex, "L"/"R")`.
- `account_root` is the expected Merkle root.
- Returns `True` if the proof is valid, otherwise `False`.

Example:
```python
ok = verify_account_merkle_proof(acct, siblings, root)
```

---

## 6. run_silently(func, *args, **kwargs)
Execute a function while suppressing all stdout/stderr output.

Behavior:
- Python prints are hidden.
- Rust-level output from the zk-verifier is also hidden.
- Returns the function's result.

Example:
```python
result = run_silently(run_demo)
```

---

## 7. short_hex(h, prefix_len=8) -> str
Return a shortened preview of a hex string.

Behavior:
- If `h` is bytes, it is first converted to hex.
- If `h` is not a string, it is returned unchanged.
- If `h` is short enough, return it unchanged.
- Otherwise output: `head ... tail`.

Example:
```python
short = short_hex("abcdef1234567890")
```

---


