# poseidon_hash_wrapper.py
# This module provides a Python-side interface for preparing data for Poseidon hashing.
# It concatenates items, splits them into fixed-size blocks, reduces each block modulo
# the Pallas Fp modulus, and passes the processed blocks to the Rust implementation.

from __future__ import annotations

from typing import List, Union, Sequence

# Allowed bytes-like types
BytesLike = Union[bytes, bytearray, memoryview]
StrOrBytes = Union[str, BytesLike]

# Attempt to import zkcrypto; any import errors are stored and raised when needed.
try:
    import zkcrypto  # type: ignore[import]
    _IMPORT_ERROR = None
except Exception as e:
    zkcrypto = None  # type: ignore[assignment]
    _IMPORT_ERROR = e

# Cached Pallas Fp modulus
_PALLAS_MODULUS: int | None = None


def _ensure_zkcrypto_available() -> None:
    """
    Ensure that the zkcrypto module is correctly imported and contains
    the required functions. Raise RuntimeError if not available.
    """
    global zkcrypto, _IMPORT_ERROR

    if _IMPORT_ERROR is not None or zkcrypto is None:  # type: ignore[truthy-function]
        raise RuntimeError(
            "zkcrypto module is not available. Ensure the Rust extension is compiled and importable."
        ) from _IMPORT_ERROR

    missing: List[str] = []
    for name in ("get_pallas_modulus_py", "poseidon_hash_blocks"):
        if not hasattr(zkcrypto, name):  # type: ignore[arg-type]
            missing.append(name)

    if missing:
        raise RuntimeError(
            "zkcrypto module is missing required functions: " + ", ".join(missing)
        )


def _to_bytes(x: StrOrBytes) -> bytes:
    """
    Convert an input to bytes:
      - str: If it is a valid hex string whose decoded length is a multiple of 32,
             decode it as hex. Otherwise encode it as UTF-8.
      - bytes / bytearray / memoryview: convert directly.
      - any other type: raise TypeError.
    """
    if isinstance(x, bytes):
        return x
    if isinstance(x, bytearray):
        return bytes(x)
    if isinstance(x, memoryview):
        return x.tobytes()
    if isinstance(x, str):
        s = x.strip().lower()
        if s.startswith("0x"):
            s = s[2:]

        if s and (len(s) % 2 == 0):
            is_hex = True
            for ch in s:
                if ch not in "0123456789abcdef":
                    is_hex = False
                    break
            if is_hex:
                try:
                    b = bytes.fromhex(s)
                    if len(b) % 32 == 0:
                        return b
                except ValueError:
                    pass

        return x.encode("utf-8")

    raise TypeError(
        f"items must be str or bytes-like (bytes/bytearray/memoryview), got: {type(x)!r}"
    )


def _get_pallas_modulus() -> int:
    """
    Retrieve the Pallas Fp modulus from zkcrypto.get_pallas_modulus_py(),
    convert it to an integer, and cache the result.
    """
    global _PALLAS_MODULUS

    if _PALLAS_MODULUS is not None:
        return _PALLAS_MODULUS

    _ensure_zkcrypto_available()

    raw = zkcrypto.get_pallas_modulus_py()  # type: ignore[call-arg]
    if not isinstance(raw, str):
        raise TypeError(
            f"zkcrypto.get_pallas_modulus_py() must return a hex string, got: {type(raw)!r}"
        )

    s = raw.strip().lower()
    if s.startswith("0x"):
        s = s[2:]

    if not s:
        raise ValueError("Pallas modulus string is empty.")

    try:
        value = int(s, 16)
    except ValueError as e:
        raise ValueError(f"Invalid hex returned from get_pallas_modulus_py(): {raw!r}") from e

    if value <= 0:
        raise ValueError(f"Pallas modulus must be a positive integer, got: {value!r}")

    _PALLAS_MODULUS = value
    return value


def concat_and_chunk_modr(
    items: Sequence[StrOrBytes],
    block_size: int = 32,
) -> List[bytes]:
    """
    Concatenate several items (each converted to bytes), then split the
    concatenated bytes into fixed-size blocks. Each block is interpreted
    as a big-endian integer, reduced modulo the Pallas Fp modulus, and
    encoded back into a fixed-size big-endian byte array.

    Returns:
        List[bytes]: each element is block_size bytes.
    """
    if block_size <= 0:
        raise ValueError(f"block_size must be a positive integer, got: {block_size!r}")

    try:
        parts = [_to_bytes(x) for x in items]
    except TypeError:
        raise

    message = b"".join(parts)

    if len(message) == 0:
        return []

    modulus = _get_pallas_modulus()
    blocks: List[bytes] = []

    for offset in range(0, len(message), block_size):
        chunk = message[offset : offset + block_size]
        if len(chunk) < block_size:
            chunk = chunk + b"\x00" * (block_size - len(chunk))

        value = int.from_bytes(chunk, "big", signed=False)
        reduced = value % modulus
        block = reduced.to_bytes(block_size, "big", signed=False)
        blocks.append(block)

    return blocks


def get_poseidon_hash(*items: StrOrBytes) -> str:
    """
    Main interface for Poseidon hashing.

    Accepted forms:
        get_poseidon_hash("a")
        get_poseidon_hash("a", "b", "c")
        get_poseidon_hash(b"bytes1", b"bytes2")
        get_poseidon_hash(["a", "b", "c"])    # if a single list/tuple is passed

    Behavior:
      - If a single list/tuple is given, treat its contents as the items.
      - Otherwise treat all arguments as the sequence of items.
      - Each item is converted to bytes, concatenated, split into fixed-size blocks,
        reduced modulo the Pallas Fp modulus, and passed to the Rust Poseidon
        implementation.
      - The resulting digest (bytes) is returned as a lowercase hex string.
    """
    if len(items) == 1 and isinstance(items[0], (list, tuple)):
        items_seq: Sequence[StrOrBytes] = items[0]  # type: ignore[assignment]
    else:
        items_seq = items  # type: ignore[assignment]

    blocks = concat_and_chunk_modr(items_seq, block_size=32)

    _ensure_zkcrypto_available()

    try:
        digest_bytes = zkcrypto.poseidon_hash_blocks(blocks)  # type: ignore[call-arg]
    except Exception as e:
        raise RuntimeError(
            "Failed to call zkcrypto.poseidon_hash_blocks(...). Check Rust bindings and argument formats."
        ) from e

    if not isinstance(digest_bytes, (bytes, bytearray, memoryview)):
        try:
            digest_bytes = bytes(digest_bytes)
        except Exception as e:
            raise TypeError(
                "Return value of poseidon_hash_blocks(...) cannot be converted to bytes."
            ) from e

    digest_bytes = bytes(digest_bytes)

    if len(digest_bytes) == 0:
        raise ValueError("poseidon_hash_blocks(...) returned an empty digest.")

    if len(digest_bytes) < 32:
        raise ValueError(
            f"poseidon_hash_blocks(...) returned a digest shorter than 32 bytes: {len(digest_bytes)}"
        )

    return digest_bytes.hex()


__all__ = [
    "get_poseidon_hash",
    "concat_and_chunk_modr",
    "BytesLike",
    "StrOrBytes",
]
