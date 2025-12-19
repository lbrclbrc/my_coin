#!/usr/bin/env python3
# tests/rust_api_tests/poseidon_hash_tests.py
#
# Poseidon hash tests (Python wrapper).
#
# Goals:
#   - Show that get_poseidon_hash works on simple inputs.
#   - Check that bytes and hex-string inputs for the same 32-byte value
#     produce the same digest.
#   - Check the "string interpretation switch":
#       * when a str looks like raw hex and decodes to a multiple of 32 bytes,
#         it is treated as raw hex bytes;
#       * otherwise the str is treated as UTF-8 text.
#     We verify that these two modes give different digests.

import os
import sys

# Add project root to sys.path
THIS_FILE = os.path.abspath(__file__)
THIS_DIR = os.path.dirname(THIS_FILE)
PROJECT_ROOT = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from wrappers.poseidon_hash_wrapper import get_poseidon_hash
from tools import short_hex


def test_poseidon_basic():
    """
    Basic smoke test: hashing a few small pieces and checking output type.
    """
    print("=== Poseidon basic test ===")
    result = get_poseidon_hash(b"value", b"sk", b"counter")
    print("Poseidon hash result:", short_hex(result))
    assert isinstance(result, str)
    assert len(result) > 0


def test_poseidon_bytes_vs_hex_string():
    """
    For a fixed 32-byte value, hashing as bytes and as a hex string
    should give the same digest, because the str is interpreted as raw hex.
    """
    print("\n=== Poseidon bytes vs hex-string (same 32-byte value) ===")

    # Fixed 32-byte pattern to make the test deterministic.
    value_bytes = b"\x01\x23\x45\x67" * 8  # 4 * 8 = 32 bytes
    value_hex = value_bytes.hex()

    print("value_bytes (hex):", short_hex(value_hex))

    digest_from_bytes = get_poseidon_hash(value_bytes)
    digest_from_hex_str = get_poseidon_hash(value_hex)  # str, valid 32-byte hex

    print("digest_from_bytes   :", short_hex(digest_from_bytes))
    print("digest_from_hex_str :", short_hex(digest_from_hex_str))

    assert isinstance(digest_from_bytes, str)
    assert isinstance(digest_from_hex_str, str)
    assert digest_from_bytes == digest_from_hex_str


def test_poseidon_hex_string_switch_mode():
    """
    Demonstrate the string parsing rule:
      - A hex-looking str whose decoded length is a multiple of 32 bytes
        is treated as raw hex bytes.
      - If we slightly change the length so that it is NOT a multiple of 32,
        the same characters are now treated as UTF-8 text instead.
    These two modes should yield different digests.
    """
    print("\n=== Poseidon string interpretation switch (hex vs UTF-8) ===")

    # Start from a 32-byte value so that the hex string length is exactly 64 chars.
    base_bytes = b"\xaa\xbb\xcc\xdd" * 8  # 32 bytes
    base_hex = base_bytes.hex()           # 64 hex chars -> 32 bytes

    print("base_bytes (hex)     :", short_hex(base_hex))

    # Mode 1: str is interpreted as raw hex bytes (because length % 32 == 0).
    digest_hex_mode = get_poseidon_hash(base_hex)

    # Mode 2: tweak the string so that decoded length is NOT a multiple of 32 bytes.
    # This keeps the same characters plus an extra "00", which breaks the "multiple of 32 bytes" rule,
    # so the wrapper should fall back to treating the whole string as UTF-8 text.
    bad_len_hex = base_hex + "00"  # 66 hex chars -> 33 bytes (not a multiple of 32)
    digest_text_mode = get_poseidon_hash(bad_len_hex)

    print("base_hex (raw-hex mode)        :", short_hex(base_hex))
    print("bad_len_hex (forces UTF-8 mode):", short_hex(bad_len_hex))
    print("digest_hex_mode                :", short_hex(digest_hex_mode))
    print("digest_text_mode               :", short_hex(digest_text_mode))

    assert isinstance(digest_hex_mode, str)
    assert isinstance(digest_text_mode, str)
    assert digest_hex_mode != digest_text_mode


def test_poseidon_hex_string_with_0x_prefix():
    """
    Check that a '0x'-prefixed hex string is still treated as raw hex bytes
    when it decodes to a multiple of 32 bytes.
    """
    print("\n=== Poseidon hex-string with 0x prefix ===")

    value_bytes = b"\x10\x20\x30\x40" * 8  # 32 bytes
    value_hex = value_bytes.hex()
    prefixed = "0x" + value_hex

    digest_from_bytes = get_poseidon_hash(value_bytes)
    digest_from_prefixed = get_poseidon_hash(prefixed)

    print("value_hex         :", short_hex(value_hex))
    print("prefixed hex str  :", short_hex(prefixed))
    print("digest_from_bytes :", short_hex(digest_from_bytes))
    print("digest_from_prefixed:", short_hex(digest_from_prefixed))

    assert digest_from_bytes == digest_from_prefixed


if __name__ == "__main__":
    # Run tests manually when this file is executed directly.
    test_poseidon_basic()
    test_poseidon_bytes_vs_hex_string()
    test_poseidon_hex_string_switch_mode()
    test_poseidon_hex_string_with_0x_prefix()
    print("\n=== all Poseidon tests finished ===")
