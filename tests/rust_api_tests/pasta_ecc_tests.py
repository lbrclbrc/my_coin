#!/usr/bin/env python3
# tests/rust_api_tests/pasta_ecc_tests.py
#
# Basic Pasta (Bandersnatch-style) ECC wrapper tests.
#
# Goals:
#   - Generate a random secret key and derive the corresponding public key.
#   - Sign a message and verify the signature (positive test).
#   - Tamper with the signature and with the message and check that
#     verification fails (negative tests).
#   - Print "RESULT: true" only if all checks behave as expected.

import os
import sys

# Add project root to sys.path
THIS_FILE = os.path.abspath(__file__)
THIS_DIR = os.path.dirname(THIS_FILE)
PROJECT_ROOT = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from wrappers.pasta_ecc_wrapper import EccKeypair, R


def main() -> None:
    print("=== Pasta ECC sign/verify tests ===")

    # 1) Construct the wrapper and get a fresh secret key.
    k = EccKeypair()
    sk = k.get_sk()
    print(f"SK: type={type(sk)}, len={len(sk)}, hex_prefix={sk.hex()[:64]}")

    # 2) Derive the compressed public key from the secret key.
    pk = k.get_pk_from_sk(True)  # compressed form
    print(f"PK: type={type(pk)}, len={len(pk)}, hex_prefix={pk.hex()[:64]}")

    # 3) Sign a message and verify the signature (positive test).
    msg = b"test message for bandersnatch"
    r, s, raw = k.sign(msg)
    print(f"signature lengths: r={len(r)}, s={len(s)}, raw={len(raw)}")
    print(f"signature r hex_prefix={r.hex()[:64]}")
    print(f"signature s hex_prefix={s.hex()[:64]}")

    ok_valid = k.verify_signature(raw, msg)
    print(f"verify(valid signature) -> {ok_valid}")

    # 4) Tamper with the signature (flip scalar s) and check that it fails.
    s_int = int.from_bytes(s, "little")
    s_tampered_int = (s_int + 1) % R
    s_tampered = s_tampered_int.to_bytes(32, "little")
    raw_tampered = r + s_tampered

    ok_tampered = k.verify_signature(raw_tampered, msg)
    print(f"verify(tampered signature) -> {ok_tampered}")

    # 5) Keep the signature but change the message and check that it fails.
    wrong_msg = b"different message"
    ok_wrong_msg = k.verify_signature(raw, wrong_msg)
    print(f"verify(valid signature, wrong message) -> {ok_wrong_msg}")

    # 6) Overall result: only succeed if everything behaves as expected.
    success = (ok_valid is True) and (ok_tampered is False) and (ok_wrong_msg is False)
    print("RESULT:", "true" if success else "false")


if __name__ == "__main__":
    main()
