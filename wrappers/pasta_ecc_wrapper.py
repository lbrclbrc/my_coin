# wrappers/pasta_ecc_wrapper.py
# Python wrapper for the Rust Pasta (Pallas) ECC bindings (module name: zkcrypto).
#
# The underlying Rust object is PastaECCKeyPairs, which stores SK/PK internally.
# This wrapper exposes a Python-friendly interface while keeping the raw byte
# behavior untouched.
#
# Key conventions:
#   - Secret keys (SK) and public keys (PK) are always 32 bytes.
#   - Compressed Pallas public keys are 32 bytes.
#   - Signatures are 64 bytes: R(32B compressed point) || S(32B scalar repr).
#
# No encoding conversions are performed beyond what is required to pass
# raw bytes to the Rust layer.

import os
import binascii
from typing import Optional, Tuple, Union

import zkcrypto  # Rust extension must be installed locally

BytesLike = Union[bytes, bytearray, memoryview]

# Field parameters (Pallas Fp)
R = int("40000000000000000000000000000000224698fc094cf91b992d30ed00000001", 16)
P = int("40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001", 16)


class EccKeypair:
    def __init__(self, sk: Optional[BytesLike] = None):
        """
        Construct the keypair wrapper. No implicit SK generation is performed.
        If sk is provided, it is set directly after validation.
        """
        self.sk: Optional[bytes] = None
        self.pk: Optional[bytes] = None

        # Rust-side object: PastaECCKeyPairs
        self._rs = zkcrypto.PastaECCKeyPairs()

        if sk is not None:
            self.set_sk(sk)

    # ---------------- SK / PK Management ----------------

    def set_sk(self, sk_bytes: BytesLike) -> None:
        """Set an existing 32-byte secret key into the wrapper and Rust object."""
        if not isinstance(sk_bytes, (bytes, bytearray, memoryview)):
            raise TypeError("sk must be bytes-like")
        sk = bytes(sk_bytes)
        if len(sk) != 32:
            raise ValueError("sk must be exactly 32 bytes")
        self.sk = sk
        self._rs.set_sk_from_bytes(self.sk)
        self.pk = None  # clear PK cache on Python side

    def set_pk(self, pk_bytes: BytesLike) -> None:
        """Set an existing compressed 32-byte public key into the wrapper and Rust object."""
        if not isinstance(pk_bytes, (bytes, bytearray, memoryview)):
            raise TypeError("pk must be bytes-like")
        pk = bytes(pk_bytes)
        if len(pk) != 32:
            raise ValueError("pk must be exactly 32 bytes")
        self.pk = pk
        self._rs.set_pk_from_bytes(self.pk)

    def get_sk(self) -> bytes:
        """
        Generate a random 32-byte secret key securely, reduce it modulo R,
        set it into both sides, and return it.
        """
        rand_bytes = os.urandom(32)
        sk_int = int.from_bytes(rand_bytes, "little") % R
        self.sk = sk_int.to_bytes(32, "little")
        self._rs.set_sk_from_bytes(self.sk)
        self.pk = None
        return self.sk

    def get_pk_from_sk(self, compressed: bool = True) -> bytes:
        """
        Derive a compressed 32-byte public key from the current SK.
        The `compressed` parameter is ignored; Pallas always returns 32 bytes.
        """
        if self.sk is None:
            raise RuntimeError("SK not set. Call get_sk() or set_sk(sk_bytes).")
        pk = self._rs.get_pk_from_sk()
        if not isinstance(pk, (bytes, bytearray)):
            try:
                pk = bytes(pk)
            except Exception as e:
                raise TypeError(f"Rust returned PK in unexpected format: {e}")
        self.pk = bytes(pk)
        return self.pk

    def get_pk_cached(self) -> Optional[bytes]:
        """
        Return the cached PK derived earlier, or retrieve it from the
        Rust-side cache if available. Returns None if no PK is cached.
        """
        if self.pk is not None:
            return self.pk
        rs_cached = self._rs.get_pk_cached()
        if rs_cached is None:
            return None
        if not isinstance(rs_cached, (bytes, bytearray)):
            try:
                rs_cached = bytes(rs_cached)
            except Exception:
                return None
        self.pk = bytes(rs_cached)
        return self.pk

    # ---------------- Sign / Verify ----------------

    def sign(self, msg: BytesLike) -> Tuple[bytes, bytes, bytes]:
        """
        Sign a message using the current SK.
        Returns a tuple:
            (r_bytes, s_bytes, raw_signature)
        where raw_signature = r_bytes || s_bytes (64 bytes).
        """
        if self.sk is None:
            raise RuntimeError("SK not set. Cannot sign without SK.")
        if not isinstance(msg, (bytes, bytearray, memoryview)):
            raise TypeError("message must be bytes-like")

        m = bytes(msg)

        raw_sig = self._rs.sign(m)
        if not isinstance(raw_sig, (bytes, bytearray)):
            try:
                raw_sig = bytes(raw_sig)
            except Exception as e:
                raise TypeError(f"Rust returned signature in unexpected format: {e}")
        raw_sig = bytes(raw_sig)

        if len(raw_sig) != 64:
            raise RuntimeError(f"unexpected signature length {len(raw_sig)} (expected 64)")

        r = raw_sig[:32]
        s = raw_sig[32:]
        return r, s, raw_sig

    def verify_signature(
        self,
        signature: Union[BytesLike, Tuple[BytesLike, BytesLike], bytes],
        msg: BytesLike,
    ) -> bool:
        """
        Verify a signature.
        Signature may be:
            - raw 64-byte bytes (r||s), or
            - a tuple (r_bytes, s_bytes)
        msg must be bytes-like.
        Returns a boolean from Rust verify().
        """
        if not isinstance(msg, (bytes, bytearray, memoryview)):
            raise TypeError("message must be bytes-like")

        m = bytes(msg)

        if isinstance(signature, (bytes, bytearray, memoryview)):
            raw_sig = bytes(signature)
        elif isinstance(signature, (list, tuple)) and len(signature) == 2:
            r_part, s_part = signature
            if not isinstance(r_part, (bytes, bytearray, memoryview)) or not isinstance(s_part, (bytes, bytearray, memoryview)):
                raise TypeError("r and s parts must be bytes-like")
            raw_sig = bytes(r_part) + bytes(s_part)
        else:
            raise TypeError("signature must be raw 64 bytes or a (r_bytes, s_bytes) tuple")

        if len(raw_sig) != 64:
            return False

        ok = self._rs.verify(m, raw_sig)
        return bool(ok)

    # ---------------- Debug Utilities ----------------

    def derive_and_print(self):
        """Debug utility: ensure SK exists, derive PK, and print basic information."""
        if self.sk is None:
            self.get_sk()
        pk = self.get_pk_from_sk(True)
        print(f"SK type: {type(self.sk)} len: {len(self.sk)}")
        print(f"PK type: {type(pk)} len: {len(pk)}")
        print("SK hex prefix:", binascii.hexlify(self.sk)[:64].decode())
        print("PK hex prefix:", binascii.hexlify(pk)[:128].decode())

    def __repr__(self):
        skh = binascii.hexlify(self.sk[:4]).decode() + "..." if self.sk else "None"
        pkh = binascii.hexlify(self.pk[:4]).decode() + "..." if self.pk else "None"
        return f"<ecc_keys sk={skh} pk={pkh}>"
