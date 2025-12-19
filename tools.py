import hashlib
import sys

from wrappers.poseidon_hash_wrapper import get_poseidon_hash

CA_SK_HEX = "17b91c4b7c1c2af81ab380624f40d68e16dac5a170d77d8d286dc99a430a0231"
CA_PK_HEX = "2cc399f82589cda838811c8d192305e5ef9067c5e3af8593c166db0f4c02d01e"

# Clerk key pair
CLERK_SK_HEX = "3c1a864ac0b382a5cc84ae61cdae8420d8beaaf87d74196ccdc6d47eae7a9c3b"
CLERK_PK_HEX = "df346e82887f95602d18d85c927807d9f22b9a324946ef17561715b8571020a6"

# Pallas Fp modulus and scalar field order
PALLAS_P = int(
    "40000000000000000000000000000000224698fc094cf91b992d30ed00000001",
    16
)
SCALAR_ORDER = int(
    "40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001",
    16
)


# ==========================================================
# Utility functions
# ==========================================================
def turn_hex_str_to_bytes(s) -> bytes:
    """
    Convert bytes or a hex string (with or without 0x prefix) into bytes.
    Raise ValueError if the input is an invalid hex string.
    """
    if isinstance(s, (bytes, bytearray)):
        return bytes(s)

    if not isinstance(s, str):
        raise TypeError("turn_hex_str_to_bytes only accepts str or bytes")

    s2 = s.strip()
    if s2.startswith(("0x", "0X")):
        s2 = s2[2:]
    if len(s2) % 2 != 0:
        raise ValueError("hex string length must be even")
    try:
        return bytes.fromhex(s2)
    except Exception as e:
        raise ValueError("invalid hex string: " + repr(e))


def derive_master_seed_from_password(password: str) -> bytes:
    """
    Derive master seed from a user password.
    Use SHA256 then reduce mod PALLAS_P.
    """
    pw_bytes = password.encode("utf-8")
    digest = hashlib.sha256(pw_bytes).digest()
    digest_int = int.from_bytes(digest, "big")
    reduced = digest_int % PALLAS_P
    return reduced.to_bytes(32, "big")


def get_hash(data) -> str:
    """
    Compute SHA256 hash and return hex string.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def verify_account_merkle_proof(account, lst_of_siblings, account_root) -> bool:
    """
    Verify the Merkle proof for an account using Poseidon hash.

    lst_of_siblings is an ordered proof:
        [ (sibling_hex, "L"/"R"), ... ]
    "L": sibling is on the left  -> parent = H(sibling, current)
    "R": sibling is on the right -> parent = H(current, sibling)
    """
    leaf_hex = account.get_self_poseidon_hash()

    def _norm_hex(s: str) -> str:
        ss = s.strip()
        if ss.startswith(("0x", "0X")):
            ss = ss[2:]
        return ss.lower()

    cur = _norm_hex(leaf_hex)

    i = 0
    while i < len(lst_of_siblings):
        item = lst_of_siblings[i]
        sib_hex = item[0]
        direction = item[1]

        sib_norm = _norm_hex(sib_hex)

        if direction == "L":
            cur = get_poseidon_hash(sib_norm, cur)
        else:
            cur = get_poseidon_hash(cur, sib_norm)

        i += 1

    root_norm = _norm_hex(account_root)
    return cur == root_norm


def run_silently(func, *args, **kwargs):
    """
    Run func(*args, **kwargs) while discarding all stdout/stderr.

    This hides:
      - Python print() inside func
      - OS-level stdout/stderr (e.g. Rust println! in the zk-verifier)
    """
    import io
    import os

    old_py_stdout = sys.stdout
    sys.stdout = io.StringIO()

    fd_out = sys.__stdout__.fileno()
    fd_err = sys.__stderr__.fileno()
    saved_fd_out = os.dup(fd_out)
    saved_fd_err = os.dup(fd_err)

    devnull_fd = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull_fd, fd_out)
    os.dup2(devnull_fd, fd_err)
    os.close(devnull_fd)

    result = func(*args, **kwargs)

    os.dup2(saved_fd_out, fd_out)
    os.dup2(saved_fd_err, fd_err)
    os.close(saved_fd_out)
    os.close(saved_fd_err)
    sys.stdout = old_py_stdout

    return result


def short_hex(h, prefix_len=8):
    """
    Return a shortened hex string like abcd1234...9f0a.
    If h is bytes or bytearray, convert to hex string first.
    If h is not a string or hex string is already short, return as-is.
    """
    if isinstance(h, (bytes, bytearray)):
        s = bytes(h).hex()
    else:
        s = h

    if not isinstance(s, str):
        return s

    if len(s) <= prefix_len * 2:
        return s

    head = s[:prefix_len]
    tail = s[-4:]
    return head + "..." + tail