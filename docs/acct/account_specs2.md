# Account Semantics

Purpose of this file
- This file explains what each Account field means and how fields relate to each other.
- Data types and value domains are defined in the dedicated AccountSpecs file; this file does not restate them.

---

## Account categories (Color)

- `Color = 0`: normal account (default on-chain state).
- `Color = 1`: privileged account (sometimes called a “blue-addr” account). It is set after a successful identity / BlueApply flow.

---

## Fields and semantics

### 1) ecc_keypair

- Role: local key material that controls this account.
- Stored as an internal ECC keypair type (`EccKeypair` Python class).
- Provides SK/PK generation, signing, and verification on the Pallas curve.
- Detailed usage and exact byte formats are documented in the ECC keypair documentation of this project.

---

### 2) addr (address)

- Role: the on-chain identifier of the account; used as the lookup key in Client↔Node messages and in node state.

- Exact derivation rule (no ambiguity):

  1. Obtain the account public key by calling:
     ```python
     pk_bytes = ecc_keypair.get_pk_from_sk()
     ```
     where `pk_bytes` is the compressed 32-byte PK as returned by `EccKeypair`.

  2. Compute the address using the project’s Poseidon internal API:
     ```python
     addr = get_poseidon_hash(pk_bytes)
     ```

- Notes:
  - The hash function used here is exactly `get_poseidon_hash` from this project.
  - For the precise Poseidon input formatting and reduction rules, see the `get_poseidon_hash` documentation in this project.
  - Because `addr` hashes the compressed PK bytes (`pk_bytes`), the address is bound to that compressed representation.

---

### 3) balance

- Role: transparent (address-based) spendable value owned by this account.
- Updated by transparent protocol actions (for example, `Transfer`, BlueApply rewards, and other address-based flows).
- Default on-chain state is `0`.

---

### 4) nonce

- Role: per-address anti-replay counter for transparent protocol actions.

- Consumption rule:

  - On-chain stored `nonce` starts at `0`.
  - A new valid request that uses this account must carry:
    ```text
    nonce_payload = nonce_on_chain + 1
    ```
  - After the request is accepted, on-chain `nonce` becomes `nonce_payload`.

- This is a pre-increment style counter used for `BlueApply` and `Transfer`.
- Whenever a protocol action with this account as the subject is approved, the account’s `nonce` increases by `1`.

---

### 5) IDCard

- Role: minimal on-chain identity tag bound to an address.

- Structure:
  - `Color`: category tag (`0` for normal, `1` for privileged).
  - `ID`: identity integer installed by BlueApply.

- Defaults:
  - Default on-chain state has `Color = 0` and `ID = 0`.
  - Privileged state sets `Color = 1` and writes `ID` according to BlueApply logic.

---

### 6) lst_of_commits

- Role: commitments owned by this account for the anonymous/shielded pool.

- Semantics:
  - Each element in `lst_of_commits` is a commitment belonging to this account.
  - These commitments correspond to anonymous notes that are ultimately controlled by the same secret key as the account’s `ecc_keypair.SK`.

- Defaults and maintenance:
  - Default on-chain state is an empty list `[]`.
  - The detailed maintenance rules for `lst_of_commits` (when commits are appended or spent) are defined in the anonymous transaction specifications. This file only specifies the ownership meaning.
