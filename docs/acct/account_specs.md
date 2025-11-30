# Account Specs (Canonical)

Scope
- Defines the public account protocol only.
- Describes:
  (1) the blockchain-default state of an Account with no prior operations,
  (2) canonical data types / encodings,
  (3) value domains (allowed ranges) for Account fields.
- Does not define block storage layout or other consensus rules.

---

## 1. Account Fields (Canonical)

Account = {
  addr: Hex32,

  balance: FieldIntNonNeg,
  nonce: FieldIntNonNeg,

  IDCard: {
    Color: 0 or 1 (may have more colors in the future),
    ID: FieldIntNonNeg
  },

  lst_of_commits: List<Hex32>,

  ecc_keypair: EccKeypair
}

Notes:
- `ecc_keypair` is an internal container for the secret/public key of this account.
- On-chain state only exposes the public parts (addr, balance, nonce, IDCard, lst_of_commits).

---

## 2. Blockchain-Default Values

For any previously unseen `addr` (no on-chain operations yet):

DEFAULT_ACCOUNT_STATE(addr) = {
  addr: addr,

  balance: 0,
  nonce: 0,

  IDCard: {
    Color: 0,
    ID: 0
  },

  lst_of_commits: []
}

Notes:
- `ecc_keypair` has no blockchain-default value. It is a local key container used by clients and nodes.

---

## 3. Constants

Deleted.

---

## 4. Data Types and Domains

### Hex32

- Definition: hex string encoding exactly 32 bytes.
- Length: 64 hex characters.
- No `"0x"` prefix.
- Lowercase canonical form is recommended.
- Domain: any string `x` such that `len(bytes_from_hex(x)) == 32`.

### FieldIntNonNeg

- Non-negative integer.
- Domain: `0 <= x <= 2^96 - 1`.
- Used for:
  - `balance`
  - `nonce`
  - `IDCard.ID`

### List<Hex32>

- Ordered list (possibly empty).
- Each element is a `Hex32`.

### EccKeypair

- Internal data type used to store the account’s secret/public key material.
- Its detailed domain/range is defined in the ECC keypair documentation of this project.

---

## 5. Missing-Field Semantics (when reading chain state)

If a field is absent in a block/state snapshot, interpret it as the default:

- missing `balance`        ⇒ `0`
- missing `nonce`          ⇒ `0`
- missing `IDCard`         ⇒ `{Color: 0, ID: 0}`
- missing `lst_of_commits` ⇒ `[]`
