# Branch comparison: bitcoin-support vs feat/bitcoin-support

This document compares the **bitcoin-support** and **feat/bitcoin-support** branches in detail, including implementation choices, dependencies, CLI behavior, and session metadata (tokens and models used to develop each branch).

---

## Session and model metadata

| Branch | Environment | Model | Tokens (approx.) |
|--------|-------------|--------|-------------------|
| **bitcoin-support** | Claude Code (claude.ai/code) | Claude Sonnet | ~100K |
| **feat/bitcoin-support** | Cursor IDE | Opus 4.6 (thinking) | ~2M |

The feat/bitcoin-support branch was developed with a much larger context (2M tokens) and a thinking model in Cursor; the bitcoin-support branch was developed with a smaller context (100K tokens) and Claude Code with Sonnet.

---

## Commit history

### bitcoin-support

- `6271319` — Add address derivation test vectors for Bitcoin P2WPKH  
- `9a825e7` — Bitcoin P2WPKH support with WIF key encoding  
- `6076a22` — Document --rng incremental option in README and add CLAUDE.md (#6)  
- (then mainline history)

### feat/bitcoin-support

- `0afb4c3` — Add address derivation test vectors for Bitcoin P2WPKH  
- `d927dee` — Add Bitcoin support with P2WPKH (native SegWit) addresses  
- `6076a22` — Document --rng incremental option in README and add CLAUDE.md (#6)  
- (then mainline history)

Both branches add the same 20 test vectors; the base Bitcoin implementation is introduced in different commits (`9a825e7` vs `d927dee`) and differs in design and dependencies.

---

## 1. Dependencies (Cargo.toml)

| Crate | bitcoin-support | feat/bitcoin-support |
|-------|-----------------|----------------------|
| **ripemd** | `0.2.0-rc.5` | `0.1` |
| **bech32** | `0.9` | `0.11` |

- **bitcoin-support** uses a release-candidate of `ripemd` and an older `bech32` API.
- **feat/bitcoin-support** uses stable `ripemd` 0.1 and `bech32` 0.11, which has a different, more structured API (e.g. `bech32::Hrp`, `bech32::segwit::encode`).

---

## 2. Bitcoin module: data structures and API

### 2.1 Type definitions

**bitcoin-support**

- `BitcoinPrivateKey([u8; 32])` — tuple struct; key bytes accessed as `self.0`.
- `BitcoinAddress(String)` — wraps only the Bech32 string; no separate witness program storage.

**feat/bitcoin-support**

- `BitcoinPrivateKey { key: [u8; 32] }` — named struct; key bytes via `self.key`.
- `BitcoinAddress { witness_program: [u8; 20], encoded: String }` — stores both the 20-byte witness program (HASH160) and the pre-encoded Bech32 string, with:
  - `Display` implemented to show `encoded`.
  - `pub fn as_bytes(&self) -> &[u8; 20]` returning the witness program.

So feat/bitcoin-support exposes the raw address bytes and keeps encoding separate from the binary form; bitcoin-support only exposes the string.

### 2.2 Validation

**bitcoin-support**

- Manual scalar validation against the secp256k1 curve order:
  - `SECP256K1_ORDER` constant (32 bytes).
  - `BitcoinPrivateKey::is_valid(bytes)` checks length, non-zero, and bytewise comparison with `SECP256K1_ORDER`.
- `PrivateKey::new` and `is_valid` both use this custom check; `SecretKey::from_slice` is only used later in `derive_address`.

**feat/bitcoin-support**

- No manual order constant. Validation is delegated to the secp256k1 library:
  - `PrivateKey::is_valid(bytes)` returns `SecretKey::from_slice(bytes).is_ok()`.
  - `PrivateKey::new` uses `SecretKey::from_slice(bytes).ok()?` and then copies into `Self { key }`.

So one branch implements curve-order checks by hand; the other relies on the library and avoids duplication and possible mistakes in the comparison logic.

### 2.3 Hashing and digest usage

**bitcoin-support**

- Comment documents a version mismatch: *"sha2 uses digest 0.10, ripemd uses digest 0.11"*.
- Uses scoped `use sha2::Digest` and `use ripemd::Digest` and `.to_vec()` to bridge digest output types:
  - `sha256d`: `Sha256::digest(...).to_vec()` then `Sha256::digest(&first).to_vec()` → copy into `[u8; 32]`.
  - `hash160`: `Sha256::digest(data).to_vec()`, then `Ripemd160::digest(&sha).to_vec()`, then copy into `[u8; 20]`.

**feat/bitcoin-support**

- Single `use sha2::Digest`; no scoped ripemd Digest import.
- Uses `.into()` for fixed-size arrays:
  - `double_sha256`: `Sha256::digest(&first).into()`.
  - `hash160`: `Ripemd160::digest(&sha).into()`.
- Function is named `double_sha256` instead of `sha256d` (same semantics).

This reflects different digest crate versions and a cleaner type flow on feat/bitcoin-support.

### 2.4 WIF (Wallet Import Format)

**bitcoin-support**

- WIF encoding is inside `PrivateKey::to_string`: builds payload `[0x80, key[32], 0x01]`, `sha256d` checksum, then `bs58::encode(payload)`.
- WIF decoding is inline in `from_string`: `bs58::decode(string).into_vec()`, then checks `len() == 38`, `decoded[0] == 0x80`, `decoded[33] == 0x01`, checksum via `sha256d`, then `Self::new(&decoded[1..33])`. So only **compressed** WIF (38 decoded bytes) is accepted.

**feat/bitcoin-support**

- Dedicated public API:
  - `BitcoinPrivateKey::to_wif(&self) -> String` — same scheme (0x80, key, 0x01, double_sha256 checksum, bs58).
  - `BitcoinPrivateKey::from_wif(wif: &str) -> Option<[u8; 32]>` — validates checksum, version 0x80, then supports:
    - 34-byte payload with `payload[33] == 0x01` (compressed) → key bytes `[1..33]`.
    - 33-byte payload (uncompressed) → key bytes `[1..33]`.
- `PrivateKey::to_string` delegates to `self.to_wif()`.
- `from_string` accepts WIF if the string starts with `'K'`, `'L'`, or `'5'` (so both compressed and uncompressed WIF), and otherwise falls back to hex.

So feat/bitcoin-support supports uncompressed WIF and exposes a clear WIF API; bitcoin-support only supports compressed WIF and keeps WIF logic inside the trait implementation.

### 2.5 Bech32 encoding

**bitcoin-support** (bech32 0.9)

- Manual construction: `bech32::u5::try_from_u8(0)` for witness version, `bech32::convert_bits(&h160, 8, 5, true)`, build `Vec<bech32::u5>`, then `bech32::encode("bc", data, bech32::Variant::Bech32)`.

**feat/bitcoin-support** (bech32 0.11)

- Segwit-specific API: `bech32::Hrp::parse_unchecked("bc")`, then `bech32::segwit::encode(hrp, bech32::segwit::VERSION_0, &witness_program)`.

Same behavior, different crate versions and style (manual vs segwit helper).

### 2.6 LazyLock

- **bitcoin-support**: `LazyLock::new(|| Secp256k1::new())`.
- **feat/bitcoin-support**: `LazyLock::new(Secp256k1::new)` (closure not needed).

---

## 3. Tests (private_key.rs)

Both branches include:

- Key creation, address prefix `bc1q`, deterministic derivation, invalid key (zeros / wrong size), WIF roundtrip, hex roundtrip, and the same 20 address derivation vectors.

**bitcoin-support additionally**

- `test_bitcoin_address_length` — asserts P2WPKH address length is 42.
- `test_bitcoin_invalid_key_above_order` — asserts key above curve order is rejected (relies on manual `SECP256K1_ORDER` check).
- `test_invalid_wif_bad_checksum` — corrupts checksum and expects `from_string` to return `None`.
- `test_known_address` — private key `0x01..01`, checks `bc1q` and length 42 (no exact address asserted).
- Uses `PrivateKey as PrivateKeyTrait` in test module.

**feat/bitcoin-support additionally**

- `test_bitcoin_known_vector` — private key with last byte 1, expects exact address `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`.
- `test_bitcoin_from_string_hex` — hex input without 0x prefix (via `format!("0x{}", "42".repeat(32))`).
- `test_bitcoin_address_bytes` — asserts `address.as_bytes().len() == 20` (uses the new `BitcoinAddress::as_bytes()`).

So: bitcoin-support tests validation and WIF checksum more explicitly; feat/bitcoin-support tests one exact address vector and the new address-bytes API.

---

## 4. CLI and main.rs

### 4.1 Help and messages

| Location | bitcoin-support | feat/bitcoin-support |
|----------|-----------------|----------------------|
| Derive `private_key` help | "Private key (hex for EVM, base58 keypair for Solana). Reads from stdin if omitted" | Adds "WIF for Bitcoin". |
| Vanity `prefix` / `suffix` help | "hex for EVM, base58 for Solana" | Adds "bech32 for Bitcoin". |
| ChainType Bitcoin | "Bitcoin (P2WPKH / native SegWit, bc1q addresses)" | "Bitcoin (P2WPKH native SegWit)". |
| Incremental RNG error | "only supported for EVM (secp256k1)" | "only supported for EVM". |
| Bitcoin derive error (accepted formats) | "WIF (Wallet Import Format, starts with K or L for compressed mainnet)" | "WIF (starts with K, L, or 5)". |
| Success output label | "Address:" | "Address (P2WPKH):". |

### 4.2 Bitcoin vanity search

**bitcoin-support**

- No validation of vanity pattern characters.
- Treats `bc1q` as fixed: computes `effective_prefix = prefix.strip_prefix("bc1q")` for search space; uses `display_prefix` for user-facing text and `search_prefix` for calculation.
- Message: "Searching for Bitcoin vanity address...", "Prefix: … (N chars)", "Suffix: … (N chars)".

**feat/bitcoin-support**

- Validates that prefix and suffix use only valid Bech32 characters:
  - `BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"`.
  - `validate_bech32_pattern()` exits with an error if any other character is used.
- No stripping of `bc1q`; prefix/suffix are used as given in the search space.
- Message: "Searching for Bitcoin P2WPKH vanity address...", "… (N bech32 chars)".
- Adds `validate_bech32_pattern()` and uses it before running the search.

So feat/bitcoin-support enforces Bech32 alphabet and avoids special-case handling of the `bc1q` prefix in the search logic.

### 4.3 Search space (calculate_bech32_search_space)

- **bitcoin-support**: Comment "bech32 charset has 32 characters" above the calculation.
- **feat/bitcoin-support**: That comment removed; logic unchanged (32^prefix_len * 32^suffix_len).

---

## 5. Library surface and docs

### 5.1 CLAUDE.md

- **feat/bitcoin-support** adds a bullet under "Blockchain modules" describing the Bitcoin module: 32-byte secp256k1, P2WPKH, HASH160, Bech32 `bc1q…`, WIF, and crates `sha2`, `ripemd`, `bech32`.

### 5.2 src/lib.rs

- **feat/bitcoin-support** updates the feature list to "EVM, Solana, and Bitcoin" and adds `[`bitcoin`]` to the module list with "Bitcoin key support (P2WPKH native SegWit)".

### 5.3 src/bitcoin/mod.rs

- **bitcoin-support**: Short module doc (P2WPKH/Bech32, WIF, mainnet).
- **feat/bitcoin-support**: Longer module doc with "Key Features" (secp256k1, WIF, P2WPKH derivation, BIP-173) and an example showing generator + Bitcoin key + `to_string()` and `derive_address()`.

### 5.4 examples/multi_blockchain_generator.rs

- **feat/bitcoin-support** adds:
  - `bitcoin::PrivateKey as BitcoinKey`.
  - A "Bitcoin Keys" section: 3 keys generated, printed as WIF and P2WPKH address and byte count.
  - Bitcoin key size in the "Key Size Information" section.
  - Alignment tweaks for "EVM key size" / "Solana key size" (spacing).

---

## 6. Summary table

| Aspect | bitcoin-support | feat/bitcoin-support |
|--------|-----------------|----------------------|
| **Session** | Claude Code, Sonnet, ~100K tokens | Cursor IDE, Opus 4.6 thinking, ~2M tokens |
| **Private key type** | Tuple `([u8; 32])` | Named `{ key: [u8; 32] }` |
| **Address type** | `String` only | `{ witness_program, encoded }` + `as_bytes()` |
| **Validation** | Manual `SECP256K1_ORDER` | `SecretKey::from_slice(...).is_ok()` |
| **Digest / hashing** | Scoped Digest, `.to_vec()` bridge | Single Digest, `.into()` |
| **WIF** | Inline in trait; compressed only (38 bytes) | `to_wif()` / `from_wif()`; compressed + uncompressed (33/34) |
| **bech32** | 0.9, manual u5 / convert_bits / encode | 0.11, `segwit::encode` |
| **ripemd** | 0.2.0-rc.5 | 0.1 |
| **Vanity** | Optional strip of `bc1q`, no char check | Bech32 character validation, no strip |
| **Docs / examples** | Minimal | CLAUDE.md, lib.rs, mod.rs, multi_blockchain example |

---

## 7. File change stats (feat/bitcoin-support vs bitcoin-support)

```
CLAUDE.md                              |   2 +
Cargo.lock                             |  66 ++------
Cargo.toml                             |   4 +-
examples/multi_blockchain_generator.rs |  23 ++-
src/bitcoin/mod.rs                     |  29 +++-
src/bitcoin/private_key.rs             | 297 ++++++++++++++++-----------------
src/lib.rs                             |   3 +-
src/main.rs                            |  55 +++---
8 files changed, 239 insertions(+), 240 deletions(-)
```

Overall, feat/bitcoin-support refactors the Bitcoin module (types, validation, WIF API, dependencies), adds Bech32 validation and clearer CLI copy, and expands documentation and examples. The bitcoin-support branch delivers a working, more minimal implementation with manual curve validation and compressed-only WIF.
