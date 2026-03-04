# Branch Comparison: `bitcoin-support` vs `feat/bitcoin-support`

Both branches add Bitcoin P2WPKH (native SegWit) support to the library, but they were produced independently by different AI models in different environments.

## Session metadata

| | `bitcoin-support` | `feat/bitcoin-support` |
|---|---|---|
| **Model** | Claude Sonnet 4.6 | Claude Opus 4.6 (extended thinking) |
| **Tool** | Claude Code CLI | Cursor IDE |
| **Approx. tokens** | ~50k (single session) | ~2M |
| **Commits** | 2 | 2 |

---

## Dependencies

| Crate | `bitcoin-support` | `feat/bitcoin-support` |
|---|---|---|
| `ripemd` | `0.2.0-rc.5` (pre-release) | `0.1` (stable) |
| `bech32` | `0.9` (legacy API) | `0.11` (current API) |
| `sha2` | `0.10` | `0.10` |

**Impact:** `ripemd 0.2.0-rc.5` pulls in `digest 0.11`, which conflicts with `sha2 0.10`'s `digest 0.10`. This forced a workaround in `bitcoin-support`. `ripemd 0.1` uses the same `digest 0.10` as `sha2`, so `feat/bitcoin-support` has no conflict and a simpler dependency tree (no `hybrid-array`, `block-buffer 0.12`, `const-oid 0.10`, `crypto-common 0.2`).

---

## `BitcoinPrivateKey` struct

**`bitcoin-support`** — tuple struct:
```rust
pub struct BitcoinPrivateKey([u8; 32]);
```

**`feat/bitcoin-support`** — named struct:
```rust
pub struct BitcoinPrivateKey {
    key: [u8; 32],
}
```

Named fields are more idiomatic and self-documenting. Field access via `.key` is clearer than `.0`.

---

## `BitcoinAddress` struct

**`bitcoin-support`** — tuple struct, stores only the encoded string:
```rust
pub struct BitcoinAddress(String);

impl std::fmt::Display for BitcoinAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
```

**`feat/bitcoin-support`** — named struct, stores both the raw witness program and the encoded string:
```rust
pub struct BitcoinAddress {
    witness_program: [u8; 20],
    encoded: String,
}

impl BitcoinAddress {
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.witness_program
    }
}
```

`feat/bitcoin-support`'s design is richer: callers can access the raw 20-byte HASH160 without re-decoding the bech32 string. This mirrors the pattern used by `EvmAddress` (which also exposes `as_bytes()`).

---

## Key validation

**`bitcoin-support`** — manual byte-by-byte comparison against the hardcoded curve order:
```rust
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, ...
];

pub fn is_valid(bytes: &[u8]) -> bool {
    if bytes.iter().all(|&b| b == 0) { return false; }
    for i in 0..32 {
        if bytes[i] < SECP256K1_ORDER[i] { return true; }
        else if bytes[i] > SECP256K1_ORDER[i] { return false; }
    }
    false
}
```

**`feat/bitcoin-support`** — delegates entirely to the `secp256k1` crate:
```rust
fn is_valid(bytes: &[u8]) -> bool {
    if bytes.len() != 32 { return false; }
    SecretKey::from_slice(bytes).is_ok()
}

fn new(bytes: &[u8]) -> Option<Self> {
    if bytes.len() != 32 { return None; }
    SecretKey::from_slice(bytes).ok()?;
    ...
}
```

`feat/bitcoin-support`'s approach is simpler and guaranteed to be correct since the `secp256k1` library is the authoritative source of truth for validity. The manual approach in `bitcoin-support` duplicates logic already present in the library, creating a maintenance risk if the curve parameters were ever to differ (unlikely but possible across library versions).

---

## Hash functions (`sha256d` / `hash160`)

**`bitcoin-support`** — scoped `use` blocks to work around the `digest 0.10` vs `0.11` conflict, with `.to_vec()` to cross the type boundary:
```rust
fn sha256d(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let first = Sha256::digest(data).to_vec();
    let second = Sha256::digest(&first).to_vec();
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha: Vec<u8> = { use sha2::Digest; Sha256::digest(data).to_vec() };
    let ripe: Vec<u8> = { use ripemd::Digest; Ripemd160::digest(&sha).to_vec() };
    let mut result = [0u8; 20];
    result.copy_from_slice(&ripe);
    result
}
```

**`feat/bitcoin-support`** — clean, idiomatic, no workaround needed:
```rust
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(&first).into()
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    Ripemd160::digest(&sha).into()
}
```

`feat/bitcoin-support` is substantially cleaner. The `.into()` conversion from `GenericArray` to `[u8; N]` works because both crates share the same `digest` version. `bitcoin-support`'s workaround (`to_vec()` + `copy_from_slice`) allocates heap memory unnecessarily on each hash call.

---

## Bech32 encoding

**`bitcoin-support`** — uses the bech32 0.9 API, manually constructing the 5-bit data vector:
```rust
let witness_version = bech32::u5::try_from_u8(0).unwrap();
let hash_5bit = bech32::convert_bits(&h160, 8, 5, true).unwrap();
let mut data: Vec<bech32::u5> = vec![witness_version];
data.extend(hash_5bit.iter().map(|&b| bech32::u5::try_from_u8(b).unwrap()));
let address = bech32::encode("bc", data, bech32::Variant::Bech32)
    .expect("bech32 encoding should not fail");
```

**`feat/bitcoin-support`** — uses the bech32 0.11 SegWit-specific API:
```rust
let hrp = bech32::Hrp::parse_unchecked("bc");
let encoded = bech32::segwit::encode(hrp, bech32::segwit::VERSION_0, &witness_program)
    .expect("valid witness program");
```

`feat/bitcoin-support`'s API is far cleaner. `bech32::segwit::encode` handles the bit conversion and witness version internally, reducing the risk of mistakes. The 0.9 API in `bitcoin-support` requires manual bit manipulation that is error-prone.

---

## WIF encoding/decoding

Both branches produce identical WIF output, but the code organisation differs.

**`bitcoin-support`** — WIF logic is inline inside `to_string` and `from_string`:
```rust
fn from_string(string: &str) -> Option<Self> {
    // Try WIF: 38 decoded bytes with correct version and compression flag
    if let Ok(decoded) = bs58::decode(string).into_vec() {
        if decoded.len() == 38 && decoded[0] == 0x80 && decoded[33] == 0x01 {
            let payload = &decoded[..34];
            let checksum = &decoded[34..38];
            let expected = sha256d(payload);
            if checksum == &expected[..4] {
                return Self::new(&decoded[1..33]);
            }
        }
    }
    // Fall back to hex
    ...
}
```

**`feat/bitcoin-support`** — extracts `to_wif()` and `from_wif()` as dedicated public methods, and guards on the leading WIF character before attempting to decode:
```rust
pub fn to_wif(&self) -> String { ... }
pub fn from_wif(wif: &str) -> Option<[u8; 32]> { ... }

fn from_string(string: &str) -> Option<Self> {
    if string.starts_with('K') || string.starts_with('L') || string.starts_with('5') {
        let key_bytes = BitcoinPrivateKey::from_wif(string)?;
        return Self::new(&key_bytes);
    }
    // Fall back to hex
    ...
}
```

`feat/bitcoin-support`'s design is better for two reasons:
1. `to_wif()` and `from_wif()` are reusable public API surface.
2. The leading-character guard (`K`/`L`/`5`) avoids attempting a base58 decode on hex strings, and also correctly handles uncompressed WIF keys (prefix `5`), which `bitcoin-support` silently rejects.

---

## Additional files changed

| File | `bitcoin-support` | `feat/bitcoin-support` |
|---|---|---|
| `CLAUDE.md` | Not updated | Updated with `src/bitcoin/` architecture note |
| `examples/multi_blockchain_generator.rs` | Not updated | Updated with Bitcoin key generation example |
| `src/bitcoin/mod.rs` | Minimal doc comment | Full module-level rustdoc with feature list and code example |
| `src/lib.rs` | Added `pub mod bitcoin` | Added `pub mod bitcoin` + updated feature list + module overview |

---

## Test coverage

| Test | `bitcoin-support` | `feat/bitcoin-support` |
|---|---|---|
| Key creation | `test_bitcoin_key_creation` | `test_bitcoin_private_key_creation` |
| Address prefix `bc1q` | `test_bitcoin_address_starts_with_bc1q` | `test_bitcoin_address_is_p2wpkh` |
| Address length (42 chars) | `test_bitcoin_address_length` | — (implicit in known vector) |
| Deterministic address | `test_bitcoin_deterministic_address` | `test_bitcoin_deterministic_address` |
| Known BIP test vector | `test_known_address` (format only) | `test_bitcoin_known_vector` (exact address `bc1qw508d...`) |
| Invalid key — zeros | `test_bitcoin_invalid_key_zeros` | `test_invalid_bitcoin_key` |
| Invalid key — above order | `test_bitcoin_invalid_key_above_order` | — |
| Invalid key — wrong size | — | `test_invalid_bitcoin_key` |
| WIF round-trip | `test_wif_roundtrip` | `test_wif_roundtrip` |
| Hex round-trip | `test_hex_roundtrip` | `test_bitcoin_from_string_hex` |
| Bad WIF checksum | `test_invalid_wif_bad_checksum` | — |
| `as_bytes()` length | — | `test_bitcoin_address_bytes` |
| 23 derivation vectors | `test_address_derivation_vectors` | `test_address_derivation_vectors` |

`bitcoin-support` has broader negative-path coverage (bad checksum, above-order key). `feat/bitcoin-support` has a stronger positive known-vector test with an exact expected address from the Bitcoin BIP-173 test suite.

---

## Summary verdict

`feat/bitcoin-support` is the cleaner implementation across every dimension:

- **Simpler dependency graph** — avoids the `digest` version conflict entirely by using `ripemd 0.1`
- **Better bech32 API** — `bech32 0.11`'s `segwit::encode` is purpose-built for this use case
- **More idiomatic structs** — named fields, `as_bytes()` on the address type
- **Cleaner validation** — delegates to `secp256k1` rather than duplicating curve order logic
- **Better WIF API** — public `to_wif()`/`from_wif()` methods, handles uncompressed keys
- **More documentation** — updated CLAUDE.md, module-level rustdoc, examples

The extra tokens and extended thinking time are visible in the quality of the output.
