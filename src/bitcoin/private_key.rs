//! Bitcoin private key implementation
//!
//! Implements P2WPKH (native SegWit/Bech32) addresses for Bitcoin mainnet.
//! Private keys are represented in Wallet Import Format (WIF).

use crate::PrivateKey;
use secp256k1::{All, PublicKey, Secp256k1, SecretKey};
use sha2::Sha256;
use ripemd::Ripemd160;
use std::sync::LazyLock;

static SECP: LazyLock<Secp256k1<All>> = LazyLock::new(|| Secp256k1::new());

/// The order (n) of the secp256k1 elliptic curve
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

#[derive(Debug, Clone, PartialEq)]
pub struct BitcoinPrivateKey([u8; 32]);

/// Bitcoin P2WPKH (native SegWit) address — a bech32-encoded string starting with `bc1q`.
#[derive(Debug, Clone, PartialEq)]
pub struct BitcoinAddress(String);

impl std::fmt::Display for BitcoinAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl BitcoinPrivateKey {
    pub fn is_valid(bytes: &[u8]) -> bool {
        if bytes.len() != 32 {
            return false;
        }
        if bytes.iter().all(|&b| b == 0) {
            return false;
        }
        for i in 0..32 {
            if bytes[i] < SECP256K1_ORDER[i] {
                return true;
            } else if bytes[i] > SECP256K1_ORDER[i] {
                return false;
            }
        }
        false
    }
}

// sha2 uses digest 0.10, ripemd uses digest 0.11 — scope each Digest import separately
// to avoid the version conflict, and use .to_vec() to cross the type boundary.

fn sha256d(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let first = Sha256::digest(data).to_vec();
    let second = Sha256::digest(&first).to_vec();
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha: Vec<u8> = {
        use sha2::Digest;
        Sha256::digest(data).to_vec()
    };
    let ripe: Vec<u8> = {
        use ripemd::Digest;
        Ripemd160::digest(&sha).to_vec()
    };
    let mut result = [0u8; 20];
    result.copy_from_slice(&ripe);
    result
}

impl PrivateKey for BitcoinPrivateKey {
    type Address = BitcoinAddress;

    fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 || !Self::is_valid(bytes) {
            return None;
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);
        Some(Self(key_bytes))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Encodes the private key in Wallet Import Format (WIF) for a compressed key.
    ///
    /// Format: base58([0x80] ++ key_bytes ++ [0x01] ++ checksum)
    /// where checksum = sha256(sha256(payload))[0..4]
    fn to_string(&self) -> String {
        let mut payload = Vec::with_capacity(34);
        payload.push(0x80u8);
        payload.extend_from_slice(&self.0);
        payload.push(0x01u8); // compressed pubkey flag
        let checksum = sha256d(&payload);
        payload.extend_from_slice(&checksum[..4]);
        bs58::encode(payload).into_string()
    }

    /// Derives a P2WPKH (native SegWit) Bitcoin address (`bc1q...`).
    ///
    /// Derivation:
    /// 1. Compressed secp256k1 public key (33 bytes)
    /// 2. HASH160 = RIPEMD-160(SHA-256(pubkey))
    /// 3. Bech32-encode: witness version 0 + 5-bit encoded hash, HRP "bc"
    fn derive_address(&self) -> Self::Address {
        let secret_key = SecretKey::from_slice(&self.0).expect("key is valid secp256k1");
        let public_key = PublicKey::from_secret_key(&SECP, &secret_key);
        let compressed_pubkey = public_key.serialize(); // 33 bytes, compressed

        let h160 = hash160(&compressed_pubkey);

        let witness_version = bech32::u5::try_from_u8(0).unwrap();
        let hash_5bit = bech32::convert_bits(&h160, 8, 5, true).unwrap();
        let mut data: Vec<bech32::u5> = vec![witness_version];
        data.extend(hash_5bit.iter().map(|&b| bech32::u5::try_from_u8(b).unwrap()));

        let address = bech32::encode("bc", data, bech32::Variant::Bech32)
            .expect("bech32 encoding should not fail");
        BitcoinAddress(address)
    }

    fn is_valid(bytes: &[u8]) -> bool {
        BitcoinPrivateKey::is_valid(bytes)
    }

    fn key_size() -> usize {
        32
    }

    /// Parses a private key from WIF format or 0x-prefixed hex.
    ///
    /// WIF (Wallet Import Format):
    /// - Base58-encoded 38-byte payload: [0x80][32 key bytes][0x01][4 checksum bytes]
    /// - Checksum is verified before accepting
    ///
    /// Hex fallback:
    /// - 0x-prefixed 64-character hex string
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
        let clean_hex = string.strip_prefix("0x").unwrap_or(string);
        if clean_hex.len() != 64 {
            return None;
        }
        let bytes = hex::decode(clean_hex).ok()?;
        Self::new(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrivateKey as PrivateKeyTrait;

    #[test]
    fn test_bitcoin_key_creation() {
        let bytes = [0x12u8; 32];
        let key = BitcoinPrivateKey::new(&bytes).expect("Valid key");
        assert_eq!(key.as_bytes(), &bytes);
        assert_eq!(BitcoinPrivateKey::key_size(), 32);
    }

    #[test]
    fn test_bitcoin_address_starts_with_bc1q() {
        let bytes = [0x12u8; 32];
        let key = BitcoinPrivateKey::new(&bytes).unwrap();
        let address = key.derive_address().to_string();
        assert!(address.starts_with("bc1q"), "Expected bc1q prefix, got: {}", address);
    }

    #[test]
    fn test_bitcoin_address_length() {
        let bytes = [0x12u8; 32];
        let key = BitcoinPrivateKey::new(&bytes).unwrap();
        let address = key.derive_address().to_string();
        // P2WPKH bech32 address is always 42 characters
        assert_eq!(address.len(), 42, "Address length: {}", address.len());
    }

    #[test]
    fn test_bitcoin_deterministic_address() {
        let bytes = [1u8; 32];
        let key1 = BitcoinPrivateKey::new(&bytes).unwrap();
        let key2 = BitcoinPrivateKey::new(&bytes).unwrap();
        assert_eq!(key1.derive_address().to_string(), key2.derive_address().to_string());
    }

    #[test]
    fn test_bitcoin_invalid_key_zeros() {
        let zeros = [0u8; 32];
        assert!(BitcoinPrivateKey::new(&zeros).is_none());
    }

    #[test]
    fn test_bitcoin_invalid_key_above_order() {
        // 0xFF * 32 exceeds the curve order
        let too_large = [0xFFu8; 32];
        assert!(BitcoinPrivateKey::new(&too_large).is_none());
    }

    #[test]
    fn test_wif_roundtrip() {
        let bytes = [0x12u8; 32];
        let key = BitcoinPrivateKey::new(&bytes).unwrap();
        let wif = key.to_string();
        // Compressed mainnet WIF starts with 'K' or 'L'
        assert!(
            wif.starts_with('K') || wif.starts_with('L'),
            "Expected WIF starting with K or L, got: {}",
            wif
        );
        let restored = BitcoinPrivateKey::from_string(&wif).unwrap();
        assert_eq!(key, restored);
    }

    #[test]
    fn test_hex_roundtrip() {
        let bytes = [0x12u8; 32];
        let hex = format!("0x{}", hex::encode(bytes));
        let key = BitcoinPrivateKey::from_string(&hex).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_invalid_wif_bad_checksum() {
        let bytes = [0x12u8; 32];
        let key = BitcoinPrivateKey::new(&bytes).unwrap();
        let mut wif_bytes = bs58::decode(key.to_string()).into_vec().unwrap();
        wif_bytes[37] ^= 0xFF; // corrupt checksum
        let bad_wif = bs58::encode(wif_bytes).into_string();
        assert!(BitcoinPrivateKey::from_string(&bad_wif).is_none());
    }

    #[test]
    fn test_known_address() {
        // Known test vector: private key 0x0101...01
        // The exact address can be verified with a Bitcoin tool; we just check format here.
        let bytes = [0x01u8; 32];
        let key = BitcoinPrivateKey::new(&bytes).unwrap();
        let addr = key.derive_address().to_string();
        assert!(addr.starts_with("bc1q"));
        assert_eq!(addr.len(), 42);
    }

    #[test]
    fn test_address_derivation_vectors() {
        let vectors: &[(&str, &str)] = &[
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a250257240d", "bc1qk5jgaepcjg9hsenq3my53w9nx4l7qchvyeu8a5"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a250257240e", "bc1qz4edc53xa0g2qke6uy95qxg0at6kanzl456xmz"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a250257240f", "bc1qwhhu6952lchwtcavsp8qgu5xk06whd48v39hq5"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a2502572410", "bc1q7yz4g2jmgzxuu0fvh0g8zlnmefq879y2msxd9g"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a2502572411", "bc1qmlwvrzkj3nwu8v5zc7dkr4xjykny6cv7sas6u7"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a2502572412", "bc1quyhftjl54kx674dtpsq3ugwspaadacgspethxu"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a2502572413", "bc1qtp3978s46nmrv2gvd9njrrv38kt4h9wvg43d9p"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a2502572414", "bc1qjfa8c086n7ge4fx3gaf54h2ed57nmjs7ssvvme"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a2502572415", "bc1qxvulj2ht8sucks7du99lh4nsjf9sh2fvd9tjaf"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a2502572416", "bc1qhrjcrjushkm4zsdc7ygdfqytdspn98d0qs2v0w"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a2502572417", "bc1qssmr406l33aelet646kku0qlwgz4z3xylx7xjh"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a2502572418", "bc1qqw0vsapckfwcnupz68k96590h4tjq3vhzuxurq"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a2502572419", "bc1q8yx0k3v3ngf70aqe9uwkl4xua3asw573n4datg"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a250257241a", "bc1qe4ufmjvtasx85j90adjcgkt8rtlv3vfrvjjyjv"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a250257241b", "bc1qxs6kjy2ue9tuv8hn4cs2hc9glp3r8devnj7amz"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a250257241c", "bc1qgquvezagw9zyhyj6xvrzdfdujy6csxxap2wy80"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a250257241d", "bc1quhf6wtqfduaa0092xkp9pz09k4rjrz9cxpulzl"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a250257241e", "bc1qnvnlk7rkj73rat8d86eeuekvdpf8x589xjevfm"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a250257241f", "bc1qhn73m4zjgy99h2wueyfdrxmtuhs8m7ws4vv2v7"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a2502572420", "bc1qq00d2la27u2ddetdqst86f8y0venr4l70vsw2f"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a2502572421", "bc1q596w4c8dveexpq9d6weedmdgnzw7uvrwfgx2xj"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a2502572422", "bc1q3vnnztxp5u4c78547x4gwpncn5luvgtvugvskr"),
            ("d56f9c9513d4ce3da196e9ae45a21084ea175fec14da5e82e3050a2502572423", "bc1q4z6xlla5dacdhpy6vddvwau7lj79npx9r4ve99"),
        ];

        for (priv_hex, expected_addr) in vectors {
            let bytes = hex::decode(priv_hex).unwrap();
            let key = BitcoinPrivateKey::new(&bytes)
                .unwrap_or_else(|| panic!("Failed to create key from {}", priv_hex));
            let address = key.derive_address().to_string();
            assert_eq!(address, *expected_addr, "address mismatch for private key {}", priv_hex);
        }
    }
}
