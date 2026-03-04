//! Bitcoin private key implementation (P2WPKH / native SegWit)
//!
//! Uses secp256k1 for key operations, SHA-256 + RIPEMD-160 for address
//! derivation, and Bech32 encoding for native SegWit (P2WPKH) addresses.

use crate::PrivateKey;
use ripemd::Ripemd160;
use secp256k1::{All, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

static SECP: LazyLock<Secp256k1<All>> = LazyLock::new(Secp256k1::new);

/// A 32-byte secp256k1 private key for Bitcoin.
#[derive(Debug, Clone, PartialEq)]
pub struct BitcoinPrivateKey {
    key: [u8; 32],
}

/// A P2WPKH (native SegWit) Bitcoin address.
///
/// Stores the 20-byte witness program (HASH160 of the compressed public key)
/// and the pre-encoded Bech32 address string.
#[derive(Debug, Clone, PartialEq)]
pub struct BitcoinAddress {
    witness_program: [u8; 20],
    encoded: String,
}

impl BitcoinAddress {
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.witness_program
    }
}

impl std::fmt::Display for BitcoinAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encoded)
    }
}

fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(&first).into()
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    Ripemd160::digest(&sha).into()
}

impl BitcoinPrivateKey {
    /// Encodes the private key in Wallet Import Format (WIF) for compressed
    /// keys on mainnet (version byte 0x80, compression flag 0x01).
    pub fn to_wif(&self) -> String {
        let mut payload = Vec::with_capacity(38);
        payload.push(0x80);
        payload.extend_from_slice(&self.key);
        payload.push(0x01);

        let checksum = double_sha256(&payload);
        payload.extend_from_slice(&checksum[..4]);

        bs58::encode(&payload).into_string()
    }

    /// Decodes a WIF-encoded private key (compressed or uncompressed, mainnet).
    pub fn from_wif(wif: &str) -> Option<[u8; 32]> {
        let bytes = bs58::decode(wif).into_vec().ok()?;
        if bytes.len() < 5 {
            return None;
        }

        let (payload, checksum) = bytes.split_at(bytes.len() - 4);
        let expected = double_sha256(payload);
        if checksum != &expected[..4] {
            return None;
        }

        if payload[0] != 0x80 {
            return None;
        }

        let key_bytes = match payload.len() {
            34 if payload[33] == 0x01 => &payload[1..33],
            33 => &payload[1..33],
            _ => return None,
        };

        let mut key = [0u8; 32];
        key.copy_from_slice(key_bytes);
        Some(key)
    }
}

impl PrivateKey for BitcoinPrivateKey {
    type Address = BitcoinAddress;

    fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        SecretKey::from_slice(bytes).ok()?;
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Some(Self { key })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Returns the WIF-encoded private key (compressed, mainnet).
    fn to_string(&self) -> String {
        self.to_wif()
    }

    /// Derives the P2WPKH (native SegWit) address:
    /// 1. Compressed public key (33 bytes)
    /// 2. HASH160 (SHA-256 then RIPEMD-160) → 20-byte witness program
    /// 3. Bech32 encode with witness version 0
    fn derive_address(&self) -> Self::Address {
        let secret_key =
            SecretKey::from_slice(&self.key).expect("validated in new()");
        let public_key = PublicKey::from_secret_key(&SECP, &secret_key);
        let compressed = public_key.serialize();

        let witness_program = hash160(&compressed);

        let hrp = bech32::Hrp::parse_unchecked("bc");
        let encoded =
            bech32::segwit::encode(hrp, bech32::segwit::VERSION_0, &witness_program)
                .expect("valid witness program");

        BitcoinAddress {
            witness_program,
            encoded,
        }
    }

    fn is_valid(bytes: &[u8]) -> bool {
        if bytes.len() != 32 {
            return false;
        }
        SecretKey::from_slice(bytes).is_ok()
    }

    fn key_size() -> usize {
        32
    }

    /// Accepts WIF (compressed/uncompressed, mainnet) or hex with optional
    /// 0x prefix.
    fn from_string(string: &str) -> Option<Self> {
        if string.starts_with('K') || string.starts_with('L') || string.starts_with('5') {
            let key_bytes = BitcoinPrivateKey::from_wif(string)?;
            return Self::new(&key_bytes);
        }

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

    #[test]
    fn test_bitcoin_private_key_creation() {
        let bytes = [0x12u8; 32];
        let key = BitcoinPrivateKey::new(&bytes).expect("Valid key");
        assert_eq!(key.as_bytes(), &bytes);
        assert_eq!(BitcoinPrivateKey::key_size(), 32);
    }

    #[test]
    fn test_bitcoin_address_is_p2wpkh() {
        let bytes = [0x12u8; 32];
        let key = BitcoinPrivateKey::new(&bytes).expect("Valid key");
        let address = key.derive_address();
        let addr_str = address.to_string();
        assert!(addr_str.starts_with("bc1q"), "P2WPKH must start with bc1q, got: {}", addr_str);
    }

    #[test]
    fn test_bitcoin_deterministic_address() {
        let bytes = [1u8; 32];
        let key1 = BitcoinPrivateKey::new(&bytes).unwrap();
        let key2 = BitcoinPrivateKey::new(&bytes).unwrap();
        assert_eq!(
            key1.derive_address().to_string(),
            key2.derive_address().to_string()
        );
    }

    #[test]
    fn test_bitcoin_known_vector() {
        // Private key: 0x0000...0001 is the generator point
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        let key = BitcoinPrivateKey::new(&bytes).unwrap();
        let address = key.derive_address();
        assert_eq!(
            address.to_string(),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
    }

    #[test]
    fn test_invalid_bitcoin_key() {
        let zeros = [0u8; 32];
        assert!(BitcoinPrivateKey::new(&zeros).is_none());

        let wrong_size = [1u8; 31];
        assert!(BitcoinPrivateKey::new(&wrong_size).is_none());
    }

    #[test]
    fn test_wif_roundtrip() {
        let bytes = [0x42u8; 32];
        let key = BitcoinPrivateKey::new(&bytes).unwrap();
        let wif = key.to_wif();

        assert!(wif.starts_with('K') || wif.starts_with('L'));

        let restored = BitcoinPrivateKey::from_string(&wif).unwrap();
        assert_eq!(key, restored);
    }

    #[test]
    fn test_bitcoin_from_string_hex() {
        let hex = format!("0x{}", "42".repeat(32));
        let key = BitcoinPrivateKey::from_string(&hex).unwrap();
        assert_eq!(key.as_bytes(), &[0x42u8; 32]);
    }

    #[test]
    fn test_bitcoin_address_bytes() {
        let bytes = [0x12u8; 32];
        let key = BitcoinPrivateKey::new(&bytes).unwrap();
        let address = key.derive_address();
        assert_eq!(address.as_bytes().len(), 20);
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
