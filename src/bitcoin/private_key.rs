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
}
