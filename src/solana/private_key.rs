//! Solana blockchain private key implementation
//!
//! This module implements the Solana private key type using Ed25519 signing keys
//! from the `ed25519-dalek` crate. Addresses are base58-encoded public keys,
//! matching the standard Solana address format.

use crate::PrivateKey as PrivateKeyTrait;
use ed25519_dalek::SigningKey;

/// Solana private key backed by a 32-byte Ed25519 signing key (seed).
///
/// The full 64-byte keypair (seed + public key) is the standard export format
/// used by wallets like Phantom. This type stores only the 32-byte seed and
/// derives the public key on demand.
///
/// # Validation Rules
///
/// - Must be exactly 32 bytes
/// - Must not be all zeros
#[derive(Debug, Clone, PartialEq)]
pub struct SolanaPrivateKey([u8; 32]);

/// Base58-encoded Ed25519 public key, matching the standard Solana address format.
#[derive(Debug, Clone, PartialEq)]
pub struct SolanaAddress {
    pubkey: [u8; 32],
    encoded: String,
}

impl SolanaAddress {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.pubkey
    }
}

impl std::fmt::Display for SolanaAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encoded)
    }
}

impl SolanaPrivateKey {
    pub fn is_valid(bytes: &[u8]) -> bool {
        if bytes.len() != 32 {
            return false;
        }
        !bytes.iter().all(|&b| b == 0)
    }

    /// Returns the full 64-byte keypair (seed ++ public_key) as used by
    /// Solana wallets for export/import.
    pub fn to_keypair_bytes(&self) -> [u8; 64] {
        let signing_key = SigningKey::from_bytes(&self.0);
        let pubkey = signing_key.verifying_key();
        let mut keypair = [0u8; 64];
        keypair[..32].copy_from_slice(&self.0);
        keypair[32..].copy_from_slice(pubkey.as_bytes());
        keypair
    }
}

impl PrivateKeyTrait for SolanaPrivateKey {
    type Address = SolanaAddress;

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

    /// Returns the base58-encoded 64-byte keypair, matching the standard
    /// format used by Phantom and other Solana wallets.
    fn to_string(&self) -> String {
        bs58::encode(self.to_keypair_bytes()).into_string()
    }

    fn derive_address(&self) -> Self::Address {
        let signing_key = SigningKey::from_bytes(&self.0);
        let pubkey = signing_key.verifying_key();
        let pubkey_bytes = pubkey.to_bytes();
        let encoded = bs58::encode(&pubkey_bytes).into_string();
        SolanaAddress {
            pubkey: pubkey_bytes,
            encoded,
        }
    }

    fn is_valid(bytes: &[u8]) -> bool {
        SolanaPrivateKey::is_valid(bytes)
    }

    fn key_size() -> usize {
        32
    }

    /// Accepts either:
    /// - Base58-encoded 64-byte keypair (standard Solana wallet export)
    /// - Base58-encoded 32-byte seed
    /// - Hex string with optional 0x prefix (64 hex chars = 32 bytes)
    fn from_string(string: &str) -> Option<Self> {
        // Try base58 first
        if let Ok(bytes) = bs58::decode(string).into_vec() {
            return match bytes.len() {
                64 => Self::new(&bytes[..32]),
                32 => Self::new(&bytes),
                _ => None,
            };
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

    #[test]
    fn test_solana_private_key_creation() {
        let bytes = [0x12u8; 32];
        let private_key = SolanaPrivateKey::new(&bytes).expect("Valid key");
        assert_eq!(private_key.as_bytes(), &bytes);
        assert_eq!(SolanaPrivateKey::key_size(), 32);
    }

    #[test]
    fn test_solana_address_is_valid_base58() {
        let bytes = [0x12u8; 32];
        let private_key = SolanaPrivateKey::new(&bytes).expect("Valid key");
        let address = private_key.derive_address();
        let addr_str = address.to_string();

        // Solana addresses are 32-44 characters in base58
        assert!(addr_str.len() >= 32 && addr_str.len() <= 44, "address length: {}", addr_str.len());
        // Should only contain base58 characters
        assert!(addr_str.chars().all(|c| {
            c.is_ascii_alphanumeric() && c != '0' && c != 'O' && c != 'I' && c != 'l'
        }));
    }

    #[test]
    fn test_solana_deterministic_address() {
        let bytes = [1u8; 32];
        let key1 = SolanaPrivateKey::new(&bytes).unwrap();
        let key2 = SolanaPrivateKey::new(&bytes).unwrap();
        assert_eq!(key1.derive_address().to_string(), key2.derive_address().to_string());
    }

    #[test]
    fn test_invalid_solana_key() {
        let zeros = [0u8; 32];
        assert!(SolanaPrivateKey::new(&zeros).is_none());

        let wrong_size = [1u8; 64];
        assert!(SolanaPrivateKey::new(&wrong_size).is_none());

        let wrong_size_2 = [1u8; 31];
        assert!(SolanaPrivateKey::new(&wrong_size_2).is_none());
    }

    #[test]
    fn test_solana_to_string_is_base58() {
        let bytes = [0x42u8; 32];
        let key = SolanaPrivateKey::new(&bytes).unwrap();
        let s = key.to_string();
        // Base58 decode should yield 64 bytes (keypair)
        let decoded = bs58::decode(&s).into_vec().unwrap();
        assert_eq!(decoded.len(), 64);
        assert_eq!(&decoded[..32], &bytes);
    }

    #[test]
    fn test_solana_from_string_base58_keypair() {
        let bytes = [0x42u8; 32];
        let key = SolanaPrivateKey::new(&bytes).unwrap();
        let s = key.to_string();
        let restored = SolanaPrivateKey::from_string(&s).unwrap();
        assert_eq!(key, restored);
    }

    #[test]
    fn test_solana_from_string_hex() {
        let hex = format!("0x{}", "42".repeat(32));
        let key = SolanaPrivateKey::from_string(&hex).unwrap();
        assert_eq!(key.as_bytes(), &[0x42u8; 32]);
    }

    #[test]
    fn test_solana_keypair_bytes() {
        let bytes = [0x01u8; 32];
        let key = SolanaPrivateKey::new(&bytes).unwrap();
        let keypair = key.to_keypair_bytes();
        assert_eq!(&keypair[..32], &bytes);
        // Second half is the derived public key
        let signing_key = SigningKey::from_bytes(&bytes);
        assert_eq!(&keypair[32..], signing_key.verifying_key().as_bytes());
    }
}
