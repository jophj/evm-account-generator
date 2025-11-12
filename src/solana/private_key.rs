//! Solana blockchain private key implementation
//!
//! This module implements a simplified Solana private key type using Ed25519 keypairs.
//!
//! # Important Note
//!
//! This is a simplified implementation for demonstration purposes. Production Solana
//! applications should use the official `solana-sdk` crate which provides proper
//! Ed25519 key derivation, base58 encoding, and all Solana-specific functionality.

use crate::PrivateKey as PrivateKeyTrait;

/// Solana-specific private key implementation
///
/// Represents a 64-byte Ed25519 keypair used in the Solana blockchain.
/// In real Solana, this consists of a 32-byte seed and a 32-byte derived key.
///
/// # Validation Rules
///
/// A valid Solana private key must:
/// - Be exactly 64 bytes
/// - Not be all zeros
///
/// # Note
///
/// This is a simplified implementation. Real Solana keypairs have more complex
/// structure and validation requirements.
#[derive(Debug, Clone, PartialEq)]
pub struct SolanaPrivateKey([u8; 64]);

/// Solana address type
///
/// In real Solana, addresses are Ed25519 public keys encoded in base58.
/// This is a simplified representation for demonstration purposes.
#[derive(Debug, Clone, PartialEq)]
pub struct SolanaAddress(String);

impl std::fmt::Display for SolanaAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl SolanaPrivateKey {
    /// Validates if the byte slice is a valid Solana private key
    ///
    /// For this simplified implementation, a valid key must:
    /// 1. Be exactly 64 bytes
    /// 2. Not be all zeros
    ///
    /// # Arguments
    ///
    /// * `bytes` - The byte slice to validate
    ///
    /// # Returns
    ///
    /// `true` if the bytes could represent a valid Solana private key, `false` otherwise
    ///
    /// # Note
    ///
    /// Real Solana Ed25519 keys have additional validation requirements that are
    /// not implemented in this simplified version.
    pub fn is_valid(bytes: &[u8]) -> bool {
        // Check length
        if bytes.len() != 64 {
            return false;
        }

        // Check that it's not all zeros
        !bytes.iter().all(|&b| b == 0)
    }
}

impl PrivateKeyTrait for SolanaPrivateKey {
    type Address = SolanaAddress;

    fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 || !Self::is_valid(bytes) {
            return None;
        }
        let mut key_bytes = [0u8; 64];
        key_bytes.copy_from_slice(bytes);
        Some(Self(key_bytes))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn to_string(&self) -> String {
        format!("0x{}", hex::encode(&self.0))
    }

    /// Derives a Solana address from this private key
    ///
    /// This is a simplified implementation that creates a hex-based address.
    ///
    /// # Real Solana Address Derivation
    ///
    /// In real Solana:
    /// 1. The first 32 bytes are the Ed25519 seed
    /// 2. The public key is derived from the seed using Ed25519
    /// 3. The public key (32 bytes) is base58-encoded as the address
    ///
    /// # Returns
    ///
    /// A simplified address string starting with "Sol"
    ///
    /// # Note
    ///
    /// This is NOT a real Solana address format. Use `solana-sdk` for production.
    fn derive_address(&self) -> Self::Address {
        // Simplified address derivation - real Solana would:
        // 1. Derive Ed25519 public key from the seed (first 32 bytes)
        // 2. Encode the public key in base58
        let hash = format!("Sol{}", hex::encode(&self.0[..16]));
        SolanaAddress(hash)
    }

    fn is_valid(bytes: &[u8]) -> bool {
        SolanaPrivateKey::is_valid(bytes)
    }

    fn key_size() -> usize {
        64
    }

    fn from_string(string: &str) -> Option<Self> {
        let clean_hex = string.strip_prefix("0x").unwrap_or(string);

        if clean_hex.len() != 128 {  // 64 bytes = 128 hex chars
            return None;
        }

        let bytes = hex::decode(clean_hex).ok()?;

        let mut key_bytes = [0u8; 64];
        key_bytes.copy_from_slice(&bytes);

        Self::new(&key_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solana_private_key_creation() {
        let bytes = [0x12u8; 64];
        let private_key = SolanaPrivateKey::new(&bytes).expect("Valid key");
        assert_eq!(private_key.as_bytes(), &bytes);
        assert_eq!(SolanaPrivateKey::key_size(), 64);
    }

    #[test]
    fn test_solana_address_derivation() {
        let bytes = [0x12u8; 64];
        let private_key = SolanaPrivateKey::new(&bytes).expect("Valid key");
        let address = private_key.derive_address();
        assert!(address.to_string().starts_with("Sol"));
    }

    #[test]
    fn test_invalid_solana_key() {
        // All zeros should be invalid
        let zeros = [0u8; 64];
        assert!(SolanaPrivateKey::new(&zeros).is_none());
        
        // Wrong size should be invalid
        let wrong_size = [1u8; 32];
        assert!(SolanaPrivateKey::new(&wrong_size).is_none());
        
        let wrong_size_2 = [1u8; 63];
        assert!(SolanaPrivateKey::new(&wrong_size_2).is_none());
    }

    #[test]
    fn test_solana_from_string() {
        let hex = "0x11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
        let private_key = SolanaPrivateKey::from_string(hex).expect("Valid hex");
        assert_eq!(private_key.to_string(), hex);
    }
}

