//! EVM (Ethereum Virtual Machine) private key implementation
//!
//! This module implements the EVM-specific private key type using ECDSA secp256k1
//! cryptography and Keccak-256 hashing for address derivation.

use crate::PrivateKey;
use keccak_asm::{Digest, Keccak256};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

/// EVM-specific private key implementation
///
/// Represents a 32-byte ECDSA secp256k1 private key used in Ethereum and
/// other EVM-compatible blockchains.
///
/// # Validation Rules
///
/// A valid EVM private key must:
/// - Be exactly 32 bytes
/// - Not be all zeros
/// - Be less than the secp256k1 curve order (n)
///
/// Invalid keys are automatically rejected during creation.
#[derive(Debug, Clone, PartialEq)]
pub struct EvmPrivateKey([u8; 32]);

/// EVM address type
///
/// Represents a 20-byte Ethereum address derived from the public key
/// using Keccak-256 hashing.
#[derive(Debug, Clone, PartialEq)]
pub struct EvmAddress([u8; 20]);

/// The order (n) of the secp256k1 elliptic curve
///
/// Any private key must be less than this value to be valid.
/// This is a fundamental constant of the secp256k1 curve used in Bitcoin and Ethereum.
pub const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

impl std::fmt::Display for EvmAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl EvmPrivateKey {
    /// Validates if the byte slice is a valid EVM private key
    ///
    /// Checks three conditions:
    /// 1. Length is exactly 32 bytes
    /// 2. Not all zeros (would be an invalid key)
    /// 3. Value is less than the secp256k1 curve order
    ///
    /// # Arguments
    ///
    /// * `bytes` - The byte slice to validate
    ///
    /// # Returns
    ///
    /// `true` if the bytes represent a valid EVM private key, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```rust
    /// use evm_account_generator::evm::PrivateKey as EvmKey;
    ///
    /// let valid_bytes = [1u8; 32];
    /// assert!(EvmKey::is_valid(&valid_bytes));
    ///
    /// let invalid_zeros = [0u8; 32];
    /// assert!(!EvmKey::is_valid(&invalid_zeros));
    /// ```
    pub fn is_valid(bytes: &[u8]) -> bool {
        // Check length
        if bytes.len() != 32 {
            return false;
        }

        // Check for all zeros
        if bytes.iter().all(|&b| b == 0) {
            return false;
        }

        // Check that the value is less than the secp256k1 curve order
        for i in 0..32 {
            if bytes[i] < SECP256K1_ORDER[i] {
                return true;  // Found a byte less than the order, so the entire number is less
            } else if bytes[i] > SECP256K1_ORDER[i] {
                return false;  // Found a byte greater than the order, so the entire number is greater
            }
            // If equal, continue checking the next byte
        }

        // All bytes are equal to the order, which is invalid (must be strictly less than)
        false
    }
}

impl PrivateKey for EvmPrivateKey {
    type Address = EvmAddress;

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

    fn to_string(&self) -> String {
        format!("0x{}", hex::encode(&self.0))
    }

    /// Derives an Ethereum address from this private key
    ///
    /// The derivation process:
    /// 1. Derive the secp256k1 public key from the private key
    /// 2. Serialize the public key in uncompressed format (65 bytes)
    /// 3. Take the coordinates (skip the first prefix byte)
    /// 4. Hash the coordinates with Keccak-256
    /// 5. Take the last 20 bytes of the hash as the address
    ///
    /// # Returns
    ///
    /// The 20-byte Ethereum address
    ///
    /// # Notes
    ///
    /// - TODO: Add EIP-55 checksumming for mixed-case address display
    /// - TODO: Consider memoizing the address derivation for performance
    fn derive_address(&self) -> Self::Address {
        // Create secp256k1 context
        let secp = Secp256k1::new();
        
        // Convert private key to secp256k1 SecretKey
        let secret_key =
            SecretKey::from_slice(&self.0).expect("Private key should be valid for secp256k1");

        // Derive the public key
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        
        // Serialize public key in uncompressed format (04 || x || y)
        let public_key_bytes = public_key.serialize_uncompressed();
        
        // Skip the 0x04 prefix byte, use only the x and y coordinates
        let public_key_coords = &public_key_bytes[1..];

        // Hash the coordinates with Keccak-256
        let mut hasher = Keccak256::new();
        hasher.update(public_key_coords);
        let hash = hasher.finalize();

        // Take the last 20 bytes of the hash as the Ethereum address
        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&hash[12..32]);
        EvmAddress(address_bytes)
    }

    fn is_valid(bytes: &[u8]) -> bool {
        EvmPrivateKey::is_valid(bytes)
    }

    fn key_size() -> usize {
        32
    }

    fn from_string(string: &str) -> Option<Self> {
        let clean_hex = string.strip_prefix("0x").unwrap_or(string);

        if clean_hex.len() != 64 {
            return None;
        }

        let bytes = hex::decode(clean_hex).ok()?;

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);

        Self::new(&key_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evm_private_key_creation() {
        let bytes = [0x12u8; 32];
        let private_key = EvmPrivateKey::new(&bytes).expect("Valid key");
        assert_eq!(private_key.as_bytes(), &bytes);
        assert_eq!(EvmPrivateKey::key_size(), 32);
    }

    #[test]
    fn test_evm_address_derivation() {
        let bytes = [0x12u8; 32];
        let private_key = EvmPrivateKey::new(&bytes).expect("Valid key");
        let address = private_key.derive_address();
        assert!(address.to_string().starts_with("0x"));
    }
}

