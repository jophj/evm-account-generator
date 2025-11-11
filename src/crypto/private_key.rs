//! EVM Private Key implementation

use crate::error::{EvmError, Result};
use crate::traits::{FromBytes, FromHex, PrivateKey};
use hex;
use keccak_asm::{Digest, Keccak256};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

/// Represents an EVM private key
#[derive(Debug, Clone, PartialEq)]
pub struct EVMPrivateKey {
    bytes: [u8; 32],
}

impl EVMPrivateKey {
    pub fn is_valid(bytes: [u8; 32]) -> bool {
        if bytes.iter().all(|&b| b == 0) {
            return false;
        }
        // secp256k1 curve order: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        const SECP256K1_ORDER: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ];

        // Compare bytes from most significant to least significant
        for i in 0..32 {
            if bytes[i] < SECP256K1_ORDER[i] {
                return true;
            } else if bytes[i] > SECP256K1_ORDER[i] {
                return false;
            }
            // If equal, continue to next byte
        }

        // If all bytes are equal to the order, it's invalid (must be strictly less)
        false
    }
}

// Traits are now imported from crate::traits

impl FromBytes for EVMPrivateKey {
    fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        Ok(Self { bytes })
    }
}

impl FromHex for EVMPrivateKey {
    fn from_hex(hex_str: &str) -> Result<Self> {
        let clean_hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);

        if clean_hex.len() != 64 {
            return Err(EvmError::InvalidPrivateKey(
                "Private key must be exactly 64 hex characters (32 bytes)".to_string(),
            ));
        }

        let bytes = hex::decode(clean_hex)?;

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);

        Self::from_bytes(key_bytes)
    }
}

impl PrivateKey for EVMPrivateKey {
    /// Returns the private key as a byte array reference
    fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Returns the private key as a Vec<u8>
    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
    fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.bytes))
    }
    fn get_address(&self) -> String {
        // Create secp256k1 context
        let secp = Secp256k1::new();

        // Create secret key from private key bytes
        let secret_key =
            SecretKey::from_slice(&self.bytes).expect("Private key should be valid for secp256k1");

        // Derive public key
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        // Get uncompressed public key bytes (65 bytes: 0x04 + 32 bytes x + 32 bytes y)
        let public_key_bytes = public_key.serialize_uncompressed();

        // Take only the x and y coordinates (skip the 0x04 prefix)
        let public_key_coords = &public_key_bytes[1..];

        // Hash the public key coordinates with Keccak256
        let mut hasher = Keccak256::new();
        hasher.update(public_key_coords);
        let hash = hasher.finalize();

        // Take the last 20 bytes of the hash as the address
        let address_bytes = &hash[12..32];

        // Convert to hex string and apply EIP-55 checksumming
        format!("0x{}", hex::encode(address_bytes))
        // TODO: apply EIP-55 checksumming
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIVATE_KEY: &str =
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    #[test]
    fn test_private_key_creation() {
        let key = EVMPrivateKey::from_hex(TEST_PRIVATE_KEY).unwrap();
        assert_eq!(key.to_hex(), TEST_PRIVATE_KEY);
    }

    #[test]
    fn test_private_key_from_bytes() {
        let bytes = [1u8; 32];
        let key = EVMPrivateKey::from_bytes(bytes);
        assert_eq!(key.unwrap().as_bytes(), &bytes);
    }

    #[test]
    fn test_private_key_error_handling() {
        // Test invalid hex
        assert!(EVMPrivateKey::from_hex("0x123g").is_err());

        // Test wrong length
        assert!(EVMPrivateKey::from_hex("0x123").is_err());

        // Test too long
        assert!(EVMPrivateKey::from_hex(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12"
        )
        .is_err());
    }

    #[test]
    fn test_get_address() {
        let key = EVMPrivateKey::from_hex(
            "0x126824047ad2ca09f61950ca590520caa7247871ac15e0ccc931ebab91a1037c",
        )
        .unwrap();
        assert_eq!(
            key.get_address(),
            "0x80C1109a04da741d485678967a6172bEC411A66B".to_lowercase()
        );
    }

    // Tests for is_valid method
    #[test]
    fn test_is_valid_all_zeros() {
        let bytes = [0u8; 32];
        assert!(!EVMPrivateKey::is_valid(bytes), "All zeros should be invalid");
    }

    #[test]
    fn test_is_valid_minimum_valid() {
        let mut bytes = [0u8; 32];
        bytes[31] = 1; // Minimum valid key: 0x0000...0001
        assert!(EVMPrivateKey::is_valid(bytes), "Minimum valid key should be valid");
    }

    #[test]
    fn test_is_valid_typical_key() {
        let bytes = [
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
        ];
        assert!(EVMPrivateKey::is_valid(bytes), "Typical private key should be valid");
    }

    #[test]
    fn test_is_valid_order_minus_one() {
        // secp256k1 order - 1 (largest valid key)
        let bytes = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
        ];
        assert!(EVMPrivateKey::is_valid(bytes), "Order - 1 should be valid (largest valid key)");
    }

    #[test]
    fn test_is_valid_exactly_order() {
        // Exactly the secp256k1 order
        let bytes = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
        ];
        assert!(!EVMPrivateKey::is_valid(bytes), "Exactly order should be invalid");
    }

    #[test]
    fn test_is_valid_order_plus_one() {
        // secp256k1 order + 1
        let bytes = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x42,
        ];
        assert!(!EVMPrivateKey::is_valid(bytes), "Order + 1 should be invalid");
    }

    #[test]
    fn test_is_valid_all_ones() {
        let bytes = [0xFFu8; 32];
        assert!(!EVMPrivateKey::is_valid(bytes), "All 0xFF should be invalid");
    }

    #[test]
    fn test_is_valid_just_below_order_different_byte() {
        // A value that's clearly below the order by differing in the first significant byte
        let bytes = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD, // 0xFD < 0xFE
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
        ];
        assert!(EVMPrivateKey::is_valid(bytes), "Value with byte clearly below order should be valid");
    }

    #[test]
    fn test_is_valid_above_order_different_byte() {
        // A value that's clearly above the order by differing in an early byte
        let bytes = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0xFF > 0xFE at this position
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
        ];
        assert!(!EVMPrivateKey::is_valid(bytes), "Value with byte clearly above order should be invalid");
    }

    #[test]
    fn test_is_valid_edge_case_last_byte_differs() {
        // All bytes match the order except the last one is lower
        let bytes = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40, // 0x40 < 0x41
        ];
        assert!(EVMPrivateKey::is_valid(bytes), "Value equal to order - 1 should be valid");
    }

    #[test]
    fn test_is_valid_multiple_valid_keys() {
        // Test several valid keys to ensure consistency
        let valid_keys = vec![
            [0x01; 32],
            [
                0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            ],
            [
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
                0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
                0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            ],
        ];

        for key in valid_keys {
            assert!(EVMPrivateKey::is_valid(key), "Valid key should pass validation: {:02X?}", key);
        }
    }
}
