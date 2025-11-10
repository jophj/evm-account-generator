//! EVM Private Key implementation

use crate::error::{EvmError, Result};
use crate::types::{ToHex, GetAddress};
use hex;
use keccak_asm::{Digest, Keccak256};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

/// Represents an EVM private key
#[derive(Debug, Clone, PartialEq)]
pub struct EVMPrivateKey {
    bytes: [u8; 32],
}

pub trait FromHex {
    fn from_hex(hex_str: &str) -> Result<EVMPrivateKey>;
}

pub trait FromBytes {
    fn from_bytes(bytes: [u8; 32]) -> Result<EVMPrivateKey>;
}

pub trait PrivateKey {
    fn as_bytes(&self) -> &[u8; 32];
    fn to_bytes(&self) -> Vec<u8>;
    fn to_hex(&self) -> String;
    fn get_address(&self) -> String;
}

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
                "Private key must be exactly 64 hex characters (32 bytes)".to_string()
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
        assert!(
            EVMPrivateKey::from_hex(
                "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12"
            )
            .is_err()
        );
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
}
