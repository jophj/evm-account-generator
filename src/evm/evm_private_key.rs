use crate::private_key::PrivateKey2;
use keccak_asm::{Digest, Keccak256};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

/// EVM-specific private key implementation
#[derive(Debug, Clone, PartialEq)]
pub struct EVMPrivateKey2([u8; 32]);

/// EVM address type
#[derive(Debug, Clone, PartialEq)]
pub struct EVMAddress([u8; 20]);

pub const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

impl std::fmt::Display for EVMAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl EVMPrivateKey2 {
    /// Validates if the byte slice is a valid EVM private key
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

impl PrivateKey2 for EVMPrivateKey2 {
    type Address = EVMAddress;

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

    fn derive_address(&self) -> Self::Address {
        let secp = Secp256k1::new();
        let secret_key =
            SecretKey::from_slice(&self.0).expect("Private key should be valid for secp256k1");

        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let public_key_bytes = public_key.serialize_uncompressed();
        let public_key_coords = &public_key_bytes[1..];

        let mut hasher = Keccak256::new();
        hasher.update(public_key_coords);
        let hash = hasher.finalize();

        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&hash[12..32]);
        EVMAddress(address_bytes)
    }

    fn is_valid(bytes: &[u8]) -> bool {
        EVMPrivateKey2::is_valid(bytes)
    }

    fn key_size() -> usize {
        32
    }

    fn from_string(string: &str) -> Option<Self> {
        let clean_hex = string.strip_prefix("0x").unwrap_or(string);

        if clean_hex.len() != 64 {
            return None;
        }

        let bytes = hex::decode(clean_hex).unwrap();

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
        let private_key = EVMPrivateKey2::new(&bytes).expect("Valid key");
        assert_eq!(private_key.as_bytes(), &bytes);
        assert_eq!(EVMPrivateKey2::key_size(), 32);
    }

    #[test]
    fn test_evm_address_derivation() {
        let bytes = [0x12u8; 32];
        let private_key = EVMPrivateKey2::new(&bytes).expect("Valid key");
        let address = private_key.derive_address();
        assert!(address.to_string().starts_with("0x"));
    }
}
