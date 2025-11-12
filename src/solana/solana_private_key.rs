use crate::private_key::PrivateKey2;

/// Solana-specific private key implementation
/// Solana uses Ed25519 keypairs which are 64 bytes (32-byte seed + 32-byte derived key)
#[derive(Debug, Clone, PartialEq)]
pub struct SolanaPrivateKey2([u8; 64]);

/// Solana address type (simplified - real Solana uses base58 encoding)
#[derive(Debug, Clone, PartialEq)]
pub struct SolanaAddress(String);

impl std::fmt::Display for SolanaAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl SolanaPrivateKey2 {
    /// Validates if the byte slice is a valid Solana private key
    /// For Solana Ed25519, any non-zero 64-byte array is valid
    pub fn is_valid(bytes: &[u8]) -> bool {
        if bytes.len() != 64 {
            return false;
        }

        // Check that it's not all zeros
        !bytes.iter().all(|&b| b == 0)
    }
}

impl PrivateKey2 for SolanaPrivateKey2 {
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

    fn derive_address(&self) -> Self::Address {
        // Simplified address derivation - real Solana would derive Ed25519 public key
        // from the seed (first 32 bytes) and use base58 encoding
        let hash = format!("Sol{}", hex::encode(&self.0[..16]));
        SolanaAddress(hash)
    }

    fn is_valid(bytes: &[u8]) -> bool {
        SolanaPrivateKey2::is_valid(bytes)
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
        let private_key = SolanaPrivateKey2::new(&bytes).expect("Valid key");
        assert_eq!(private_key.as_bytes(), &bytes);
        assert_eq!(SolanaPrivateKey2::key_size(), 64);
    }

    #[test]
    fn test_solana_address_derivation() {
        let bytes = [0x12u8; 64];
        let private_key = SolanaPrivateKey2::new(&bytes).expect("Valid key");
        let address = private_key.derive_address();
        assert!(address.to_string().starts_with("Sol"));
    }

    #[test]
    fn test_invalid_solana_key() {
        // All zeros should be invalid
        let zeros = [0u8; 64];
        assert!(SolanaPrivateKey2::new(&zeros).is_none());
        
        // Wrong size should be invalid
        let wrong_size = [1u8; 32];
        assert!(SolanaPrivateKey2::new(&wrong_size).is_none());
        
        let wrong_size_2 = [1u8; 63];
        assert!(SolanaPrivateKey2::new(&wrong_size_2).is_none());
    }

    #[test]
    fn test_solana_from_string() {
        let hex = "0x11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
        let private_key = SolanaPrivateKey2::from_string(hex).expect("Valid hex");
        assert_eq!(private_key.to_string(), hex);
    }
}

