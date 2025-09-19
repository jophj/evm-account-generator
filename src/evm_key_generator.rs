/// EVM Private Key Generator Module
///
/// This module provides functionality to generate EVM private keys.
/// Uses cryptographically secure random number generation.
use hex;
use crate::rng::RandomBytes32;

/// Trait for converting types to hexadecimal representation
pub trait ToHex {
    /// Converts the type to a hexadecimal string with 0x prefix
    fn to_hex(&self) -> String;
}

/// Represents an EVM private key
#[derive(Debug, Clone, PartialEq)]
pub struct PrivateKey {
    bytes: [u8; 32],
}

impl PrivateKey {
    /// Creates a new PrivateKey from a 32-byte array
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Creates a new PrivateKey from a hex string
    ///
    /// # Arguments
    ///
    /// * `hex_str` - A hex string with or without 0x prefix
    ///
    /// # Returns
    ///
    /// Result containing PrivateKey or error message
    pub fn from_hex(hex_str: &str) -> Result<Self, String> {
        let clean_hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);

        if clean_hex.len() != 64 {
            return Err("Private key must be exactly 64 hex characters (32 bytes)".to_string());
        }

        let bytes = hex::decode(clean_hex)
            .map_err(|_| "Invalid hex characters in private key".to_string())?;

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);

        Ok(Self::from_bytes(key_bytes))
    }

    /// Returns the private key as a byte array
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Returns the private key as a Vec<u8>
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

impl ToHex for PrivateKey {
    fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.bytes))
    }
}

/// Generates a cryptographically secure EVM private key using a provided RNG
///
/// # Arguments
///
/// * `rng` - A mutable reference to any type implementing RandomBytes32
///
/// # Returns
///
/// A PrivateKey instance with randomly generated data
///
/// # Example
///
/// ```
/// use evm_account_generator::evm_key_generator::{generate_private_key_with_rng, ToHex};
/// use rand::thread_rng;
///
/// let mut rng = thread_rng();
/// let private_key = generate_private_key_with_rng(&mut rng);
/// println!("Generated private key: {}", private_key.to_hex());
/// ```
pub fn generate_private_key_with_rng<R: RandomBytes32>(rng: &mut R) -> PrivateKey {
    loop {
        // Generate random bytes
        let bytes = rng.random_bytes_32();

        // Ensure the private key is valid for secp256k1 (must be < curve order)
        // The secp256k1 curve order is: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        // We'll use a simple check: ensure it's not zero and not too large
        if !is_zero(&bytes) && is_valid_secp256k1_key(&bytes) {
            return PrivateKey::from_bytes(bytes);
        }
    }
}


/// Checks if a byte array is all zeros
fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// Checks if a private key is valid for secp256k1
/// This is a simplified check - in production you'd want to use a proper secp256k1 library
fn is_valid_secp256k1_key(bytes: &[u8; 32]) -> bool {
    // secp256k1 curve order: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    const SECP256K1_ORDER: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
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

/// Generates an EVM private key as raw bytes (legacy function)
///
/// This function uses the default thread-local RNG internally.
///
/// # Returns
///
/// A Vec<u8> containing the 32 bytes of the private key
///
/// # Example
///
/// ```
/// use evm_account_generator::evm_key_generator::generate_private_key_bytes;
///
/// let private_key_bytes = generate_private_key_bytes();
/// println!("Generated private key bytes: {:?}", private_key_bytes);
/// assert_eq!(private_key_bytes.len(), 32);
/// ```
pub fn generate_private_key_bytes() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    generate_private_key_with_rng(&mut rng).to_bytes()
}

/// Validates if a string is a valid EVM private key format
///
/// # Arguments
///
/// * `key` - A string slice that holds the private key to validate
///
/// # Returns
///
/// A boolean indicating whether the key is valid
///
/// # Example
///
/// ```
/// use evm_account_generator::evm_key_generator::is_valid_private_key;
///
/// let key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
/// assert!(is_valid_private_key(key));
/// ```
pub fn is_valid_private_key(key: &str) -> bool {
    PrivateKey::from_hex(key).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIVATE_KEY: &str =
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    /// Mock RNG for deterministic testing
    struct MockRng {
        bytes: [u8; 32],
        call_count: usize,
    }

    impl MockRng {
        fn new(bytes: [u8; 32]) -> Self {
            Self { bytes, call_count: 0 }
        }
    }

    impl RandomBytes32 for MockRng {
        fn random_bytes_32(&mut self) -> [u8; 32] {
            self.call_count += 1;
            // Return invalid bytes first (all zeros), then valid bytes
            if self.call_count == 1 {
                [0u8; 32] // Invalid: all zeros
            } else {
                self.bytes // Valid bytes
            }
        }
    }

    #[test]
    fn test_private_key_creation() {
        let key = PrivateKey::from_hex(TEST_PRIVATE_KEY).unwrap();
        assert_eq!(key.to_hex(), TEST_PRIVATE_KEY);
    }

    #[test]
    fn test_to_hex_trait() {
        let mut rng = rand::thread_rng();
        let key = generate_private_key_with_rng(&mut rng);
        let hex = key.to_hex();

        // Verify it's a valid hex string with proper format
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 66); // 0x + 64 hex chars
        assert!(is_valid_private_key(&hex));
    }

    #[test]
    fn test_generate_private_key_with_explicit_rng() {
        let mut rng = rand::thread_rng();
        let key = generate_private_key_with_rng(&mut rng);
        let hex = key.to_hex();

        // Verify the generated key is valid
        assert!(is_valid_private_key(&hex));
        assert_eq!(hex.len(), 66); // 0x + 64 hex chars
        assert!(hex.starts_with("0x"));

        // Verify it's not all zeros
        assert_ne!(
            hex,
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_generate_private_key_randomness() {
        // Generate multiple keys and ensure they're different
        let mut rng = rand::thread_rng();
        let key1 = generate_private_key_with_rng(&mut rng);
        let key2 = generate_private_key_with_rng(&mut rng);
        let key3 = generate_private_key_with_rng(&mut rng);

        // Very unlikely to generate the same key twice
        assert_ne!(key1.to_hex(), key2.to_hex());
        assert_ne!(key2.to_hex(), key3.to_hex());
        assert_ne!(key1.to_hex(), key3.to_hex());
    }

    #[test]
    fn test_generate_private_key_bytes() {
        let bytes = generate_private_key_bytes();
        assert_eq!(bytes.len(), 32);

        // Verify the bytes form a valid private key
        let hex_string = format!("0x{}", hex::encode(&bytes));
        assert!(is_valid_private_key(&hex_string));
    }

    #[test]
    fn test_private_key_from_bytes() {
        let mut rng = rand::thread_rng();
        let original_key = generate_private_key_with_rng(&mut rng);
        let bytes = *original_key.as_bytes();
        let reconstructed_key = PrivateKey::from_bytes(bytes);

        assert_eq!(original_key, reconstructed_key);
        assert_eq!(original_key.to_hex(), reconstructed_key.to_hex());
    }

    #[test]
    fn test_is_valid_private_key() {
        // Valid keys
        assert!(is_valid_private_key(TEST_PRIVATE_KEY));
        assert!(is_valid_private_key(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ));

        // Test with generated key
        let mut rng = rand::thread_rng();
        let generated_key = generate_private_key_with_rng(&mut rng);
        assert!(is_valid_private_key(&generated_key.to_hex()));

        // Invalid keys
        assert!(!is_valid_private_key("0x123")); // Too short
        assert!(!is_valid_private_key(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefg"
        )); // Invalid hex character
        assert!(!is_valid_private_key(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1"
        )); // Too long
    }

    #[test]
    fn test_private_key_error_handling() {
        // Test invalid hex
        assert!(PrivateKey::from_hex("0x123g").is_err());

        // Test wrong length
        assert!(PrivateKey::from_hex("0x123").is_err());

        // Test too long
        assert!(
            PrivateKey::from_hex(
                "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12"
            )
            .is_err()
        );
    }

    #[test]
    fn test_secp256k1_validation() {
        // Test that we don't generate invalid keys
        let mut rng = rand::thread_rng();
        for _ in 0..10 {
            let key = generate_private_key_with_rng(&mut rng);
            let bytes = key.as_bytes();

            // Should not be all zeros
            assert!(!is_zero(bytes));

            // Should be valid for secp256k1
            assert!(is_valid_secp256k1_key(bytes));
        }
    }

    #[test]
    fn test_zero_key_detection() {
        let zero_bytes = [0u8; 32];
        assert!(is_zero(&zero_bytes));

        let non_zero_bytes = [1u8; 32];
        assert!(!is_zero(&non_zero_bytes));
    }

    #[test]
    fn test_generate_private_key_with_rng() {
        // Test with deterministic mock RNG
        let test_bytes = [
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
            0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78,
            0x90, 0xab, 0xcd, 0xef,
        ];
        let mut mock_rng = MockRng::new(test_bytes);

        let key = generate_private_key_with_rng(&mut mock_rng);
        let expected_key = PrivateKey::from_bytes(test_bytes);

        assert_eq!(key, expected_key);
        assert_eq!(key.to_hex(), expected_key.to_hex());
        
        // Verify that the mock RNG was called twice (once for zeros, once for valid bytes)
        assert_eq!(mock_rng.call_count, 2);
    }

    #[test]
    fn test_generate_private_key_with_real_rng() {
        // Test with real RNG
        let mut rng = rand::thread_rng();
        let key = generate_private_key_with_rng(&mut rng);
        
        // Verify the generated key is valid
        assert!(is_valid_private_key(&key.to_hex()));
        assert_eq!(key.to_hex().len(), 66); // 0x + 64 hex chars
        assert!(key.to_hex().starts_with("0x"));
    }


    #[test]
    fn test_composability_with_different_rngs() {
        // Test that we can use different RNG implementations
        let test_bytes1 = [1u8; 32];
        let test_bytes2 = [2u8; 32];
        
        let mut mock_rng1 = MockRng::new(test_bytes1);
        let mut mock_rng2 = MockRng::new(test_bytes2);
        
        let key1 = generate_private_key_with_rng(&mut mock_rng1);
        let key2 = generate_private_key_with_rng(&mut mock_rng2);
        
        // Keys should be different because they use different mock data
        assert_ne!(key1, key2);
        assert_ne!(key1.to_hex(), key2.to_hex());
    }
}
