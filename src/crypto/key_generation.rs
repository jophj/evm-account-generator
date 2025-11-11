//! EVM private key generation functions

use crate::crypto::EVMPrivateKey;
use crate::traits::{FromBytes, PrivateKey, RandomBytes32};

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
/// use evm_account_generator::{generate_private_key_with_rng, PrivateKey};
/// use rand::thread_rng;
///
/// let mut rng = thread_rng();
/// let private_key = generate_private_key_with_rng(&mut rng);
/// println!("Generated private key: {}", private_key.to_hex());
/// ```
pub fn generate_private_key_with_rng<R: RandomBytes32>(rng: &mut R) -> EVMPrivateKey {
    loop {
        // Generate random bytes
        let bytes = rng.random_bytes_32();

        // Ensure the private key is valid for secp256k1 (must be < curve order)
        // The secp256k1 curve order is: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        // We'll use a simple check: ensure it's not zero and not too large
        if !is_zero(&bytes) && is_valid_secp256k1_key(&bytes) {
            return EVMPrivateKey::from_bytes(bytes).unwrap();
        }
    }
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
/// use evm_account_generator::generate_private_key_bytes;
///
/// let private_key_bytes = generate_private_key_bytes();
/// println!("Generated private key bytes: {:?}", private_key_bytes);
/// assert_eq!(private_key_bytes.len(), 32);
/// ```
pub fn generate_private_key_bytes() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    generate_private_key_with_rng(&mut rng).to_bytes()
}

/// Checks if a byte array is all zeros
fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// Checks if a private key is valid for secp256k1
/// This is a simplified check - in production you'd want to use a proper secp256k1 library
pub fn is_valid_secp256k1_key(bytes: &[u8; 32]) -> bool {
    EVMPrivateKey::is_valid(*bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::mock::MockRng;
    use crate::traits::{FromHex, PrivateKey};

    #[test]
    fn test_generate_private_key_with_explicit_rng() {
        let mut rng = rand::thread_rng();
        let key = generate_private_key_with_rng(&mut rng);
        let hex = key.to_hex();

        // Verify the generated key is valid
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
        let key = EVMPrivateKey::from_hex(&hex_string);
        assert!(key.is_ok());
    }

    #[test]
    fn test_zero_key_detection() {
        let zero_bytes = [0u8; 32];
        assert!(is_zero(&zero_bytes));

        let non_zero_bytes = [1u8; 32];
        assert!(!is_zero(&non_zero_bytes));
    }

    #[test]
    fn test_generate_private_key_with_mock_rng() {
        // Test with deterministic mock RNG
        let test_bytes = [
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
            0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78,
            0x90, 0xab, 0xcd, 0xef,
        ];
        let mut mock_rng = MockRng::new(test_bytes);

        let key = generate_private_key_with_rng(&mut mock_rng);
        let expected_key = EVMPrivateKey::from_bytes(test_bytes).unwrap();

        assert_eq!(key.to_hex(), expected_key.to_hex());

        // Verify that the mock RNG was called twice (once for zeros, once for valid bytes)
        assert_eq!(mock_rng.call_count(), 2);
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
        assert_ne!(key1.to_hex(), key2.to_hex());
    }
}
