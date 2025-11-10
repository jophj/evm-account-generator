//! Private key validation functions

use crate::crypto::PrivateKey;

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
/// use evm_account_generator::crypto::is_valid_private_key;
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
    use crate::crypto::generate_private_key_with_rng;
    use crate::types::ToHex;

    const TEST_PRIVATE_KEY: &str =
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

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
}
