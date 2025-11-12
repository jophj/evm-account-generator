//! Generic PrivateKey trait demonstration
//!
//! This module demonstrates how to design a generic PrivateKey trait that can be
//! implemented across different blockchain types (EVM, Solana, etc.)

use crate::error::{EvmError, Result};

/// Generic PrivateKey trait that can be implemented for different blockchain types
/// 
/// This trait supports keys of different sizes (e.g., 32 bytes for EVM, 64 bytes for Solana)
pub trait PrivateKey: Sized + Clone {
    /// The type of address this private key generates
    type Address: std::fmt::Display;

    /// Creates a new private key from raw bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice representing the private key
    ///
    /// # Returns
    ///
    /// Result containing the private key or an error if invalid
    fn create(bytes: &[u8]) -> Result<Self>;

    /// Returns the private key as a byte slice reference
    fn as_bytes(&self) -> &[u8];

    /// Converts the private key to a hexadecimal string
    fn to_hex(&self) -> String;

    /// Derives the address from this private key
    fn derive_address(&self) -> Self::Address;

    /// Validates if the byte slice is a valid private key for this blockchain
    fn is_valid(bytes: &[u8]) -> bool;

    /// Returns the expected size in bytes for this key type
    fn key_size() -> usize;
}

// ============================================================================
// EVM Private Key Implementation
// ============================================================================

/// EVM-specific private key implementation
#[derive(Debug, Clone, PartialEq)]
pub struct EVMPrivateKey {
    bytes: [u8; 32],
}

/// EVM address type
#[derive(Debug, Clone, PartialEq)]
pub struct EVMAddress(String);

impl std::fmt::Display for EVMAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PrivateKey for EVMPrivateKey {
    type Address = EVMAddress;

    fn create(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(EvmError::InvalidPrivateKey(
                format!("EVM private key must be exactly 32 bytes, got {}", bytes.len()),
            ));
        }

        if !Self::is_valid(bytes) {
            return Err(EvmError::InvalidPrivateKey(
                "Invalid private key: must be non-zero and less than secp256k1 curve order".to_string(),
            ));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: key_bytes })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.bytes))
    }

    fn derive_address(&self) -> Self::Address {
        use keccak_asm::{Digest, Keccak256};
        use secp256k1::{PublicKey, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&self.bytes)
            .expect("Private key should be valid for secp256k1");

        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let public_key_bytes = public_key.serialize_uncompressed();
        let public_key_coords = &public_key_bytes[1..];

        let mut hasher = Keccak256::new();
        hasher.update(public_key_coords);
        let hash = hasher.finalize();

        let address_bytes = &hash[12..32];
        EVMAddress(format!("0x{}", hex::encode(address_bytes)))
    }

    fn is_valid(bytes: &[u8]) -> bool {
        // Must be exactly 32 bytes
        if bytes.len() != 32 {
            return false;
        }

        // Check if all zeros
        if bytes.iter().all(|&b| b == 0) {
            return false;
        }

        // secp256k1 curve order
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
        }

        false
    }

    fn key_size() -> usize {
        32
    }
}

// ============================================================================
// Solana Private Key Implementation
// ============================================================================

/// Solana-specific private key implementation
/// Solana uses Ed25519 keypairs which are 64 bytes (32 byte seed + 32 byte public key)
#[derive(Debug, Clone, PartialEq)]
pub struct SolanaPrivateKey {
    bytes: [u8; 64],
}

/// Solana address type (base58 encoded)
#[derive(Debug, Clone, PartialEq)]
pub struct SolanaAddress(String);

impl std::fmt::Display for SolanaAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PrivateKey for SolanaPrivateKey {
    type Address = SolanaAddress;

    fn create(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(EvmError::InvalidPrivateKey(
                format!("Solana private key must be exactly 64 bytes, got {}", bytes.len()),
            ));
        }

        if !Self::is_valid(bytes) {
            return Err(EvmError::InvalidPrivateKey(
                "Invalid Solana private key: must be non-zero".to_string(),
            ));
        }

        let mut key_bytes = [0u8; 64];
        key_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: key_bytes })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.bytes))
    }

    fn derive_address(&self) -> Self::Address {
        // For Solana, the address is derived from the Ed25519 public key
        // In a real implementation, the public key is stored in bytes[32..64]
        // This is a simplified version - real implementation would use ed25519-dalek
        use keccak_asm::{Digest, Keccak256};
        
        // The public key portion is typically the last 32 bytes
        let pubkey_bytes = &self.bytes[32..64];
        
        let mut hasher = Keccak256::new();
        hasher.update(pubkey_bytes);
        let hash = hasher.finalize();
        
        // Mock base58 encoding (real Solana would use proper base58)
        SolanaAddress(format!("Sol{}", hex::encode(&hash[..16])))
    }

    fn is_valid(bytes: &[u8]) -> bool {
        // Must be exactly 64 bytes
        if bytes.len() != 64 {
            return false;
        }

        // For Solana/Ed25519, any non-zero 64-byte value is valid
        // Ed25519 doesn't have the same curve order restrictions as secp256k1
        !bytes.iter().all(|&b| b == 0)
    }

    fn key_size() -> usize {
        64
    }
}

// ============================================================================
// Generic Functions that work with any PrivateKey implementation
// ============================================================================

/// Generic function to create and display a private key for any blockchain
pub fn create_and_display<T: PrivateKey>(bytes: &[u8]) -> Result<()> {
    let key = T::create(bytes)?;
    println!("Private Key (hex): {}", key.to_hex());
    println!("Address: {}", key.derive_address());
    Ok(())
}

/// Generic function to validate and create keys
pub fn validate_and_create<T: PrivateKey>(bytes: &[u8]) -> Result<T> {
    if T::is_valid(bytes) {
        T::create(bytes)
    } else {
        Err(EvmError::InvalidPrivateKey("Validation failed".to_string()))
    }
}

/// Generic function to compare two keys of the same type
pub fn keys_match<T: PrivateKey>(key1: &T, key2: &T) -> bool {
    key1.as_bytes() == key2.as_bytes()
}

// ============================================================================
// Tests demonstrating generic trait usage
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Test data for EVM (32 bytes)
    const TEST_BYTES_EVM_1: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
    ];

    const TEST_BYTES_EVM_2: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    // Test data for Solana (64 bytes)
    const TEST_BYTES_SOLANA_1: [u8; 64] = [
        // First 32 bytes (seed)
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
        // Second 32 bytes (public key)
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
    ];

    const TEST_BYTES_SOLANA_2: [u8; 64] = [
        // First 32 bytes (seed)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        // Second 32 bytes (public key)
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    ];

    // ========================================================================
    // Test 1: Using generic functions with different implementations
    // ========================================================================

    #[test]
    fn test_generic_create_evm() {
        // Using generic create function with EVM type
        let result: Result<EVMPrivateKey> = validate_and_create(&TEST_BYTES_EVM_1);
        assert!(result.is_ok());
        
        let key = result.unwrap();
        assert_eq!(key.as_bytes(), &TEST_BYTES_EVM_1);
        assert_eq!(EVMPrivateKey::key_size(), 32);
    }

    #[test]
    fn test_generic_create_solana() {
        // Using generic create function with Solana type
        let result: Result<SolanaPrivateKey> = validate_and_create(&TEST_BYTES_SOLANA_1);
        assert!(result.is_ok());
        
        let key = result.unwrap();
        assert_eq!(key.as_bytes(), &TEST_BYTES_SOLANA_1);
        assert_eq!(SolanaPrivateKey::key_size(), 64);
    }

    // ========================================================================
    // Test 2: Generic function that works with both types
    // ========================================================================

    #[test]
    fn test_keys_match_generic() {
        // Create two EVM keys and compare using generic function
        let evm_key1 = EVMPrivateKey::create(&TEST_BYTES_EVM_1).unwrap();
        let evm_key2 = EVMPrivateKey::create(&TEST_BYTES_EVM_1).unwrap();
        let evm_key3 = EVMPrivateKey::create(&TEST_BYTES_EVM_2).unwrap();

        assert!(keys_match(&evm_key1, &evm_key2));
        assert!(!keys_match(&evm_key1, &evm_key3));

        // Create two Solana keys and compare using the same generic function
        let sol_key1 = SolanaPrivateKey::create(&TEST_BYTES_SOLANA_1).unwrap();
        let sol_key2 = SolanaPrivateKey::create(&TEST_BYTES_SOLANA_1).unwrap();
        let sol_key3 = SolanaPrivateKey::create(&TEST_BYTES_SOLANA_2).unwrap();

        assert!(keys_match(&sol_key1, &sol_key2));
        assert!(!keys_match(&sol_key1, &sol_key3));
    }

    // ========================================================================
    // Test 3: Using trait bounds in generic contexts
    // ========================================================================

    fn process_key<T: PrivateKey>(bytes: &[u8]) -> String 
    where
        T::Address: std::fmt::Display,
    {
        let key = T::create(bytes).expect("Valid key");
        format!("Key: {} -> Address: {}", key.to_hex(), key.derive_address())
    }

    #[test]
    fn test_process_key_generic() {
        let evm_info = process_key::<EVMPrivateKey>(&TEST_BYTES_EVM_1);
        assert!(evm_info.contains("0x"));
        assert!(evm_info.contains("Address:"));

        let sol_info = process_key::<SolanaPrivateKey>(&TEST_BYTES_SOLANA_1);
        assert!(sol_info.contains("0x"));
        assert!(sol_info.contains("Address:"));
    }

    // ========================================================================
    // Test 4: Working with collections of generic keys
    // ========================================================================

    #[test]
    fn test_generic_key_collection() {
        // Create a vector of EVM keys using generic trait
        let evm_keys: Vec<EVMPrivateKey> = vec![&TEST_BYTES_EVM_1[..], &TEST_BYTES_EVM_2[..]]
            .into_iter()
            .filter_map(|bytes| EVMPrivateKey::create(bytes).ok())
            .collect();

        assert_eq!(evm_keys.len(), 2);

        // Create a vector of Solana keys using the same pattern
        let sol_keys: Vec<SolanaPrivateKey> = vec![&TEST_BYTES_SOLANA_1[..], &TEST_BYTES_SOLANA_2[..]]
            .into_iter()
            .filter_map(|bytes| SolanaPrivateKey::create(bytes).ok())
            .collect();

        assert_eq!(sol_keys.len(), 2);
    }

    // ========================================================================
    // Test 5: Demonstrating validation differences
    // ========================================================================

    #[test]
    fn test_validation_differences() {
        // All zeros should fail for both
        let zeros_32 = [0u8; 32];
        let zeros_64 = [0u8; 64];
        assert!(!EVMPrivateKey::is_valid(&zeros_32));
        assert!(!SolanaPrivateKey::is_valid(&zeros_64));

        // Value at secp256k1 curve order should fail for EVM but Solana accepts any non-zero 64 bytes
        let at_order_32 = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
        ];
        
        let at_order_64 = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        
        assert!(!EVMPrivateKey::is_valid(&at_order_32)); // Invalid for EVM (at order)
        assert!(SolanaPrivateKey::is_valid(&at_order_64)); // Valid for Solana (non-zero)

        // Test wrong size validation
        assert!(!EVMPrivateKey::is_valid(&[1u8; 64])); // 64 bytes invalid for EVM
        assert!(!SolanaPrivateKey::is_valid(&[1u8; 32])); // 32 bytes invalid for Solana
    }

    // ========================================================================
    // Test 6: Using trait objects for runtime polymorphism
    // ========================================================================

    #[test]
    fn test_clone_and_compare() {
        let key1 = EVMPrivateKey::create(&TEST_BYTES_EVM_1).unwrap();
        let key2 = key1.clone();
        
        assert_eq!(key1.as_bytes(), key2.as_bytes());
        assert_eq!(key1.to_hex(), key2.to_hex());

        let sol_key1 = SolanaPrivateKey::create(&TEST_BYTES_SOLANA_1).unwrap();
        let sol_key2 = sol_key1.clone();
        
        assert_eq!(sol_key1.as_bytes(), sol_key2.as_bytes());
        assert_eq!(sol_key1.to_hex(), sol_key2.to_hex());
    }

    // ========================================================================
    // Test 7: Demonstrating address derivation
    // ========================================================================

    #[test]
    fn test_address_derivation_generic() {
        fn get_address_string<T: PrivateKey>(bytes: &[u8]) -> String {
            let key = T::create(bytes).expect("Valid key");
            key.derive_address().to_string()
        }

        let evm_address = get_address_string::<EVMPrivateKey>(&TEST_BYTES_EVM_1);
        assert!(evm_address.starts_with("0x"));
        assert_eq!(evm_address.len(), 42); // 0x + 40 hex chars

        let sol_address = get_address_string::<SolanaPrivateKey>(&TEST_BYTES_SOLANA_1);
        assert!(sol_address.starts_with("Sol"));
    }

    // ========================================================================
    // Test 8: Builder pattern with generic types
    // ========================================================================

    struct KeyPair<T: PrivateKey> {
        private_key: T,
        address: T::Address,
    }

    impl<T: PrivateKey> KeyPair<T> {
        fn new(bytes: &[u8]) -> Result<Self> {
            let private_key = T::create(bytes)?;
            let address = private_key.derive_address();
            Ok(Self { private_key, address })
        }

        fn get_hex(&self) -> String {
            self.private_key.to_hex()
        }

        fn get_address(&self) -> &T::Address {
            &self.address
        }
    }

    #[test]
    fn test_generic_keypair() {
        // Create EVM keypair
        let evm_keypair = KeyPair::<EVMPrivateKey>::new(&TEST_BYTES_EVM_1).unwrap();
        assert_eq!(evm_keypair.private_key.as_bytes(), &TEST_BYTES_EVM_1);
        assert!(evm_keypair.get_hex().starts_with("0x"));
        assert!(!evm_keypair.get_address().to_string().is_empty());

        // Create Solana keypair using the same structure
        let sol_keypair = KeyPair::<SolanaPrivateKey>::new(&TEST_BYTES_SOLANA_1).unwrap();
        assert_eq!(sol_keypair.private_key.as_bytes(), &TEST_BYTES_SOLANA_1);
        assert!(sol_keypair.get_hex().starts_with("0x"));
        assert!(!sol_keypair.get_address().to_string().is_empty());
    }

    // ========================================================================
    // Test 9: Demonstrating trait method usage consistency
    // ========================================================================

    #[test]
    fn test_trait_methods_consistency() {
        fn test_key_methods<T: PrivateKey>(bytes: &[u8]) {
            // All these methods must work the same way for any T
            let key = T::create(bytes).expect("Valid key");
            
            // as_bytes should return the original bytes
            assert_eq!(key.as_bytes(), bytes);
            
            // to_hex should produce a hex string
            let hex = key.to_hex();
            assert!(hex.starts_with("0x"));
            assert_eq!(hex.len(), 2 + bytes.len() * 2); // 0x + 2 hex chars per byte
            
            // derive_address should produce a displayable address
            let address = key.derive_address();
            let address_str = address.to_string();
            assert!(!address_str.is_empty());
        }

        // Test with EVM (32 bytes)
        test_key_methods::<EVMPrivateKey>(&TEST_BYTES_EVM_1);
        
        // Test with Solana (64 bytes)
        test_key_methods::<SolanaPrivateKey>(&TEST_BYTES_SOLANA_1);
    }

    // ========================================================================
    // Test 10: Error handling with generic types
    // ========================================================================

    #[test]
    fn test_generic_error_handling() {
        fn try_create_key<T: PrivateKey>(bytes: &[u8]) -> Result<T> {
            if !T::is_valid(bytes) {
                return Err(EvmError::InvalidPrivateKey(
                    "Key validation failed".to_string()
                ));
            }
            T::create(bytes)
        }

        let zeros_32 = [0u8; 32];
        let zeros_64 = [0u8; 64];
        
        // Both should fail with all zeros
        assert!(try_create_key::<EVMPrivateKey>(&zeros_32).is_err());
        assert!(try_create_key::<SolanaPrivateKey>(&zeros_64).is_err());
        
        // Both should succeed with valid bytes
        assert!(try_create_key::<EVMPrivateKey>(&TEST_BYTES_EVM_1).is_ok());
        assert!(try_create_key::<SolanaPrivateKey>(&TEST_BYTES_SOLANA_1).is_ok());

        // Test wrong size errors
        assert!(EVMPrivateKey::create(&zeros_64).is_err()); // Wrong size for EVM
        assert!(SolanaPrivateKey::create(&zeros_32).is_err()); // Wrong size for Solana
    }

    // ========================================================================
    // Test 11: Demonstrating key size differences
    // ========================================================================

    #[test]
    fn test_key_size_differences() {
        // EVM keys are 32 bytes
        assert_eq!(EVMPrivateKey::key_size(), 32);
        let evm_key = EVMPrivateKey::create(&TEST_BYTES_EVM_1).unwrap();
        assert_eq!(evm_key.as_bytes().len(), 32);
        
        // Solana keys are 64 bytes
        assert_eq!(SolanaPrivateKey::key_size(), 64);
        let sol_key = SolanaPrivateKey::create(&TEST_BYTES_SOLANA_1).unwrap();
        assert_eq!(sol_key.as_bytes().len(), 64);
        
        // Hex representation reflects the different sizes
        // EVM: 0x + 64 hex chars (32 bytes * 2)
        assert_eq!(evm_key.to_hex().len(), 66);
        // Solana: 0x + 128 hex chars (64 bytes * 2)
        assert_eq!(sol_key.to_hex().len(), 130);
    }
}

