//! Generic Private Key Generator
//!
//! This module provides a generic, blockchain-agnostic approach to generating private keys.
//! The same generator can create keys for different blockchain networks (EVM, Solana, etc.)
//! by leveraging Rust's type system and the `PrivateKey2` trait.
//!
//! # Architecture
//!
//! The module consists of two main components:
//! - `PrivateKeyGenerator<T>` - A generic trait for generating private keys of type T
//! - `RngPrivateKeyGenerator<R>` - A concrete implementation that uses any RNG
//!
//! # Key Features
//!
//! - **Flexible Key Sizes**: Automatically generates the correct number of bytes (32 for EVM, 64 for Solana)
//! - **Type Safety**: Compile-time guarantees using Rust's type system
//! - **Automatic Validation**: Retries generation if invalid keys are produced
//!
//! # Examples
//!
//! ## Basic Usage with EVM
//!
//! ```
//! use evm_account_generator::{
//!     RngPrivateKeyGenerator, PrivateKeyGenerator, ThreadRngFillBytes, PrivateKey2,
//!     evm::evm_private_key::EVMPrivateKey2,
//! };
//!
//! let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
//! let evm_key: EVMPrivateKey2 = generator.generate();
//! println!("EVM Key (32 bytes): {}", evm_key.to_string());
//! ```
//!
//! ## Using with Multiple Blockchains
//!
//! ```
//! use evm_account_generator::{
//!     RngPrivateKeyGenerator, PrivateKeyGenerator, ThreadRngFillBytes, PrivateKey2,
//!     evm::evm_private_key::EVMPrivateKey2,
//!     solana::solana_private_key::SolanaPrivateKey2,
//! };
//!
//! // Create a single generator
//! let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
//!
//! // Generate keys for different blockchains with different sizes
//! let evm_key: EVMPrivateKey2 = generator.generate();      // 32 bytes
//! let solana_key: SolanaPrivateKey2 = generator.generate(); // 64 bytes
//!
//! println!("EVM Key: {}", evm_key.to_string());
//! println!("Solana Key: {}", solana_key.to_string());
//! ```
//!
//! ## Writing Generic Functions
//!
//! ```
//! use evm_account_generator::{
//!     RngPrivateKeyGenerator, PrivateKeyGenerator, PrivateKey2, FillBytes,
//! };
//!
//! fn generate_batch<T, R>(generator: &mut RngPrivateKeyGenerator<R>, count: usize) -> Vec<T>
//! where
//!     T: PrivateKey2,
//!     R: FillBytes,
//! {
//!     (0..count).map(|_| generator.generate()).collect()
//! }
//! ```

use crate::PrivateKey2;

/// Generic trait for generating private keys of a specific type
///
/// This trait allows for different implementations of key generation strategies.
/// The type parameter `T` must implement `PrivateKey2`, ensuring type safety
/// across different blockchain networks.
pub trait PrivateKeyGenerator<T: PrivateKey2> {
    /// Generates a new private key of type T
    ///
    /// # Returns
    ///
    /// A newly generated private key of type T
    fn generate(&mut self) -> T;
}

/// Trait for types that can fill a byte buffer with random data
///
/// This trait provides a simple interface for random byte generation
/// without requiring a blanket implementation over all RNG types.
pub trait FillBytes {
    /// Fill the destination buffer with random bytes
    ///
    /// # Arguments
    ///
    /// * `dest` - A mutable byte slice to fill with random data
    fn fill_bytes(&mut self, dest: &mut [u8]);
}


/// A concrete implementation of PrivateKeyGenerator that uses an RNG
/// to generate random private keys for any blockchain type
///
/// This generator is generic over both the private key type (T) and the RNG type (R).
/// It automatically handles:
/// - Different key sizes (32 bytes for EVM, 64 bytes for Solana, etc.)
/// - Invalid keys by retrying with new random bytes
/// - Blockchain-specific validation rules
///
/// # Type Parameters
///
/// * `R` - The random number generator type, must implement `rand::RngCore`
///
/// # Examples
///
/// ```
/// use evm_account_generator::{
///     RngPrivateKeyGenerator, PrivateKeyGenerator, ThreadRngFillBytes,
///     evm::evm_private_key::EVMPrivateKey2,
/// };
///
/// let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
/// let key: EVMPrivateKey2 = generator.generate();
/// ```
pub struct RngPrivateKeyGenerator<R: FillBytes> {
    rng: R,
}

impl<R: FillBytes> RngPrivateKeyGenerator<R> {
    /// Creates a new generator with the given RNG
    ///
    /// # Arguments
    ///
    /// * `rng` - Any random number generator implementing `rand::RngCore`
    ///
    /// # Examples
    ///
    /// ```
    /// use evm_account_generator::{RngPrivateKeyGenerator, ThreadRngFillBytes};
    ///
    /// let generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
    /// ```
    pub fn new(rng: R) -> Self {
        Self { rng }
    }
}

impl<T, R> PrivateKeyGenerator<T> for RngPrivateKeyGenerator<R>
where
    T: PrivateKey2,
    R: FillBytes,
{
    /// Generates a new private key of type T
    ///
    /// This method:
    /// 1. Queries the key size from T::key_size()
    /// 2. Generates random bytes of the appropriate size
    /// 3. Validates the bytes using T::is_valid()
    /// 4. If invalid, generates new bytes and retries (loop until valid)
    /// 5. Returns the validated key
    ///
    /// # Returns
    ///
    /// A newly generated and validated private key
    ///
    /// # Notes
    ///
    /// The generator takes `&mut self` because the RNG needs to update its internal state.
    /// For most RNGs, this is necessary to produce different random values on each call.
    fn generate(&mut self) -> T {
        let key_size = T::key_size();
        
        loop {
            // Generate the appropriate number of bytes for this key type
            let mut bytes = vec![0u8; key_size];
            
            // Fill with random bytes from the RNG
            self.rng.fill_bytes(&mut bytes);

            // Validate and return if valid, otherwise retry
            if T::is_valid(&bytes) {
                // We know it's valid because we just checked, so unwrap is safe
                return T::new(&bytes).unwrap();
            }
            // If invalid, loop continues and generates new random bytes
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{evm::evm_private_key::EVMPrivateKey2, ThreadRngFillBytes};

    /// Mock RNG for testing that returns predetermined bytes
    struct MockRng {
        sequences: Vec<Vec<u8>>,
        index: usize,
    }

    impl MockRng {
        fn new(sequences: Vec<Vec<u8>>) -> Self {
            Self {
                sequences,
                index: 0,
            }
        }
    }

    impl FillBytes for MockRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let source = &self.sequences[self.index];
            dest.copy_from_slice(&source[..dest.len()]);
            self.index = (self.index + 1) % self.sequences.len();
        }
    }

    #[test]
    fn test_generate_evm_private_key() {
        let mock_rng = MockRng::new(vec![
            vec![0u8; 32],  // Invalid: all zeros
            vec![1u8; 32],  // Valid
        ]);
        
        let mut generator: RngPrivateKeyGenerator<MockRng> = RngPrivateKeyGenerator::new(mock_rng);
        let private_key: EVMPrivateKey2 = generator.generate();
        
        // Should skip the all-zeros and generate the valid key
        assert_eq!(
            private_key.to_string(), 
            "0x0101010101010101010101010101010101010101010101010101010101010101"
        );
    }

    #[test]
    fn test_generate_multiple_evm_keys() {
        let mock_rng = MockRng::new(vec![
            vec![1u8; 32],
            vec![2u8; 32],
            vec![3u8; 32],
        ]);
        
        let mut generator = RngPrivateKeyGenerator::new(mock_rng);
        
        let key1: EVMPrivateKey2 = generator.generate();
        let key2: EVMPrivateKey2 = generator.generate();
        let key3: EVMPrivateKey2 = generator.generate();
        
        assert_eq!(
            key1.to_string(), 
            "0x0101010101010101010101010101010101010101010101010101010101010101"
        );
        assert_eq!(
            key2.to_string(), 
            "0x0202020202020202020202020202020202020202020202020202020202020202"
        );
        assert_eq!(
            key3.to_string(), 
            "0x0303030303030303030303030303030303030303030303030303030303030303"
        );
    }

    #[test]
    fn test_generate_solana_private_key() {
        use crate::solana::solana_private_key::SolanaPrivateKey2;
        
        let mock_rng = MockRng::new(vec![
            vec![0u8; 64],  // Invalid: all zeros
            vec![5u8; 64],  // Valid - 64 bytes for Solana
        ]);
        
        let mut generator: RngPrivateKeyGenerator<MockRng> = RngPrivateKeyGenerator::new(mock_rng);
        let private_key: SolanaPrivateKey2 = generator.generate();
        
        // Should skip the all-zeros and generate the valid key (64 bytes = 128 hex chars)
        let expected = format!(
            "0x{}",
            "05".repeat(64)
        );
        assert_eq!(private_key.to_string(), expected);
        assert_eq!(private_key.to_string().len(), 130); // 0x + 128 hex chars
    }

    #[test]
    fn test_generator_handles_invalid_keys() {
        // Test that generator retries when invalid keys are generated
        let mock_rng = MockRng::new(vec![
            vec![0u8; 32],  // Invalid: all zeros
            vec![0u8; 32],  // Invalid: all zeros again
            vec![0u8; 32],  // Invalid: all zeros again
            vec![7u8; 32],  // Valid
        ]);
        
        let mut generator = RngPrivateKeyGenerator::new(mock_rng);
        let key: EVMPrivateKey2 = generator.generate();
        
        assert_eq!(
            key.to_string(),
            "0x0707070707070707070707070707070707070707070707070707070707070707"
        );
    }

    #[test]
    fn test_generator_with_different_sizes() {
        use crate::solana::solana_private_key::SolanaPrivateKey2;
        
        // Test that the same generator can handle different key sizes
        let mock_rng = MockRng::new(vec![
            vec![10u8; 32],  // For EVM (32 bytes)
            vec![20u8; 64],  // For Solana (64 bytes)
        ]);
        
        let mut generator = RngPrivateKeyGenerator::new(mock_rng);
        
        // Generate 32-byte EVM key
        let evm_key: EVMPrivateKey2 = generator.generate();
        assert_eq!(evm_key.as_bytes().len(), 32);
        
        // Generate 64-byte Solana key with same generator
        let sol_key: SolanaPrivateKey2 = generator.generate();
        assert_eq!(sol_key.as_bytes().len(), 64);
    }

    #[test]
    fn test_generator_produces_valid_addresses() {
        use crate::solana::solana_private_key::SolanaPrivateKey2;
        
        let mock_rng = MockRng::new(vec![
            vec![11u8; 32],  // EVM key
            vec![22u8; 64],  // Solana key
        ]);
        
        let mut generator = RngPrivateKeyGenerator::new(mock_rng);
        
        // Test EVM address generation
        let evm_key: EVMPrivateKey2 = generator.generate();
        let evm_addr = evm_key.derive_address();
        assert!(evm_addr.to_string().starts_with("0x"));
        assert_eq!(evm_addr.to_string().len(), 42); // 0x + 40 hex chars
        
        // Test Solana address generation
        let sol_key: SolanaPrivateKey2 = generator.generate();
        let sol_addr = sol_key.derive_address();
        assert!(sol_addr.to_string().starts_with("Sol"));
    }

    #[test]
    fn test_key_size_detection() {
        // Verify that key_size() returns correct values
        assert_eq!(EVMPrivateKey2::key_size(), 32);
        
        use crate::solana::solana_private_key::SolanaPrivateKey2;
        assert_eq!(SolanaPrivateKey2::key_size(), 64);
    }

    #[test]
    fn test_fill_bytes_trait() {
        // Test that our MockRng correctly implements FillBytes
        let mut mock_rng = MockRng::new(vec![
            vec![0xAA; 32],
            vec![0xBB; 32],
        ]);
        
        let mut buf1 = vec![0u8; 32];
        let mut buf2 = vec![0u8; 32];
        
        mock_rng.fill_bytes(&mut buf1);
        mock_rng.fill_bytes(&mut buf2);
        
        assert_eq!(buf1, vec![0xAA; 32]);
        assert_eq!(buf2, vec![0xBB; 32]);
    }

    #[test]
    fn test_generator_cycles_through_sequences() {
        // Test that MockRng cycles through its sequences
        let mock_rng = MockRng::new(vec![
            vec![1u8; 32],
            vec![2u8; 32],
        ]);
        
        let mut generator = RngPrivateKeyGenerator::new(mock_rng);
        
        let key1: EVMPrivateKey2 = generator.generate();
        let key2: EVMPrivateKey2 = generator.generate();
        let key3: EVMPrivateKey2 = generator.generate(); // Should cycle back to first
        
        assert_eq!(
            key1.to_string(),
            "0x0101010101010101010101010101010101010101010101010101010101010101"
        );
        assert_eq!(
            key2.to_string(),
            "0x0202020202020202020202020202020202020202020202020202020202020202"
        );
        assert_eq!(
            key3.to_string(),
            "0x0101010101010101010101010101010101010101010101010101010101010101"
        );
    }

    #[test]
    fn test_multiple_solana_keys() {
        use crate::solana::solana_private_key::SolanaPrivateKey2;
        
        let mock_rng = MockRng::new(vec![
            vec![0x11; 64],
            vec![0x22; 64],
            vec![0x33; 64],
        ]);
        
        let mut generator = RngPrivateKeyGenerator::new(mock_rng);
        
        let key1: SolanaPrivateKey2 = generator.generate();
        let key2: SolanaPrivateKey2 = generator.generate();
        let key3: SolanaPrivateKey2 = generator.generate();
        
        // All keys should be different
        assert_ne!(key1.to_string(), key2.to_string());
        assert_ne!(key2.to_string(), key3.to_string());
        assert_ne!(key1.to_string(), key3.to_string());
        
        // All should be 64 bytes
        assert_eq!(key1.as_bytes().len(), 64);
        assert_eq!(key2.as_bytes().len(), 64);
        assert_eq!(key3.as_bytes().len(), 64);
    }

    #[test]
    fn test_mixed_blockchain_key_generation() {
        use crate::solana::solana_private_key::SolanaPrivateKey2;
        
        let mock_rng = MockRng::new(vec![
            vec![0x10; 32],  // EVM
            vec![0x20; 64],  // Solana
            vec![0x30; 32],  // EVM
            vec![0x40; 64],  // Solana
        ]);
        
        let mut generator = RngPrivateKeyGenerator::new(mock_rng);
        
        // Alternate between blockchain types
        let evm1: EVMPrivateKey2 = generator.generate();
        let sol1: SolanaPrivateKey2 = generator.generate();
        let evm2: EVMPrivateKey2 = generator.generate();
        let sol2: SolanaPrivateKey2 = generator.generate();
        
        // Verify correct sizes
        assert_eq!(evm1.as_bytes().len(), 32);
        assert_eq!(sol1.as_bytes().len(), 64);
        assert_eq!(evm2.as_bytes().len(), 32);
        assert_eq!(sol2.as_bytes().len(), 64);
        
        // Verify all keys are unique
        assert_ne!(evm1.to_string(), evm2.to_string());
        assert_ne!(sol1.to_string(), sol2.to_string());
    }

    #[test]
    fn test_with_thread_rng() {
        // Test that ThreadRngFillBytes works with the generator
        let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
        
        // Generate EVM keys
        let key1: EVMPrivateKey2 = generator.generate();
        let key2: EVMPrivateKey2 = generator.generate();
        
        // Keys should be different (extremely unlikely to be the same)
        assert_ne!(key1.to_string(), key2.to_string());
        
        // Both should be valid hex strings with 0x prefix
        assert!(key1.to_string().starts_with("0x"));
        assert!(key2.to_string().starts_with("0x"));
        assert_eq!(key1.to_string().len(), 66); // 0x + 64 hex chars
        assert_eq!(key2.to_string().len(), 66);
    }

    #[test]
    fn test_thread_rng_with_multiple_blockchains() {
        use crate::solana::solana_private_key::SolanaPrivateKey2;
        
        // Test that ThreadRngFillBytes works with different blockchain types
        let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
        
        // Generate EVM keys (32 bytes each)
        let evm_key1: EVMPrivateKey2 = generator.generate();
        let evm_key2: EVMPrivateKey2 = generator.generate();
        
        // Generate Solana keys with the same generator (64 bytes each)
        let sol_key1: SolanaPrivateKey2 = generator.generate();
        let sol_key2: SolanaPrivateKey2 = generator.generate();
        
        // All keys should be valid and different
        assert_ne!(evm_key1.to_string(), evm_key2.to_string());
        assert_ne!(sol_key1.to_string(), sol_key2.to_string());
        
        // Verify EVM keys are 32 bytes (64 hex chars + 0x prefix = 66 chars)
        assert_eq!(evm_key1.to_string().len(), 66);
        assert_eq!(evm_key2.to_string().len(), 66);
        
        // Verify Solana keys are 64 bytes (128 hex chars + 0x prefix = 130 chars)
        assert_eq!(sol_key1.to_string().len(), 130);
        assert_eq!(sol_key2.to_string().len(), 130);
        
        // EVM keys should generate valid addresses
        let evm_addr = evm_key1.derive_address();
        assert!(evm_addr.to_string().starts_with("0x"));
        
        // Solana keys should generate valid addresses
        let sol_addr = sol_key1.derive_address();
        assert!(sol_addr.to_string().starts_with("Sol"));
    }
}
