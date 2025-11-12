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
//!     RngPrivateKeyGenerator, PrivateKeyGenerator, PrivateKey2,
//!     evm::evm_private_key::EVMPrivateKey2,
//! };
//! use rand::thread_rng;
//!
//! let mut generator = RngPrivateKeyGenerator::new(thread_rng());
//! let evm_key: EVMPrivateKey2 = generator.generate();
//! println!("EVM Key (32 bytes): {}", evm_key.to_string());
//! ```
//!
//! ## Using with Multiple Blockchains
//!
//! ```
//! use evm_account_generator::{
//!     RngPrivateKeyGenerator, PrivateKeyGenerator, PrivateKey2,
//!     evm::evm_private_key::EVMPrivateKey2,
//!     solana::solana_private_key::SolanaPrivateKey2,
//! };
//! use rand::thread_rng;
//!
//! // Create a single generator
//! let mut generator = RngPrivateKeyGenerator::new(thread_rng());
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
//!     RngPrivateKeyGenerator, PrivateKeyGenerator, PrivateKey2,
//! };
//! use rand::RngCore;
//!
//! fn generate_batch<T, R>(generator: &mut RngPrivateKeyGenerator<R>, count: usize) -> Vec<T>
//! where
//!     T: PrivateKey2,
//!     R: RngCore,
//! {
//!     (0..count).map(|_| generator.generate()).collect()
//! }
//! ```

use crate::PrivateKey2;
use rand::RngCore;

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
///     RngPrivateKeyGenerator, PrivateKeyGenerator,
///     evm::evm_private_key::EVMPrivateKey2,
/// };
/// use rand::thread_rng;
///
/// let mut generator = RngPrivateKeyGenerator::new(thread_rng());
/// let key: EVMPrivateKey2 = generator.generate();
/// ```
pub struct RngPrivateKeyGenerator<R: RngCore> {
    rng: R,
}

impl<R: RngCore> RngPrivateKeyGenerator<R> {
    /// Creates a new generator with the given RNG
    ///
    /// # Arguments
    ///
    /// * `rng` - Any random number generator implementing `rand::RngCore`
    ///
    /// # Examples
    ///
    /// ```
    /// use evm_account_generator::RngPrivateKeyGenerator;
    /// use rand::thread_rng;
    ///
    /// let generator = RngPrivateKeyGenerator::new(thread_rng());
    /// ```
    pub fn new(rng: R) -> Self {
        Self { rng }
    }
}

impl<T, R> PrivateKeyGenerator<T> for RngPrivateKeyGenerator<R>
where
    T: PrivateKey2,
    R: RngCore,
{
    fn generate(&mut self) -> T {
        let key_size = T::key_size();
        
        loop {
            // Generate the appropriate number of bytes for this key type
            let mut bytes = vec![0u8; key_size];
            self.rng.fill_bytes(&mut bytes);
            
            if T::is_valid(&bytes) {
                return T::new(&bytes).unwrap();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::evm_private_key::EVMPrivateKey2;
    use rand::RngCore;

    /// Mock RNG for testing that returns predetermined bytes
    struct MockRng {
        sequences: Vec<Vec<u8>>,
        index: usize,
    }

    impl MockRng {
        fn new(sequences: Vec<Vec<u8>>) -> Self {
            Self { sequences, index: 0 }
        }
    }

    impl RngCore for MockRng {
        fn next_u32(&mut self) -> u32 {
            unimplemented!("MockRng only implements fill_bytes")
        }

        fn next_u64(&mut self) -> u64 {
            unimplemented!("MockRng only implements fill_bytes")
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let source = &self.sequences[self.index];
            dest.copy_from_slice(&source[..dest.len()]);
            self.index = (self.index + 1) % self.sequences.len();
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
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
        assert_eq!(private_key.to_string(), "0x0101010101010101010101010101010101010101010101010101010101010101");
    }

    #[test]
    fn test_generate_multiple_keys() {
        let mock_rng = MockRng::new(vec![
            vec![1u8; 32],
            vec![2u8; 32],
            vec![3u8; 32],
        ]);
        
        let mut generator = RngPrivateKeyGenerator::new(mock_rng);
        
        let key1: EVMPrivateKey2 = generator.generate();
        let key2: EVMPrivateKey2 = generator.generate();
        let key3: EVMPrivateKey2 = generator.generate();
        
        assert_eq!(key1.to_string(), "0x0101010101010101010101010101010101010101010101010101010101010101");
        assert_eq!(key2.to_string(), "0x0202020202020202020202020202020202020202020202020202020202020202");
        assert_eq!(key3.to_string(), "0x0303030303030303030303030303030303030303030303030303030303030303");
    }

    #[test]
    fn test_with_thread_rng() {
        use rand::thread_rng;
        
        let mut generator = RngPrivateKeyGenerator::new(thread_rng());
        
        let key1: EVMPrivateKey2 = generator.generate();
        let key2: EVMPrivateKey2 = generator.generate();
        
        // Keys should be different
        assert_ne!(key1.to_string(), key2.to_string());
        
        // Both should be valid hex strings with 0x prefix
        assert!(key1.to_string().starts_with("0x"));
        assert!(key2.to_string().starts_with("0x"));
        assert_eq!(key1.to_string().len(), 66); // 0x + 64 hex chars
        assert_eq!(key2.to_string().len(), 66);
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
        assert_eq!(
            private_key.to_string(), 
            "0x0505050505050505050505050505050505050505050505050505050505050505\
             0505050505050505050505050505050505050505050505050505050505050505"
        );
    }

    #[test]
    fn test_generator_works_with_multiple_blockchain_types() {
        use crate::solana::solana_private_key::SolanaPrivateKey2;
        use rand::thread_rng;
        
        // Create a single RNG generator
        let mut generator = RngPrivateKeyGenerator::new(thread_rng());
        
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