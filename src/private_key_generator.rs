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
//!     RngPrivateKeyGenerator, PrivateKeyGenerator, ThreadRngFillBytes, PrivateKey,
//!     evm::PrivateKey as EvmKey,
//! };
//!
//! let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
//! let evm_key: EvmKey = generator.generate();
//! println!("EVM Key (32 bytes): {}", evm_key.to_string());
//! ```
//!
//! ## Using with Multiple Blockchains
//!
//! ```
//! use evm_account_generator::{
//!     RngPrivateKeyGenerator, PrivateKeyGenerator, ThreadRngFillBytes, PrivateKey,
//!     evm::PrivateKey as EvmKey,
//!     solana::PrivateKey as SolanaKey,
//! };
//!
//! // Create a single generator
//! let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
//!
//! // Generate keys for different blockchains with different sizes
//! let evm_key: EvmKey = generator.generate();         // 32 bytes
//! let solana_key: SolanaKey = generator.generate();   // 64 bytes
//!
//! println!("EVM Key: {}", evm_key.to_string());
//! println!("Solana Key: {}", solana_key.to_string());
//! ```
//!
//! ## Writing Generic Functions
//!
//! ```
//! use evm_account_generator::{
//!     RngPrivateKeyGenerator, PrivateKeyGenerator, PrivateKey, FillBytes,
//! };
//!
//! fn generate_batch<T, R>(generator: &mut RngPrivateKeyGenerator<R>, count: usize) -> Vec<T>
//! where
//!     T: PrivateKey,
//!     R: FillBytes,
//! {
//!     (0..count).map(|_| generator.generate()).collect()
//! }
//! ```

use crate::{PrivateKey};

/// Generic trait for generating private keys of a specific type
///
/// This trait allows for different implementations of key generation strategies.
/// The type parameter `T` must implement `PrivateKey`, ensuring type safety
/// across different blockchain networks.
pub trait PrivateKeyGenerator<T: PrivateKey> {
    fn generate(&mut self) -> T;
}

pub trait FillBytes {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

pub struct RngPrivateKeyGenerator<R: FillBytes> {
    rng: R,
}


pub struct SequentialPrivateKeyGenerator<K: PrivateKey> {
    current: Vec<u8>,
    _phantom: std::marker::PhantomData<K>,
}

impl<K: PrivateKey> SequentialPrivateKeyGenerator<K> {

    pub fn new(seed: K) -> Self {
        Self {
            current: seed.as_bytes().to_vec(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Increments the internal byte array by 1 (big-endian)
    ///
    /// This treats the byte array as a big-endian unsigned integer and adds 1.
    /// If overflow occurs, it wraps around to 1 (skipping 0 since 0 is invalid).
    fn increment_bytes(&mut self) {
        // Add 1 to the byte array, treating it as big-endian
        let mut carry = 1u16;
        for byte in self.current.iter_mut().rev() {
            let sum = *byte as u16 + carry;
            *byte = sum as u8;
            carry = sum >> 8;
            if carry == 0 {
                break;
            }
        }

        // If we overflowed (carry still > 0 after the loop), all bytes wrapped to 0
        // Set to 1 to skip the invalid all-zeros value
        if carry > 0 {
            let len = self.current.len();
            self.current[len - 1] = 1;
        }
    }
}

impl<K: PrivateKey> PrivateKeyGenerator<K> for SequentialPrivateKeyGenerator<K> {

    fn generate(&mut self) -> K {
        loop {
            // Increment the current value
            self.increment_bytes();

            // Try to create a key from the current bytes
            // If valid, return it; otherwise, continue incrementing
            if K::is_valid(&self.current) {
                return K::new(&self.current).expect("Validated bytes should create valid key");
            }
            // If invalid, loop continues and increments again
        }
    }
}


impl<R: FillBytes> RngPrivateKeyGenerator<R> {
    pub fn new(rng: R) -> Self {
        Self { rng }
    }
}


impl<T, R> PrivateKeyGenerator<T> for RngPrivateKeyGenerator<R>
where
    T: PrivateKey,
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
    use crate::{evm::PrivateKey as EvmKey, ThreadRngFillBytes};

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
        let private_key: EvmKey = generator.generate();
        
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
        
        let key1: EvmKey = generator.generate();
        let key2: EvmKey = generator.generate();
        let key3: EvmKey = generator.generate();
        
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
        use crate::solana::PrivateKey as SolanaKey;
        
        let mock_rng = MockRng::new(vec![
            vec![0u8; 64],  // Invalid: all zeros
            vec![5u8; 64],  // Valid - 64 bytes for Solana
        ]);
        
        let mut generator: RngPrivateKeyGenerator<MockRng> = RngPrivateKeyGenerator::new(mock_rng);
        let private_key: SolanaKey = generator.generate();
        
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
        let key: EvmKey = generator.generate();
        
        assert_eq!(
            key.to_string(),
            "0x0707070707070707070707070707070707070707070707070707070707070707"
        );
    }

    #[test]
    fn test_generator_with_different_sizes() {
        use crate::solana::PrivateKey as SolanaKey;
        
        // Test that the same generator can handle different key sizes
        let mock_rng = MockRng::new(vec![
            vec![10u8; 32],  // For EVM (32 bytes)
            vec![20u8; 64],  // For Solana (64 bytes)
        ]);
        
        let mut generator = RngPrivateKeyGenerator::new(mock_rng);
        
        // Generate 32-byte EVM key
        let evm_key: EvmKey = generator.generate();
        assert_eq!(evm_key.as_bytes().len(), 32);
        
        // Generate 64-byte Solana key with same generator
        let sol_key: SolanaKey = generator.generate();
        assert_eq!(sol_key.as_bytes().len(), 64);
    }

    #[test]
    fn test_generator_produces_valid_addresses() {
        use crate::solana::PrivateKey as SolanaKey;
        
        let mock_rng = MockRng::new(vec![
            vec![11u8; 32],  // EVM key
            vec![22u8; 64],  // Solana key
        ]);
        
        let mut generator = RngPrivateKeyGenerator::new(mock_rng);
        
        // Test EVM address generation
        let evm_key: EvmKey = generator.generate();
        let evm_addr = evm_key.derive_address();
        assert!(evm_addr.to_string().starts_with("0x"));
        assert_eq!(evm_addr.to_string().len(), 42); // 0x + 40 hex chars
        
        // Test Solana address generation
        let sol_key: SolanaKey = generator.generate();
        let sol_addr = sol_key.derive_address();
        assert!(sol_addr.to_string().starts_with("Sol"));
    }

    #[test]
    fn test_key_size_detection() {
        // Verify that key_size() returns correct values
        assert_eq!(EvmKey::key_size(), 32);
        
        use crate::solana::PrivateKey as SolanaKey;
        assert_eq!(SolanaKey::key_size(), 64);
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
        
        let key1: EvmKey = generator.generate();
        let key2: EvmKey = generator.generate();
        let key3: EvmKey = generator.generate(); // Should cycle back to first
        
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
        use crate::solana::PrivateKey as SolanaKey;
        
        let mock_rng = MockRng::new(vec![
            vec![0x11; 64],
            vec![0x22; 64],
            vec![0x33; 64],
        ]);
        
        let mut generator = RngPrivateKeyGenerator::new(mock_rng);
        
        let key1: SolanaKey = generator.generate();
        let key2: SolanaKey = generator.generate();
        let key3: SolanaKey = generator.generate();
        
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
        use crate::solana::PrivateKey as SolanaKey;
        
        let mock_rng = MockRng::new(vec![
            vec![0x10; 32],  // EVM
            vec![0x20; 64],  // Solana
            vec![0x30; 32],  // EVM
            vec![0x40; 64],  // Solana
        ]);
        
        let mut generator = RngPrivateKeyGenerator::new(mock_rng);
        
        // Alternate between blockchain types
        let evm1: EvmKey = generator.generate();
        let sol1: SolanaKey = generator.generate();
        let evm2: EvmKey = generator.generate();
        let sol2: SolanaKey = generator.generate();
        
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
        let key1: EvmKey = generator.generate();
        let key2: EvmKey = generator.generate();
        
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
        use crate::solana::PrivateKey as SolanaKey;
        
        // Test that ThreadRngFillBytes works with different blockchain types
        let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
        
        // Generate EVM keys (32 bytes each)
        let evm_key1: EvmKey = generator.generate();
        let evm_key2: EvmKey = generator.generate();
        
        // Generate Solana keys with the same generator (64 bytes each)
        let sol_key1: SolanaKey = generator.generate();
        let sol_key2: SolanaKey = generator.generate();
        
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

    // Tests for SequentialPrivateKeyGenerator

    #[test]
    fn test_sequential_generator_basic_evm() {
        // Test sequential generation starting from 1
        let seed = EvmKey::from_string("0x0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let mut generator = SequentialPrivateKeyGenerator::new(seed);
        
        let key1 = generator.generate();
        let key2 = generator.generate();
        let key3 = generator.generate();
        
        assert_eq!(
            key1.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000002"
        );
        assert_eq!(
            key2.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000003"
        );
        assert_eq!(
            key3.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000004"
        );
    }

    #[test]
    fn test_sequential_generator_with_carry() {
        // Test that carry propagates correctly when a byte overflows
        let seed = EvmKey::from_string("0x00000000000000000000000000000000000000000000000000000000000000FF").unwrap();
        let mut generator = SequentialPrivateKeyGenerator::new(seed);
        
        let key1 = generator.generate();
        let key2 = generator.generate();
        
        assert_eq!(
            key1.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000100"
        );
        assert_eq!(
            key2.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000101"
        );
    }

    #[test]
    fn test_sequential_generator_multiple_byte_carry() {
        // Test carry across multiple bytes
        let seed = EvmKey::from_string("0x000000000000000000000000000000000000000000000000000000000000FFFF").unwrap();
        let mut generator = SequentialPrivateKeyGenerator::new(seed);
        
        let key = generator.generate();
        
        assert_eq!(
            key.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000010000"
        );
    }

    #[test]
    fn test_sequential_generator_solana() {
        use crate::solana::PrivateKey as SolanaKey;
        
        // Test sequential generation with Solana keys (64 bytes)
        let seed_hex = format!("0x{}", "00".repeat(63) + "01");
        let seed = SolanaKey::from_string(&seed_hex).unwrap();
        let mut generator = SequentialPrivateKeyGenerator::new(seed);
        
        let key1 = generator.generate();
        let key2 = generator.generate();
        
        let expected1 = format!("0x{}", "00".repeat(63) + "02");
        let expected2 = format!("0x{}", "00".repeat(63) + "03");
        
        assert_eq!(key1.to_string(), expected1);
        assert_eq!(key2.to_string(), expected2);
    }

    #[test]
    fn test_sequential_generator_skips_invalid_keys() {
        // Test that the generator skips invalid keys (e.g., keys >= secp256k1 order)
        // Start just before the secp256k1 curve order
        let seed = EvmKey::from_string("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F").unwrap();
        let mut generator = SequentialPrivateKeyGenerator::new(seed);
        
        // The next key would be 0xFFFF...4140 which is >= the curve order
        // So the generator should skip it and find the next valid key
        let key = generator.generate();
        
        // Verify it's valid
        assert!(EvmKey::is_valid(key.as_bytes()));
        
        // Should not be the all-zeros that would come after overflow
        assert_ne!(key.to_string(), "0x0000000000000000000000000000000000000000000000000000000000000000");
    }

    #[test]
    fn test_sequential_generator_different_seeds() {
        // Test that different seeds produce different sequences
        let seed1 = EvmKey::from_string("0x0000000000000000000000000000000000000000000000000000000000000010").unwrap();
        let seed2 = EvmKey::from_string("0x0000000000000000000000000000000000000000000000000000000000000020").unwrap();
        
        let mut gen1 = SequentialPrivateKeyGenerator::new(seed1);
        let mut gen2 = SequentialPrivateKeyGenerator::new(seed2);
        
        let key1 = gen1.generate();
        let key2 = gen2.generate();
        
        assert_eq!(
            key1.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000011"
        );
        assert_eq!(
            key2.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000021"
        );
    }

    #[test]
    fn test_sequential_generator_overflow_wraps_to_one() {
        use crate::solana::PrivateKey as SolanaKey;
        
        // Test with Solana key that will overflow (all FF bytes)
        let seed_hex = format!("0x{}", "FF".repeat(64));
        let seed = SolanaKey::from_string(&seed_hex).unwrap();
        let mut generator = SequentialPrivateKeyGenerator::new(seed);
        
        // Should wrap to 1, not 0 (since 0 is invalid)
        let key = generator.generate();
        
        // The key should be valid and not all zeros
        assert!(SolanaKey::is_valid(key.as_bytes()));
        
        // Verify it's 1
        let expected = format!("0x{}", "00".repeat(63) + "01");
        assert_eq!(key.to_string(), expected);
    }

    #[test]
    fn test_sequential_generator_produces_valid_addresses() {
        use crate::solana::PrivateKey as SolanaKey;
        
        // Test that generated keys can derive valid addresses
        let evm_seed = EvmKey::from_string("0x0000000000000000000000000000000000000000000000000000000000000042").unwrap();
        let mut evm_gen = SequentialPrivateKeyGenerator::new(evm_seed);
        
        let evm_key = evm_gen.generate();
        let evm_addr = evm_key.derive_address();
        assert!(evm_addr.to_string().starts_with("0x"));
        assert_eq!(evm_addr.to_string().len(), 42);
        
        // Test Solana
        let sol_seed_hex = format!("0x{}", "00".repeat(63) + "42");
        let sol_seed = SolanaKey::from_string(&sol_seed_hex).unwrap();
        let mut sol_gen = SequentialPrivateKeyGenerator::new(sol_seed);
        
        let sol_key = sol_gen.generate();
        let sol_addr = sol_key.derive_address();
        assert!(sol_addr.to_string().starts_with("Sol"));
    }
}
