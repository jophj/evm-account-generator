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
//! - **Flexible Key Sizes**: Automatically generates the correct number of bytes per blockchain
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
//! let evm_key: EvmKey = generator.generate();         // 32-byte secp256k1 key
//! let solana_key: SolanaKey = generator.generate();   // 32-byte Ed25519 seed
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
            vec![0u8; 32],  // Invalid: all zeros
            vec![5u8; 32],  // Valid - 32 bytes for Solana
        ]);
        
        let mut generator: RngPrivateKeyGenerator<MockRng> = RngPrivateKeyGenerator::new(mock_rng);
        let private_key: SolanaKey = generator.generate();
        
        // Should skip the all-zeros and generate the valid key
        assert_eq!(private_key.as_bytes(), &[5u8; 32]);
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
    fn test_generator_with_different_chains() {
        use crate::solana::PrivateKey as SolanaKey;
        
        let mock_rng = MockRng::new(vec![
            vec![10u8; 32],  // For EVM (32 bytes)
            vec![20u8; 32],  // For Solana (32 bytes)
        ]);
        
        let mut generator = RngPrivateKeyGenerator::new(mock_rng);
        
        let evm_key: EvmKey = generator.generate();
        assert_eq!(evm_key.as_bytes().len(), 32);
        
        let sol_key: SolanaKey = generator.generate();
        assert_eq!(sol_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_generator_produces_valid_addresses() {
        use crate::solana::PrivateKey as SolanaKey;
        
        let mock_rng = MockRng::new(vec![
            vec![11u8; 32],  // EVM key
            vec![22u8; 32],  // Solana key
        ]);
        
        let mut generator = RngPrivateKeyGenerator::new(mock_rng);
        
        let evm_key: EvmKey = generator.generate();
        let evm_addr = evm_key.derive_address();
        assert!(evm_addr.to_string().starts_with("0x"));
        assert_eq!(evm_addr.to_string().len(), 42);
        
        let sol_key: SolanaKey = generator.generate();
        let sol_addr = sol_key.derive_address();
        let addr_str = sol_addr.to_string();
        assert!(addr_str.len() >= 32 && addr_str.len() <= 44);
    }

    #[test]
    fn test_key_size_detection() {
        assert_eq!(EvmKey::key_size(), 32);
        
        use crate::solana::PrivateKey as SolanaKey;
        assert_eq!(SolanaKey::key_size(), 32);
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
            vec![0x11; 32],
            vec![0x22; 32],
            vec![0x33; 32],
        ]);
        
        let mut generator = RngPrivateKeyGenerator::new(mock_rng);
        
        let key1: SolanaKey = generator.generate();
        let key2: SolanaKey = generator.generate();
        let key3: SolanaKey = generator.generate();
        
        assert_ne!(key1.to_string(), key2.to_string());
        assert_ne!(key2.to_string(), key3.to_string());
        assert_ne!(key1.to_string(), key3.to_string());
        
        assert_eq!(key1.as_bytes().len(), 32);
        assert_eq!(key2.as_bytes().len(), 32);
        assert_eq!(key3.as_bytes().len(), 32);
    }

    #[test]
    fn test_mixed_blockchain_key_generation() {
        use crate::solana::PrivateKey as SolanaKey;
        
        let mock_rng = MockRng::new(vec![
            vec![0x10; 32],  // EVM
            vec![0x20; 32],  // Solana
            vec![0x30; 32],  // EVM
            vec![0x40; 32],  // Solana
        ]);
        
        let mut generator = RngPrivateKeyGenerator::new(mock_rng);
        
        let evm1: EvmKey = generator.generate();
        let sol1: SolanaKey = generator.generate();
        let evm2: EvmKey = generator.generate();
        let sol2: SolanaKey = generator.generate();
        
        assert_eq!(evm1.as_bytes().len(), 32);
        assert_eq!(sol1.as_bytes().len(), 32);
        assert_eq!(evm2.as_bytes().len(), 32);
        assert_eq!(sol2.as_bytes().len(), 32);
        
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
        
        let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
        
        let evm_key1: EvmKey = generator.generate();
        let evm_key2: EvmKey = generator.generate();
        let sol_key1: SolanaKey = generator.generate();
        let sol_key2: SolanaKey = generator.generate();
        
        assert_ne!(evm_key1.to_string(), evm_key2.to_string());
        assert_ne!(sol_key1.to_string(), sol_key2.to_string());
        
        // EVM: 0x + 64 hex chars = 66
        assert_eq!(evm_key1.to_string().len(), 66);
        assert_eq!(evm_key2.to_string().len(), 66);
        
        // Solana: base58 of 64-byte keypair
        assert!(sol_key1.to_string().len() > 40);
        assert!(sol_key2.to_string().len() > 40);
        
        let evm_addr = evm_key1.derive_address();
        assert!(evm_addr.to_string().starts_with("0x"));
        
        let sol_addr = sol_key1.derive_address();
        let addr_str = sol_addr.to_string();
        assert!(addr_str.len() >= 32 && addr_str.len() <= 44);
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
        
        let seed_hex = format!("0x{}", "00".repeat(31) + "01");
        let seed = SolanaKey::from_string(&seed_hex).unwrap();
        let mut generator = SequentialPrivateKeyGenerator::new(seed);
        
        let key1 = generator.generate();
        let key2 = generator.generate();
        
        assert_eq!(key1.as_bytes(), &{
            let mut b = [0u8; 32]; b[31] = 2; b
        });
        assert_eq!(key2.as_bytes(), &{
            let mut b = [0u8; 32]; b[31] = 3; b
        });
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
        
        let seed_hex = format!("0x{}", "FF".repeat(32));
        let seed = SolanaKey::from_string(&seed_hex).unwrap();
        let mut generator = SequentialPrivateKeyGenerator::new(seed);
        
        let key = generator.generate();
        
        assert!(SolanaKey::is_valid(key.as_bytes()));
        
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(key.as_bytes(), &expected);
    }

    #[test]
    fn test_sequential_generator_produces_valid_addresses() {
        use crate::solana::PrivateKey as SolanaKey;
        
        let evm_seed = EvmKey::from_string("0x0000000000000000000000000000000000000000000000000000000000000042").unwrap();
        let mut evm_gen = SequentialPrivateKeyGenerator::new(evm_seed);
        
        let evm_key = evm_gen.generate();
        let evm_addr = evm_key.derive_address();
        assert!(evm_addr.to_string().starts_with("0x"));
        assert_eq!(evm_addr.to_string().len(), 42);
        
        let sol_seed_hex = format!("0x{}", "00".repeat(31) + "42");
        let sol_seed = SolanaKey::from_string(&sol_seed_hex).unwrap();
        let mut sol_gen = SequentialPrivateKeyGenerator::new(sol_seed);
        
        let sol_key = sol_gen.generate();
        let sol_addr = sol_key.derive_address();
        let addr_str = sol_addr.to_string();
        assert!(addr_str.len() >= 32 && addr_str.len() <= 44);
    }
}
