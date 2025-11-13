//! Thread-local random number generator wrapper
//!
//! This module provides a wrapper around `rand::thread_rng()` that implements
//! the `FillBytes` trait, allowing it to be used with `RngPrivateKeyGenerator`.

use rand::RngCore;
use crate::FillBytes;

/// A wrapper around `rand::rngs::ThreadRng` that implements `FillBytes`
///
/// This wrapper provides a clean interface to use `rand::thread_rng()` with the
/// `PrivateKeyGenerator` without implementing `FillBytes` for all `RngCore` types.
///
/// # Security
///
/// `ThreadRng` is cryptographically secure and suitable for generating private keys.
/// It automatically reseeds from the system's entropy source when necessary.
///
/// # Performance
///
/// `ThreadRng` is fast and efficient, using thread-local storage to avoid
/// contention in multi-threaded applications.
///
/// # Examples
///
/// ```rust
/// use evm_account_generator::{
///     RngPrivateKeyGenerator, PrivateKeyGenerator, ThreadRngFillBytes,
///     PrivateKey, evm::PrivateKey as EvmKey,
/// };
///
/// let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
/// let key: EvmKey = generator.generate();
/// println!("Generated key: {}", key.to_string());
/// ```
pub struct ThreadRngFillBytes(rand::rngs::ThreadRng);

impl ThreadRngFillBytes {
    /// Creates a new `ThreadRngFillBytes` using `rand::thread_rng()`
    ///
    /// This initializes a thread-local cryptographically secure RNG.
    ///
    /// # Returns
    ///
    /// A new `ThreadRngFillBytes` instance ready for use
    ///
    /// # Examples
    ///
    /// ```rust
    /// use evm_account_generator::ThreadRngFillBytes;
    ///
    /// let rng = ThreadRngFillBytes::new();
    /// ```
    pub fn new() -> Self {
        Self(rand::thread_rng())
    }
}

impl FillBytes for ThreadRngFillBytes {
    /// Fills the destination buffer with cryptographically secure random bytes
    ///
    /// # Arguments
    ///
    /// * `dest` - A mutable byte slice to fill with random data
    ///
    /// # Examples
    ///
    /// ```rust
    /// use evm_account_generator::{FillBytes, ThreadRngFillBytes};
    ///
    /// let mut rng = ThreadRngFillBytes::new();
    /// let mut buffer = [0u8; 32];
    /// rng.fill_bytes(&mut buffer);
    /// // buffer now contains random bytes
    /// ```
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        RngCore::fill_bytes(&mut self.0, dest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_rng_fill_bytes() {
        let mut rng = ThreadRngFillBytes::new();
        let mut dest = [0u8; 32];
        rng.fill_bytes(&mut dest);
        assert_ne!(dest, [0u8; 32]);
    }
}

