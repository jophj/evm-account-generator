use rand::RngCore;

use crate::FillBytes;

/// A wrapper around `rand::rngs::ThreadRng` that implements `FillBytes`
///
/// This provides a clean way to use `thread_rng()` with the `PrivateKeyGenerator`
/// without polluting all `RngCore` types with the `FillBytes` trait.
///
/// # Examples
///
/// ```
/// use evm_account_generator::{RngPrivateKeyGenerator, PrivateKeyGenerator, ThreadRngFillBytes};
/// use evm_account_generator::evm::evm_private_key::EVMPrivateKey2;
///
/// let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
/// let key: EVMPrivateKey2 = generator.generate();
/// ```
pub struct ThreadRngFillBytes(rand::rngs::ThreadRng);

impl ThreadRngFillBytes {
    /// Creates a new `ThreadRngFillBytes` using `rand::thread_rng()`
    ///
    /// # Examples
    ///
    /// ```
    /// use evm_account_generator::ThreadRngFillBytes;
    ///
    /// let rng = ThreadRngFillBytes::new();
    /// ```
    pub fn new() -> Self {
        Self(rand::thread_rng())
    }
}

impl FillBytes for ThreadRngFillBytes {
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