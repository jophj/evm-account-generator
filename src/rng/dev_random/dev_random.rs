use std::{fs::File, io::Read};

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
pub struct DevRandomRng(File);

impl DevRandomRng {
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
        let file = File::open("/dev/random");
        if file.is_err() {
            panic!("Failed to open /dev/random");
        }

        Self(file.unwrap())
    }
}

impl FillBytes for DevRandomRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read_exact(dest)
            .expect("Failed to read from /dev/random");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_rng_fill_bytes() {
        let mut rng = DevRandomRng::new();
        let mut dest = [0u8; 32];
        rng.fill_bytes(&mut dest);
        assert_ne!(dest, [0u8; 32]);
    }
}