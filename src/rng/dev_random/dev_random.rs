//! System entropy source using /dev/random
//!
//! This module provides a random number generator that reads entropy directly
//! from the operating system's `/dev/random` device.

use std::{fs::File, io::Read};
use crate::FillBytes;

/// A random number generator that reads from `/dev/random`
///
/// This RNG provides high-quality entropy directly from the operating system's
/// kernel entropy pool. It's suitable for cryptographic applications requiring
/// the highest level of randomness.
///
/// # Platform Support
///
/// - ✅ Linux: Fully supported
/// - ✅ macOS: Fully supported
/// - ✅ BSD: Fully supported
/// - ❌ Windows: Not supported (will panic)
///
/// # Blocking Behavior
///
/// On Unix-like systems, `/dev/random` will block if insufficient entropy is
/// available in the kernel pool. This ensures maximum security but may cause
/// delays, especially during system boot or in low-entropy environments.
///
/// For non-blocking random numbers, consider using `ThreadRngFillBytes` instead.
///
/// # Panics
///
/// Panics if:
/// - `/dev/random` cannot be opened (e.g., on Windows or restricted environments)
/// - Reading from `/dev/random` fails
///
/// # Examples
///
/// ```rust,no_run
/// use evm_account_generator::{
///     DevRandomRng, RngPrivateKeyGenerator, PrivateKeyGenerator,
///     PrivateKey2, evm::evm_private_key::EVMPrivateKey2,
/// };
///
/// let rng = DevRandomRng::new();
/// let mut generator = RngPrivateKeyGenerator::new(rng);
/// let key: EVMPrivateKey2 = generator.generate();
/// ```
pub struct DevRandomRng(File);

impl DevRandomRng {
    /// Creates a new `DevRandomRng` by opening `/dev/random`
    ///
    /// # Panics
    ///
    /// Panics if `/dev/random` cannot be opened. This typically happens on:
    /// - Windows (no `/dev/random` exists)
    /// - Restricted environments where device access is blocked
    /// - Systems without a proper entropy source
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use evm_account_generator::DevRandomRng;
    ///
    /// // This works on Unix-like systems
    /// let rng = DevRandomRng::new();
    /// ```
    ///
    /// # Notes
    ///
    /// Consider using `ThreadRngFillBytes` if you need cross-platform support
    /// or want to avoid potential blocking behavior.
    pub fn new() -> Self {
        let file = File::open("/dev/random")
            .expect("Failed to open /dev/random. This RNG is only available on Unix-like systems.");
        Self(file)
    }
}

impl FillBytes for DevRandomRng {
    /// Fills the destination buffer with random bytes from `/dev/random`
    ///
    /// This method will block until sufficient entropy is available from the
    /// kernel's entropy pool.
    ///
    /// # Arguments
    ///
    /// * `dest` - A mutable byte slice to fill with random data
    ///
    /// # Panics
    ///
    /// Panics if reading from `/dev/random` fails for any reason (e.g., I/O error).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use evm_account_generator::{FillBytes, DevRandomRng};
    ///
    /// let mut rng = DevRandomRng::new();
    /// let mut buffer = [0u8; 32];
    /// rng.fill_bytes(&mut buffer);
    /// // buffer now contains high-quality random bytes from the OS
    /// ```
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