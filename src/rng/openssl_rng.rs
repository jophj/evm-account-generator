//! System entropy source using OpenSSL
//!
//! This module provides a random number generator backed by the system OpenSSL
//! library. It binds to `libcrypto` via the `openssl` crate's FFI and calls
//! `RAND_bytes` — it does **not** shell out to the `openssl` command-line binary.

use openssl::rand::rand_bytes;
use crate::FillBytes;

/// A random number generator backed by the system OpenSSL library.
///
/// This RNG fills buffers using OpenSSL's `RAND_bytes` (a cryptographically
/// secure DRBG that OpenSSL seeds from the operating system). It is suitable
/// for environments that require OpenSSL as the entropy source — for example,
/// FIPS or other compliance policies.
///
/// # Platform Support
///
/// - ✅ Linux: Fully supported
/// - ✅ macOS: Fully supported
/// - ✅ BSD: Fully supported
/// - ✅ Windows: Fully supported
///
/// Requires the system OpenSSL development libraries to be available at build time.
///
/// # Panics
///
/// Panics if OpenSSL's `RAND_bytes` fails to produce random bytes.
///
/// # Examples
///
/// ```rust,no_run
/// use multichain_keygen::{
///     OpenSslRng, RngPrivateKeyGenerator, PrivateKeyGenerator,
///     PrivateKey, evm::PrivateKey as EvmKey,
/// };
///
/// let rng = OpenSslRng::new();
/// let mut generator = RngPrivateKeyGenerator::new(rng);
/// let key: EvmKey = generator.generate();
/// ```
pub struct OpenSslRng;

impl OpenSslRng {
    /// Creates a new `OpenSslRng`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use multichain_keygen::OpenSslRng;
    ///
    /// let rng = OpenSslRng::new();
    /// ```
    pub fn new() -> Self {
        Self
    }
}

impl Default for OpenSslRng {
    fn default() -> Self {
        Self::new()
    }
}

impl FillBytes for OpenSslRng {
    /// Fills the destination buffer with random bytes from OpenSSL's `RAND_bytes`.
    ///
    /// # Arguments
    ///
    /// * `dest` - A mutable byte slice to fill with random data
    ///
    /// # Panics
    ///
    /// Panics if OpenSSL's `RAND_bytes` fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use multichain_keygen::{FillBytes, OpenSslRng};
    ///
    /// let mut rng = OpenSslRng::new();
    /// let mut buffer = [0u8; 32];
    /// rng.fill_bytes(&mut buffer);
    /// // buffer now contains random bytes from OpenSSL
    /// ```
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_bytes(dest).expect("OpenSSL RAND_bytes failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openssl_fill_bytes() {
        let mut rng = OpenSslRng::new();
        let mut dest = [0u8; 32];
        rng.fill_bytes(&mut dest);
        assert_ne!(dest, [0u8; 32]);
    }

    #[test]
    fn test_openssl_fill_bytes_differ() {
        let mut rng = OpenSslRng::new();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut a);
        rng.fill_bytes(&mut b);
        // Two independent draws should not collide.
        assert_ne!(a, b);
    }
}
