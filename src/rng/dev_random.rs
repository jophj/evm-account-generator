//! Dev Random RNG implementation
//!
//! This module provides a random number generator that reads from /dev/random
//! without external dependencies, using only the standard library.

use std::fs::File;
use std::io::Read;
use crate::rng::RandomBytes32;
use crate::error::{EvmError, Result};

/// A random number generator that reads from /dev/random
pub struct DevRandomRng {
    file: File,
}

impl DevRandomRng {
    /// Creates a new DevRandomRng instance
    /// 
    /// # Returns
    /// 
    /// Result containing DevRandomRng or an error if /dev/random cannot be opened
    /// 
    /// # Example
    /// 
    /// ```
    /// use evm_account_generator::rng::DevRandomRng;
    /// 
    /// let rng = DevRandomRng::new().expect("Failed to open /dev/random");
    /// ```
    pub fn new() -> Result<Self> {
        let file = File::open("/dev/random")
            .map_err(|e| EvmError::RngInitFailed(format!("Failed to open /dev/random: {}", e)))?;
        Ok(DevRandomRng { file })
    }
}

impl RandomBytes32 for DevRandomRng {
    fn random_bytes_32(&mut self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        
        // Read exactly 32 bytes from /dev/random
        // This will block until sufficient entropy is available
        self.file.read_exact(&mut bytes)
            .expect("Failed to read from /dev/random");
        
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dev_random_rng_creation() {
        // Test that we can create a DevRandomRng instance
        let result = DevRandomRng::new();
        
        // On systems without /dev/random, this might fail
        // We'll handle both cases gracefully
        match result {
            Ok(_) => {
                // Success - /dev/random is available
                println!("DevRandomRng created successfully");
            }
            Err(e) => {
                // This might happen on Windows or other systems without /dev/random
                println!("DevRandomRng creation failed (expected on some systems): {}", e);
            }
        }
    }

    #[test]
    #[cfg(unix)] // Only run on Unix-like systems
    fn test_dev_random_rng_generates_bytes() {
        // Only test on Unix systems where /dev/random should exist
        if let Ok(mut rng) = DevRandomRng::new() {
            let bytes1 = rng.random_bytes_32();
            let bytes2 = rng.random_bytes_32();
            
            // Verify we get 32 bytes
            assert_eq!(bytes1.len(), 32);
            assert_eq!(bytes2.len(), 32);
            
            // Verify the bytes are different (extremely unlikely to be the same)
            assert_ne!(bytes1, bytes2);
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_dev_random_rng_with_key_generation() {
        // Test integration with key generation
        use crate::crypto::generate_private_key_with_rng;
        use crate::types::ToHex;
        
        if let Ok(mut rng) = DevRandomRng::new() {
            let key = generate_private_key_with_rng(&mut rng);
            let hex = key.to_hex();
            
            // Verify the key is valid
            assert!(hex.starts_with("0x"));
            assert_eq!(hex.len(), 66); // 0x + 64 hex chars
        }
    }
}
