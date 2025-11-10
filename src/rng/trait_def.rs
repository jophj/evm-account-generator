//! Random number generation trait definition

use rand::RngCore;

/// Trait for generating 32 random bytes for private key generation
pub trait RandomBytes32 {
    /// Generates 32 random bytes
    fn random_bytes_32(&mut self) -> [u8; 32];
}

/// Implementation of RandomBytes32 for any type that implements RngCore
impl<T: RngCore> RandomBytes32 for T {
    fn random_bytes_32(&mut self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.fill_bytes(&mut bytes);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_random_bytes32_trait() {
        // Test that the trait works with different RNG types
        let mut thread_rng = thread_rng();
        let bytes1 = thread_rng.random_bytes_32();
        let bytes2 = thread_rng.random_bytes_32();
        
        // Should generate different bytes each time
        assert_ne!(bytes1, bytes2);
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
    }

    #[test]
    fn test_random_bytes32_with_thread_rng() {
        let mut rng = thread_rng();
        let bytes = rng.random_bytes_32();
        
        assert_eq!(bytes.len(), 32);
    }
}
