//! Random number generation trait definition
//! 
//! Note: The RandomBytes32 trait is now defined in crate::traits
//! This module re-exports it for backward compatibility.

pub use crate::traits::RandomBytes32;

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
