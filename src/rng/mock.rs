//! Mock RNG implementation for testing

use crate::traits::RandomBytes32;

/// Mock RNG for deterministic testing
pub struct MockRng {
    bytes: [u8; 32],
    call_count: usize,
}

impl MockRng {
    /// Creates a new MockRng with predetermined bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            call_count: 0,
        }
    }

    /// Returns the number of times random_bytes_32 has been called
    pub fn call_count(&self) -> usize {
        self.call_count
    }
}

impl RandomBytes32 for MockRng {
    fn random_bytes_32(&mut self) -> [u8; 32] {
        self.call_count += 1;
        // Return invalid bytes first (all zeros), then valid bytes
        if self.call_count == 1 {
            [0u8; 32] // Invalid: all zeros
        } else {
            self.bytes // Valid bytes
        }
    }
}
