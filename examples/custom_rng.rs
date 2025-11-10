//! Custom RNG implementation example

use evm_account_generator::{RandomBytes32, generate_private_key_with_rng, PrivateKey};

/// A simple deterministic RNG for demonstration purposes
/// WARNING: This is NOT cryptographically secure and should never be used in production!
struct DemoRng {
    seed: u64,
}

impl DemoRng {
    fn new(seed: u64) -> Self {
        Self { seed }
    }
}

impl RandomBytes32 for DemoRng {
    fn random_bytes_32(&mut self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        
        // Simple linear congruential generator (NOT secure!)
        for i in 0..32 {
            self.seed = self.seed.wrapping_mul(1103515245).wrapping_add(12345);
            bytes[i] = (self.seed >> 24) as u8;
        }
        
        bytes
    }
}

fn main() {
    println!("EVM Account Generator - Custom RNG Example");
    println!("==========================================");
    println!("WARNING: This uses a demo RNG that is NOT cryptographically secure!");
    println!();

    // Create a deterministic RNG with a fixed seed
    let mut demo_rng = DemoRng::new(12345);
    
    // Generate keys - these will be the same every time due to the fixed seed
    for i in 1..=3 {
        let private_key = generate_private_key_with_rng(&mut demo_rng);
        println!("Key {}: {}", i, private_key.to_hex());
    }
    
    println!();
    println!("Note: These keys are deterministic because we used a fixed seed.");
    println!("In production, always use cryptographically secure RNGs!");
}
