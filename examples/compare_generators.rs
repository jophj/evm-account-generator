//! Example comparing RngPrivateKeyGenerator and SequentialPrivateKeyGenerator
//!
//! This demonstrates the difference between random and sequential key generation.

use evm_account_generator::{
    PrivateKey, PrivateKeyGenerator, RngPrivateKeyGenerator, 
    SequentialPrivateKeyGenerator, ThreadRngFillBytes,
    evm::PrivateKey as EvmKey,
};

fn main() {
    println!("=== Comparing Random vs Sequential Generators ===\n");

    // Random Generator Example
    println!("1. Random Generator (RngPrivateKeyGenerator):");
    println!("   - Generates cryptographically random keys");
    println!("   - Each key is independent");
    println!("   - Suitable for production use\n");
    
    let mut rng_generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
    
    println!("   Generated keys:");
    for i in 1..=3 {
        let key: EvmKey = rng_generator.generate();
        let last_bytes = &key.to_string()[58..];
        println!("   Key {}: ...{}", i, last_bytes);
    }

    // Sequential Generator Example
    println!("\n2. Sequential Generator (SequentialPrivateKeyGenerator):");
    println!("   - Generates deterministic sequence of keys");
    println!("   - Each key increments by 1 from the previous");
    println!("   - Useful for testing and development\n");
    
    let seed = EvmKey::from_string(
        "0x0000000000000000000000000000000000000000000000000000000000001000"
    ).expect("Valid seed");
    
    let mut seq_generator = SequentialPrivateKeyGenerator::new(seed);
    
    println!("   Generated keys (starting from 0x...1000):");
    for i in 1..=3 {
        let key: EvmKey = seq_generator.generate();
        let last_bytes = &key.to_string()[58..];
        println!("   Key {}: ...{}", i, last_bytes);
    }

    // Use Case: Testing address derivation
    println!("\n3. Use Case: Testing Address Derivation");
    println!("   Sequential generator allows predictable testing:\n");
    
    let test_seed = EvmKey::from_string(
        "0x0000000000000000000000000000000000000000000000000000000000000001"
    ).expect("Valid seed");
    
    let mut test_generator = SequentialPrivateKeyGenerator::new(test_seed);
    
    for i in 1..=3 {
        let key: EvmKey = test_generator.generate();
        let address = key.derive_address();
        println!("   Key 0x...{:04x} → Address: {}", i + 1, address);
    }

    println!("\n4. Performance Note:");
    println!("   - Random: Depends on RNG source (fast with thread_rng)");
    println!("   - Sequential: Very fast, just increments bytes");
    println!("   - Both skip invalid keys automatically\n");

    println!("=== Comparison Complete ===");
}

