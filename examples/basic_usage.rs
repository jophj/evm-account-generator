//! Basic usage example for EVM account generator
//!
//! This example demonstrates the simplest way to generate an EVM private key
//! using the default thread-based random number generator.

use evm_account_generator::{
    RngPrivateKeyGenerator,
    PrivateKeyGenerator,
    ThreadRngFillBytes,
    PrivateKey2,
    evm::evm_private_key::EVMPrivateKey2,
};

fn main() {
    println!("EVM Account Generator - Basic Usage Example");
    println!("==========================================\n");

    // Create a generator using the thread RNG
    let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
    
    // Generate a private key
    let private_key: EVMPrivateKey2 = generator.generate();
    
    // Display the results
    println!("Generated private key: {}", private_key.to_string());
    println!("Corresponding address: {}", private_key.derive_address());
    
    println!("\n✓ Successfully generated EVM account!");
}
