//! DevRandomRng usage example
//! 
//! This example demonstrates generating EVM private keys using /dev/random
//! for cryptographically secure entropy from the operating system.
//! 
//! Note: On Unix systems, /dev/random may block until sufficient entropy is available.

use evm_account_generator::{
    DevRandomRng, 
    RngPrivateKeyGenerator, 
    PrivateKeyGenerator,
    PrivateKey2,
    evm::evm_private_key::EVMPrivateKey2,
};

fn main() {
    println!("EVM Account Generator - DevRandomRng Example");
    println!("============================================\n");
    
    println!("Attempting to use /dev/random for key generation...");
    println!("Note: This may block until sufficient entropy is available\n");
    
    // Create a DevRandomRng instance
    let rng = DevRandomRng::new();
    
    // Create a generator with DevRandomRng
    let mut generator = RngPrivateKeyGenerator::new(rng);
    
    // Generate an EVM private key
    let private_key: EVMPrivateKey2 = generator.generate();
    
    // Display the results
    println!("✓ Successfully generated EVM private key");
    println!("  Private Key: {}", private_key.to_string());
    println!("  Address:     {}", private_key.derive_address());
    println!("\nKey generated using system entropy from /dev/random");
    
    // Generate a few more keys to demonstrate
    println!("\nGenerating 3 additional keys...\n");
    for i in 1..=3 {
        let key: EVMPrivateKey2 = generator.generate();
        println!("Key {}: {}", i, key.to_string());
        println!("Address {}: {}", i, key.derive_address());
        println!();
    }
    
    println!("All keys generated successfully using /dev/random entropy!");
}
