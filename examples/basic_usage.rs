//! Basic usage example for EVM account generator
//!
//! This example demonstrates the simplest way to generate an EVM private key
//! using the thread-based random number generator (cryptographically secure).
//!
//! This is the recommended approach for most applications as it:
//! - Is cross-platform (works on Windows, Linux, macOS, BSD)
//! - Is cryptographically secure (uses OS entropy)
//! - Doesn't block (unlike /dev/random)
//! - Is fast and efficient

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

    // Step 1: Create a cryptographically secure RNG
    // ThreadRngFillBytes wraps rand::thread_rng() which is:
    // - Cryptographically secure (ChaCha20 algorithm)
    // - Automatically seeded from the OS
    // - Thread-local (no contention in multi-threaded apps)
    let thread_rng = ThreadRngFillBytes::new();
    
    // Step 2: Create a key generator with the RNG
    // The generator can produce keys for any blockchain by specifying the type
    let mut generator = RngPrivateKeyGenerator::new(thread_rng);
    
    // Step 3: Generate an EVM private key
    // The type annotation tells Rust which blockchain's key to generate
    // The generator automatically:
    // - Generates 32 random bytes (EVM key size)
    // - Validates the key (non-zero, within secp256k1 curve order)
    // - Retries if invalid (extremely rare)
    let private_key: EVMPrivateKey2 = generator.generate();
    
    // Step 4: Display the results
    println!("Generated EVM private key:");
    println!("  Private Key: {}", private_key.to_string());
    println!("  Address:     {}", private_key.derive_address());
    
    // Additional information
    println!("\nKey details:");
    println!("  Key length:  {} bytes ({} hex characters)", 
             private_key.as_bytes().len(), 
             private_key.to_string().len() - 2); // -2 for "0x" prefix
    println!("  Format:      0x-prefixed hexadecimal");
    
    println!("\n✓ Successfully generated EVM account!");
    println!("\n⚠️  SECURITY WARNING:");
    println!("   Never share your private key with anyone!");
    println!("   Anyone with your private key has full control of your account.");
}
