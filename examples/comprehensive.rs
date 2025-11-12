//! Comprehensive example demonstrating all features of the EVM account generator
//!
//! This example showcases:
//! - Creating keys from raw bytes
//! - Generating keys with ThreadRng
//! - Generating keys with DevRandomRng (Unix-only)
//! - Parsing keys from hex strings
//! - Error handling for invalid keys
//! - Address derivation

use evm_account_generator::{
    DevRandomRng, PrivateKeyGenerator, RngPrivateKeyGenerator, ThreadRngFillBytes,
    PrivateKey2, evm::evm_private_key::EVMPrivateKey2,
};

fn main() {
    println!("EVM Account Generator - Comprehensive Example");
    println!("==============================================\n");

    // === 1. Creating a key from raw bytes ===
    println!("1. Creating key from raw bytes:");
    let private_key = EVMPrivateKey2::new(&[0x12u8; 32]).expect("Valid key");
    println!("   Private Key: {}", private_key.to_string());
    println!("   Address:     {}", private_key.derive_address());
    println!();

    // === 2. Generating a key using ThreadRng ===
    println!("2. Generating key with ThreadRng (cryptographically secure):");
    let mut thread_rng_generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
    let private_key: EVMPrivateKey2 = thread_rng_generator.generate();
    println!("   Private Key: {}", private_key.to_string());
    println!("   Address:     {}", private_key.derive_address());
    println!();

    // === 3. Generating a key using DevRandomRng (Unix-only) ===
    println!("3. Generating key with DevRandomRng (system entropy):");
    println!("   Note: This may block until sufficient entropy is available");
    let dev_random_rng = DevRandomRng::new();
    let mut dev_random_generator = RngPrivateKeyGenerator::new(dev_random_rng);
    let private_key_dev: EVMPrivateKey2 = dev_random_generator.generate();
    println!("   Private Key: {}", private_key_dev.to_string());
    println!("   Address:     {}", private_key_dev.derive_address());
    println!();
    
    // === 4. Parsing keys from hex strings ===
    println!("4. Parsing key from hex string:");
    let hex_str = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    match EVMPrivateKey2::from_string(hex_str) {
        Some(key) => {
            println!("   ✓ Successfully parsed key");
            println!("   Private Key: {}", key.to_string());
            println!("   Address:     {}", key.derive_address());
        }
        None => println!("   ✗ Failed to parse key"),
    }
    println!();
    
    // === 5. Error handling demonstrations ===
    println!("5. Error handling examples:");
    
    // Test with too-short hex string
    print!("   Testing short key (0x123): ");
    match EVMPrivateKey2::from_string("0x123") {
        Some(key) => println!("✗ Unexpected success: {}", key.to_string()),
        None => println!("✓ Correctly rejected (invalid length)"),
    }
    
    // Test with invalid hex characters
    print!("   Testing invalid hex (with 'g'): ");
    match EVMPrivateKey2::from_string("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefg") {
        Some(key) => println!("✗ Unexpected success: {}", key.to_string()),
        None => println!("✓ Correctly rejected (invalid hex)"),
    }
    
    // Test with all zeros (invalid for secp256k1)
    print!("   Testing all zeros: ");
    let zeros = [0u8; 32];
    match EVMPrivateKey2::new(&zeros) {
        Some(key) => println!("✗ Unexpected success: {}", key.to_string()),
        None => println!("✓ Correctly rejected (all zeros invalid)"),
    }
    
    println!("\n✓ Comprehensive example completed successfully!");
}
