//! Example demonstrating generic PrivateKeyGenerator with multiple blockchain types
//! 
//! This example shows how to use the same RngPrivateKeyGenerator to generate
//! private keys for different blockchain networks (EVM and Solana).

use evm_account_generator::{
    PrivateKeyGenerator, RngPrivateKeyGenerator, PrivateKey2,
    evm::evm_private_key::EVMPrivateKey2,
    solana::solana_private_key::SolanaPrivateKey2,
};
use rand::thread_rng;

fn main() {
    // Create a single RNG-based generator
    let mut generator = RngPrivateKeyGenerator::new(thread_rng());
    
    println!("=== Generic Private Key Generator Demo ===\n");
    
    // Generate EVM private keys
    println!("--- EVM (Ethereum) Keys ---");
    for i in 1..=3 {
        let key: EVMPrivateKey2 = generator.generate();
        let address = key.derive_address();
        println!("EVM Key #{}", i);
        println!("  Private Key: {}", key.to_string());
        println!("  Address:     {}", address);
        println!();
    }
    
    // Generate Solana private keys using the same generator
    println!("--- Solana Keys ---");
    for i in 1..=3 {
        let key: SolanaPrivateKey2 = generator.generate();
        let address = key.derive_address();
        println!("Solana Key #{}", i);
        println!("  Private Key: {}", key.to_string());
        println!("  Address:     {}", address);
        println!();
    }
    
    // Demonstrate that the trait is generic and type-safe
    demonstrate_generic_function(&mut generator);
}

/// Generic function that works with any PrivateKey2 implementation
fn demonstrate_generic_function<R: rand::RngCore>(
    generator: &mut RngPrivateKeyGenerator<R>
) {
    println!("--- Generic Function Demo ---");
    
    // Can generate any type that implements PrivateKey2
    let evm_key: EVMPrivateKey2 = generator.generate();
    println!("Generated EVM key (32 bytes): {}", evm_key.to_string());
    
    let solana_key: SolanaPrivateKey2 = generator.generate();
    println!("Generated Solana key (64 bytes): {}", solana_key.to_string());
    
    println!("\nThe same generator can create keys for any blockchain with different sizes!");
}

