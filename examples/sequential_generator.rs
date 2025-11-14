//! Example demonstrating the SequentialPrivateKeyGenerator
//!
//! This generator produces deterministic sequences of private keys by starting
//! from a seed and incrementing by 1 for each new key.

use evm_account_generator::{
    PrivateKey, PrivateKeyGenerator, SequentialPrivateKeyGenerator,
    evm::PrivateKey as EvmKey,
    solana::PrivateKey as SolanaKey,
};

fn main() {
    println!("=== Sequential Private Key Generator Demo ===\n");

    // Example 1: Generate sequential EVM keys
    println!("1. Generating sequential EVM keys:");
    println!("   Starting from seed: 0x...0001");
    
    let evm_seed = EvmKey::from_string(
        "0x0000000000000000000000000000000000000000000000000000000000000001"
    ).expect("Valid seed");
    
    let mut evm_generator = SequentialPrivateKeyGenerator::new(evm_seed);
    
    for i in 1..=5 {
        let key: EvmKey = evm_generator.generate();
        let address = key.derive_address();
        println!("   Key {}: {}", i, key.to_string());
        println!("      Address: {}", address);
    }

    // Example 2: Generate sequential Solana keys
    println!("\n2. Generating sequential Solana keys:");
    println!("   Starting from seed: 0x...0100");
    
    let sol_seed_hex = format!("0x{}0100", "00".repeat(62));
    let sol_seed = SolanaKey::from_string(&sol_seed_hex).expect("Valid seed");
    
    let mut sol_generator = SequentialPrivateKeyGenerator::new(sol_seed);
    
    for i in 1..=3 {
        let key: SolanaKey = sol_generator.generate();
        let address = key.derive_address();
        println!("   Key {}: {}...", i, &key.to_string()[..50]);
        println!("      Address: {}", address);
    }

    // Example 3: Demonstrating carry propagation
    println!("\n3. Demonstrating byte carry propagation:");
    println!("   Starting from seed: 0x...00FE (254)");
    
    let carry_seed = EvmKey::from_string(
        "0x00000000000000000000000000000000000000000000000000000000000000FE"
    ).expect("Valid seed");
    
    let mut carry_generator = SequentialPrivateKeyGenerator::new(carry_seed);
    
    for i in 1..=3 {
        let key: EvmKey = carry_generator.generate();
        let last_bytes = &key.to_string()[58..]; // Last 4 hex chars (2 bytes)
        println!("   Key {}: ...{}", i, last_bytes);
    }

    // Example 4: Using a custom seed
    println!("\n4. Using a custom seed:");
    println!("   Starting from seed: 0x...CAFE");
    
    let custom_seed = EvmKey::from_string(
        "0x000000000000000000000000000000000000000000000000000000000000CAFE"
    ).expect("Valid seed");
    
    let mut custom_generator = SequentialPrivateKeyGenerator::new(custom_seed);
    
    for i in 1..=3 {
        let key: EvmKey = custom_generator.generate();
        let address = key.derive_address();
        let last_bytes = &key.to_string()[58..];
        println!("   Key {}: ...{}", i, last_bytes);
        println!("      Address: {}", address);
    }

    println!("\n=== Demo Complete ===");
}

