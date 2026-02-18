//! Multi-blockchain key generation example
//! 
//! This example demonstrates the power of the library's generic architecture.
//! It shows how a single RNG and generator can produce keys for different
//! blockchain networks with different key sizes and validation rules.
//!
//! # Key Concepts Demonstrated
//!
//! - **Generic Key Generation**: One generator works for all blockchains
//! - **Type Safety**: Rust's type system ensures correctness at compile-time
//! - **Automatic Sizing**: The generator knows each blockchain's key size
//! - **Automatic Validation**: Each blockchain's validation rules are applied
//! - **Code Reusability**: Generic functions work with any blockchain
//!
//! # Blockchains Demonstrated
//!
//! - **EVM (Ethereum)**: 32-byte ECDSA secp256k1 keys
//! - **Solana**: 64-byte Ed25519 keypairs

use evm_account_generator::{
    PrivateKey, PrivateKeyGenerator, RngPrivateKeyGenerator, FillBytes, ThreadRngFillBytes,
    evm::PrivateKey as EvmKey,
    solana::PrivateKey as SolanaKey,
};

fn main() {
    println!("=== Multi-Blockchain Private Key Generator Demo ===\n");
    
    // Create a single RNG-based generator
    // This generator can produce keys for ANY blockchain that implements PrivateKey2
    let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
    
    println!("Using a single generator to create keys for multiple blockchains...\n");

    // === Generate EVM (Ethereum) Keys ===
    println!("--- EVM (Ethereum) Keys ---");
    println!("Key size: 32 bytes (256 bits)");
    println!("Algorithm: ECDSA secp256k1");
    println!("Compatible with: Ethereum, Polygon, BSC, Avalanche, etc.\n");
    
    for i in 1..=3 {
        // The type annotation tells the generator to create an EVM key
        let key: EvmKey = generator.generate();
        let address = key.derive_address();
        
        println!("EVM Key #{}", i);
        println!("  Private Key: {}", key.to_string());
        println!("  Address:     {}", address);
        println!("  Bytes:       {} bytes", key.as_bytes().len());
        println!();
    }
    
    // === Generate Solana Keys ===
    println!("--- Solana Keys ---");
    println!("Key size: 32 bytes (256 bits)");
    println!("Algorithm: Ed25519");
    println!("Compatible with: Solana\n");
    
    for i in 1..=3 {
        // Same generator, different type annotation = different blockchain
        let key: SolanaKey = generator.generate();
        let address = key.derive_address();
        
        println!("Solana Key #{}", i);
        println!("  Private Key: {}", key.to_string());
        println!("  Address:     {}", address);
        println!("  Bytes:       {} bytes", key.as_bytes().len());
        println!();
    }
    
    // === Demonstrate Generic Programming ===
    demonstrate_generic_function(&mut generator);
    
    // === Demonstrate Key Size Detection ===
    println!("\n--- Key Size Information ---");
    println!("EVM key size:    {} bytes", EvmKey::key_size());
    println!("Solana key size: {} bytes", SolanaKey::key_size());
    
    println!("\n✓ Multi-blockchain key generation completed successfully!");
    println!("\n💡 Key Insight:");
    println!("   The same generator and RNG work seamlessly with different");
    println!("   blockchain types thanks to Rust's trait-based generic programming!");
}

/// Generic function that works with any blockchain's private key
///
/// This demonstrates how you can write blockchain-agnostic code that works
/// with any type implementing PrivateKey.
///
/// # Type Parameters
///
/// - `R`: The RNG type (must implement FillBytes)
fn demonstrate_generic_function<R: FillBytes>(
    generator: &mut RngPrivateKeyGenerator<R>
) {
    println!("--- Generic Function Demo ---");
    println!("This function works with ANY blockchain that implements PrivateKey\n");
    
    // Generate keys of different types using type annotations
    let evm_key: EvmKey = generator.generate();
    println!("Generated EVM key:");
    println!("  Size: {} bytes", evm_key.as_bytes().len());
    println!("  Key:  {}", evm_key.to_string());
    println!();
    
    let solana_key: SolanaKey = generator.generate();
    println!("Generated Solana key:");
    println!("  Size: {} bytes", solana_key.as_bytes().len());
    println!("  Key:  {}", solana_key.to_string());
    println!();
    
    println!("The same generator function created keys of different sizes!");
    println!("This is the power of generic programming in Rust.");
}

