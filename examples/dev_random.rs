//! DevRandomRng usage example
//! 
//! This example demonstrates generating EVM private keys using `/dev/random`
//! for maximum-security entropy directly from the operating system kernel.
//! 
//! # When to Use DevRandomRng
//! 
//! Use DevRandomRng when:
//! - You need the highest possible entropy quality
//! - You're generating keys for high-value accounts
//! - You're in a security-critical environment
//! - You can tolerate potential blocking behavior
//! 
//! # When NOT to Use DevRandomRng
//! 
//! Consider using ThreadRngFillBytes instead if:
//! - You need cross-platform support (Windows doesn't have /dev/random)
//! - You can't tolerate blocking behavior
//! - You're generating many keys quickly
//! - You're on a low-entropy system (embedded, VMs, containers)
//! 
//! # Platform Support
//! 
//! - ✅ Linux, macOS, BSD: Fully supported
//! - ❌ Windows: Will panic (no /dev/random)
//! 
//! # Blocking Behavior
//! 
//! On Unix systems, /dev/random may block until sufficient entropy is
//! available in the kernel pool. This is most likely to occur:
//! - During system boot
//! - On systems with limited entropy sources
//! - In virtualized/containerized environments
//! - On embedded devices without hardware RNG

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
    
    // Display platform information
    #[cfg(target_family = "unix")]
    println!("Platform: Unix-like system detected");
    #[cfg(not(target_family = "unix"))]
    println!("Platform: Non-Unix system (this example will fail)");
    
    println!("Attempting to use /dev/random for key generation...");
    println!("Note: This may block until sufficient entropy is available\n");
    
    // Create a DevRandomRng instance
    // This opens /dev/random and will panic if it fails
    // (e.g., on Windows or in restricted environments)
    let rng = DevRandomRng::new();
    println!("✓ Successfully opened /dev/random\n");
    
    // Create a generator with DevRandomRng
    let mut generator = RngPrivateKeyGenerator::new(rng);
    
    // Generate an EVM private key
    // This reads 32 bytes from /dev/random
    println!("Generating first key (may block if entropy is low)...");
    let private_key: EVMPrivateKey2 = generator.generate();
    
    // Display the results
    println!("✓ Successfully generated EVM private key");
    println!("  Private Key: {}", private_key.to_string());
    println!("  Address:     {}", private_key.derive_address());
    println!("  Entropy source: /dev/random (kernel entropy pool)\n");
    
    // Generate additional keys to demonstrate
    println!("Generating 3 additional keys...\n");
    for i in 1..=3 {
        println!("Generating key {}...", i);
        let key: EVMPrivateKey2 = generator.generate();
        println!("  Key:     {}", key.to_string());
        println!("  Address: {}", key.derive_address());
        println!();
    }
    
    println!("✓ All keys generated successfully!");
    println!("\nEntropy Statistics:");
    println!("  Source: /dev/random");
    println!("  Quality: Maximum (kernel-level entropy)");
    println!("  Bytes consumed: {} bytes (4 keys × 32 bytes)", 4 * 32);
    
    println!("\n⚠️  SECURITY NOTE:");
    println!("   /dev/random provides the highest quality entropy, but:");
    println!("   - ThreadRngFillBytes is also cryptographically secure");
    println!("   - For most applications, ThreadRngFillBytes is recommended");
    println!("   - Use /dev/random only when maximum security is required");
}
