//! OpenSslRng usage example
//!
//! This example demonstrates generating EVM private keys using the system
//! OpenSSL library (`RAND_bytes`) as the entropy source.
//!
//! # When to Use OpenSslRng
//!
//! Use OpenSslRng when:
//! - Your environment mandates OpenSSL as the entropy source (e.g. FIPS or
//!   other compliance policies)
//! - You want randomness sourced through OpenSSL's DRBG specifically
//!
//! # When NOT to Use OpenSslRng
//!
//! Consider using ThreadRngFillBytes instead if:
//! - You have no OpenSSL-specific requirement — it is no more secure
//! - You want to avoid the system OpenSSL build/link dependency
//!
//! # Platform Support
//!
//! - ✅ Linux, macOS, BSD, Windows: Fully supported
//!
//! Requires the system OpenSSL development libraries at build time. This binds
//! to `libcrypto` via FFI — it does not shell out to the `openssl` binary.

use multichain_keygen::{
    OpenSslRng,
    RngPrivateKeyGenerator,
    PrivateKeyGenerator,
    PrivateKey,
    evm::PrivateKey as EvmKey,
};

fn main() {
    println!("Multichain Keygen - OpenSslRng Example");
    println!("============================================\n");

    println!("Using the system OpenSSL library (RAND_bytes) for key generation...\n");

    // Create an OpenSslRng instance (backed by OpenSSL's RAND_bytes).
    let rng = OpenSslRng::new();

    // Create a generator with OpenSslRng.
    let mut generator = RngPrivateKeyGenerator::new(rng);

    // Generate an EVM private key (reads 32 bytes from OpenSSL).
    println!("Generating first key...");
    let private_key: EvmKey = generator.generate();

    println!("✓ Successfully generated EVM private key");
    println!("  Private Key: {}", private_key.to_string());
    println!("  Address:     {}", private_key.derive_address());
    println!("  Entropy source: OpenSSL RAND_bytes\n");

    // Generate additional keys to demonstrate.
    println!("Generating 3 additional keys...\n");
    for i in 1..=3 {
        println!("Generating key {}...", i);
        let key: EvmKey = generator.generate();
        println!("  Key:     {}", key.to_string());
        println!("  Address: {}", key.derive_address());
        println!();
    }

    println!("✓ All keys generated successfully!");
    println!("\nEntropy Statistics:");
    println!("  Source: OpenSSL RAND_bytes");
    println!("  Bytes consumed: {} bytes (4 keys × 32 bytes)", 4 * 32);

    println!("\n⚠️  SECURITY NOTE:");
    println!("   OpenSslRng is cryptographically sound, but:");
    println!("   - ThreadRngFillBytes is also cryptographically secure");
    println!("   - Prefer OpenSslRng only when OpenSSL is a specific requirement");
}
