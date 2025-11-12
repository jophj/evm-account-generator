//! Solana blockchain support
//!
//! This module provides private key generation and address derivation for
//! the Solana blockchain using Ed25519 keypairs.
//!
//! # Key Features
//!
//! - 64-byte Ed25519 keypairs (seed + derived key)
//! - Simplified validation (non-zero check)
//! - Base58-style address formatting (simplified)
//!
//! # Note
//!
//! This is a simplified implementation for demonstration purposes.
//! Production Solana applications should use the official `solana-sdk` crate.
//!
//! # Examples
//!
//! ```rust
//! use evm_account_generator::{
//!     RngPrivateKeyGenerator, PrivateKeyGenerator, ThreadRngFillBytes,
//!     PrivateKey2, solana::solana_private_key::SolanaPrivateKey2,
//! };
//!
//! let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
//! let key: SolanaPrivateKey2 = generator.generate();
//!
//! println!("Private Key: {}", key.to_string());
//! println!("Address: {}", key.derive_address());
//! ```

pub mod solana_private_key;
pub use solana_private_key::SolanaPrivateKey2;

