//! Solana blockchain support
//!
//! This module provides private key generation and address derivation for
//! the Solana blockchain using Ed25519 signing keys (`ed25519-dalek`).
//!
//! # Key Features
//!
//! - 32-byte Ed25519 signing keys (seeds)
//! - Proper Ed25519 public key derivation via `ed25519-dalek`
//! - Base58-encoded addresses matching the standard Solana format
//! - Import/export compatible with wallets like Phantom (base58 64-byte keypair)
//!
//! # Examples
//!
//! ```rust
//! use evm_account_generator::{
//!     RngPrivateKeyGenerator, PrivateKeyGenerator, ThreadRngFillBytes,
//!     PrivateKey, solana::PrivateKey as SolanaKey,
//! };
//!
//! let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
//! let key: SolanaKey = generator.generate();
//!
//! println!("Private Key: {}", key.to_string());
//! println!("Address: {}", key.derive_address());
//! ```

mod private_key;

pub use private_key::{SolanaPrivateKey as PrivateKey, SolanaAddress as Address};
