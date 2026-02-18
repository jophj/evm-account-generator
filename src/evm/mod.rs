//! EVM (Ethereum Virtual Machine) blockchain support
//!
//! This module provides private key generation and address derivation for
//! EVM-compatible blockchains including Ethereum, Polygon, BSC, and others.
//!
//! # Key Features
//!
//! - 32-byte ECDSA secp256k1 private keys
//! - secp256k1 curve validation
//! - Keccak-256 hash-based address derivation
//! - 20-byte Ethereum addresses
//!
//! # Examples
//!
//! ```rust
//! use evm_account_generator::{
//!     RngPrivateKeyGenerator, PrivateKeyGenerator, ThreadRngFillBytes,
//!     PrivateKey, evm::PrivateKey as EvmKey,
//! };
//!
//! let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
//! let key: EvmKey = generator.generate();
//!
//! println!("Private Key: {}", key.to_string());
//! println!("Address: {}", key.derive_address());
//! ```

mod private_key;
mod incremental_generator;

pub use private_key::{EvmPrivateKey as PrivateKey, EvmAddress as Address};
pub use incremental_generator::EvmIncrementalGenerator;