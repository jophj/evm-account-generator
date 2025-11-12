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
//!     PrivateKey2, evm::evm_private_key::EVMPrivateKey2,
//! };
//!
//! let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
//! let key: EVMPrivateKey2 = generator.generate();
//!
//! println!("Private Key: {}", key.to_string());
//! println!("Address: {}", key.derive_address());
//! ```

pub mod evm_private_key;