//! # EVM Account Generator Library
//! 
//! A type-safe, composable library for generating blockchain private keys.
//! Supports multiple blockchain networks including EVM (Ethereum) and Solana.
//!
//! ## Features
//!
//! - **Type-Safe Key Generation**: Compile-time guarantees for different blockchain types
//! - **Multi-Blockchain Support**: Generate keys for EVM (32 bytes) and Solana (64 bytes)
//! - **Flexible RNG Options**: Use thread-local RNG or system entropy (/dev/random)
//! - **Automatic Validation**: Built-in validation with automatic retry for invalid keys
//! - **Composable Architecture**: Trait-based design for easy extension
//!
//! ## Quick Start
//!
//! ### Generate an EVM Private Key
//!
//! ```rust
//! use evm_account_generator::{
//!     RngPrivateKeyGenerator, PrivateKeyGenerator, ThreadRngFillBytes,
//!     PrivateKey, evm::PrivateKey as EvmKey,
//! };
//!
//! // Create a generator using thread RNG
//! let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
//!
//! // Generate an EVM private key
//! let private_key: EvmKey = generator.generate();
//!
//! println!("Private Key: {}", private_key.to_string());
//! println!("Address: {}", private_key.derive_address());
//! ```
//!
//! ### Generate Keys for Multiple Blockchains
//!
//! ```rust
//! use evm_account_generator::{
//!     RngPrivateKeyGenerator, PrivateKeyGenerator, ThreadRngFillBytes,
//!     PrivateKey,
//!     evm::PrivateKey as EvmKey,
//!     solana::PrivateKey as SolanaKey,
//! };
//!
//! // One generator can create keys for different blockchains
//! let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
//!
//! let evm_key: EvmKey = generator.generate();         // 32 bytes
//! let solana_key: SolanaKey = generator.generate();   // 64 bytes
//! ```
//!
//! ## Architecture
//!
//! The library is built around three core traits:
//!
//! - [`PrivateKey`] - Defines the interface for blockchain private keys
//! - [`PrivateKeyGenerator`] - Defines how to generate keys of a specific type
//! - [`FillBytes`] - Defines how to fill buffers with random data
//!
//! This trait-based design provides compile-time type safety while remaining
//! flexible and extensible to new blockchain networks.
//!
//! ## Module Overview
//!
//! - [`private_key`] - Core trait definitions
//! - [`private_key_generator`] - Generic key generation implementation
//! - [`evm`] - Ethereum Virtual Machine key support
//! - [`solana`] - Solana blockchain key support
//! - [`rng`] - Random number generation implementations

pub mod rng;
pub mod private_key;
pub mod private_key_generator;
pub mod evm;
pub mod solana;

pub use private_key::PrivateKey;
pub use private_key_generator::{PrivateKeyGenerator, RngPrivateKeyGenerator, SequentialPrivateKeyGenerator, FillBytes};
pub use rng::{ThreadRngFillBytes, DevRandomRng};
