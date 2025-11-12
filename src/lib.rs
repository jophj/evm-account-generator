//! EVM Account Generator Library
//! 
//! This library provides functionality for generating EVM (Ethereum Virtual Machine) private keys.
//! Uses cryptographically secure random number generation with a composable architecture.
//!
//! # Quick Start
//!
//! ```rust
//! use evm_account_generator::{generate_private_key_with_rng};
//! use rand::thread_rng;
//!
//! let mut rng = thread_rng();
//! let private_key = generate_private_key_with_rng(&mut rng);
//! ```

pub mod crypto;
pub mod rng;
pub mod traits;
pub mod private_key;
pub mod private_key_generator;
pub mod error;
pub mod evm;
pub mod solana;

// Re-export the main types and functions for easier access
pub use crypto::{
    EVMPrivateKey, 
    generate_private_key_with_rng,
    generate_private_key_bytes, 
    is_valid_private_key
};

pub use private_key::PrivateKey2;
pub use private_key_generator::{PrivateKeyGenerator, RngPrivateKeyGenerator, FillBytes};
pub use rng::thread_rng::thread_rng::ThreadRngFillBytes;
pub use rng::DevRandomRng;
pub use traits::{ToHex, GetAddress, FromHex, FromBytes, RandomBytes32};
pub use error::{EvmError, Result};
