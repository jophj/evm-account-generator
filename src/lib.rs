//! EVM Account Generator Library
//! 
//! This library provides functionality for generating EVM (Ethereum Virtual Machine) private keys.
//! Uses cryptographically secure random number generation with a composable architecture.
//!
//! # Quick Start
//!
//! ```rust
//! use evm_account_generator::{generate_private_key_with_rng, ToHex};
//! use rand::thread_rng;
//!
//! let mut rng = thread_rng();
//! let private_key = generate_private_key_with_rng(&mut rng);
//! println!("Private key: {}", private_key.to_hex());
//! ```

pub mod crypto;
pub mod rng;
pub mod types;
pub mod error;

// Re-export the main types and functions for easier access
pub use crypto::{
    PrivateKey, 
    generate_private_key_with_rng,
    generate_private_key_bytes, 
    is_valid_private_key
};

pub use rng::{RandomBytes32, DevRandomRng};
pub use types::{ToHex, GetAddress};
pub use error::{EvmError, Result};
