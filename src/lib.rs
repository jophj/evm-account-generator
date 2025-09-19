//! EVM Account Generator Library
//! 
//! This library provides functionality for generating EVM (Ethereum Virtual Machine) private keys.
//! Uses cryptographically secure random number generation.

pub mod evm_key_generator;
pub mod rng;
pub mod dev_random_rng;

// Re-export the main types and functions for easier access
pub use evm_key_generator::{
    PrivateKey, 
    ToHex, 
    generate_private_key_with_rng,
    generate_private_key_bytes, 
    is_valid_private_key
};

pub use rng::RandomBytes32;
pub use dev_random_rng::DevRandomRng;
