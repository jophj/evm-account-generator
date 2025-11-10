//! Cryptographic operations for EVM account generation

pub mod private_key;
pub mod key_generation;
pub mod validation;

pub use private_key::EVMPrivateKey;
pub use key_generation::{generate_private_key_with_rng, generate_private_key_bytes};
pub use validation::is_valid_private_key;
