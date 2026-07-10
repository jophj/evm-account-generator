//! Random number generation module
//!
//! This module provides traits and implementations for generating random bytes
//! used in cryptographic key generation.

mod thread_rng;
mod dev_random;
mod openssl_rng;

pub use dev_random::DevRandomRng;
pub use openssl_rng::OpenSslRng;
pub use thread_rng::ThreadRngFillBytes;
