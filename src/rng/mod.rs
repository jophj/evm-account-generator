//! Random number generation module
//!
//! This module provides traits and implementations for generating random bytes
//! used in cryptographic key generation.

pub mod trait_def;
pub mod dev_random_legacy;
pub mod thread_rng;
pub mod dev_random;

#[cfg(test)]
pub mod mock;

pub use trait_def::RandomBytes32;
pub use dev_random_legacy::DevRandomRngLegacy;
pub use dev_random::DevRandomRng;
pub use thread_rng::ThreadRngFillBytes;