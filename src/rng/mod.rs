//! Random number generation module
//!
//! This module provides traits and implementations for generating random bytes
//! used in cryptographic key generation.

pub mod thread_rng;
pub mod dev_random;

pub use dev_random::DevRandomRng;
pub use thread_rng::ThreadRngFillBytes;