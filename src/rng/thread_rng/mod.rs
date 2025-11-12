//! Thread-local random number generator
//!
//! Provides a wrapper around `rand::thread_rng()` for use with the key generator.

pub mod thread_rng;

pub use thread_rng::ThreadRngFillBytes;