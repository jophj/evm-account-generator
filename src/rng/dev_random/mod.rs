//! System entropy source using /dev/random
//!
//! Provides access to the operating system's high-quality entropy source.
//! Only available on Unix-like systems (Linux, macOS, BSD).

pub mod dev_random;

pub use dev_random::DevRandomRng;