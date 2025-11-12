//! Error types for blockchain key generation
//!
//! This module defines error types used throughout the library and provides
//! convenient conversions from common error types.

use std::fmt;

/// Error types for blockchain key generation operations
///
/// This enum represents all possible errors that can occur during
/// key generation, parsing, and validation operations.
#[derive(Debug, Clone, PartialEq)]
pub enum EvmError {
    /// Invalid private key format or value
    ///
    /// Returned when a private key is outside the valid range,
    /// is all zeros, or doesn't meet blockchain-specific requirements.
    InvalidPrivateKey(String),
    
    /// Invalid hexadecimal encoding
    ///
    /// Returned when parsing a hex string that contains non-hex characters
    /// or has an incorrect length.
    InvalidHex(String),
    
    /// Random number generator initialization failed
    ///
    /// Returned when the RNG cannot be initialized (e.g., /dev/random
    /// is not available on the system).
    RngInitFailed(String),
    
    /// I/O error occurred
    ///
    /// Returned when reading from system resources (e.g., /dev/random) fails.
    IoError(String),
}

impl fmt::Display for EvmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvmError::InvalidPrivateKey(msg) => write!(f, "Invalid private key: {}", msg),
            EvmError::InvalidHex(msg) => write!(f, "Invalid hex: {}", msg),
            EvmError::RngInitFailed(msg) => write!(f, "RNG initialization failed: {}", msg),
            EvmError::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for EvmError {}

/// Converts hex decoding errors into EvmError
impl From<hex::FromHexError> for EvmError {
    fn from(err: hex::FromHexError) -> Self {
        EvmError::InvalidHex(err.to_string())
    }
}

/// Converts I/O errors into EvmError
impl From<std::io::Error> for EvmError {
    fn from(err: std::io::Error) -> Self {
        EvmError::IoError(err.to_string())
    }
}

/// Convenience Result type for blockchain operations
///
/// Uses [`EvmError`] as the error type for all operations in this library.
pub type Result<T> = std::result::Result<T, EvmError>;
