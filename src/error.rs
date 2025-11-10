/// Error types for EVM account generation
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum EvmError {
    /// Invalid private key format
    InvalidPrivateKey(String),
    /// Invalid hex encoding
    InvalidHex(String),
    /// RNG initialization failed
    RngInitFailed(String),
    /// IO error (for DevRandomRng)
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

impl From<hex::FromHexError> for EvmError {
    fn from(err: hex::FromHexError) -> Self {
        EvmError::InvalidHex(err.to_string())
    }
}

impl From<std::io::Error> for EvmError {
    fn from(err: std::io::Error) -> Self {
        EvmError::IoError(err.to_string())
    }
}

/// Result type for EVM operations
pub type Result<T> = std::result::Result<T, EvmError>;
