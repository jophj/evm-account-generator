//! Core traits for EVM account generation
//!
//! This module contains all the fundamental traits used throughout the application
//! for private key operations, hex conversion, and address generation.

use crate::error::Result;
use crate::crypto::EVMPrivateKey;

/// Trait for creating private keys from hexadecimal strings
pub trait FromHex {
    /// Creates a private key from a hex string (with or without 0x prefix)
    /// 
    /// # Arguments
    /// 
    /// * `hex_str` - A hex string representing the private key
    /// 
    /// # Returns
    /// 
    /// Result containing the private key or an error
    fn from_hex(hex_str: &str) -> Result<EVMPrivateKey>;
}

/// Trait for creating private keys from byte arrays
pub trait FromBytes {
    /// Creates a private key from a 32-byte array
    /// 
    /// # Arguments
    /// 
    /// * `bytes` - A 32-byte array representing the private key
    /// 
    /// # Returns
    /// 
    /// Result containing the private key or an error
    fn from_bytes(bytes: [u8; 32]) -> Result<EVMPrivateKey>;
}

/// Core trait for private key operations
pub trait PrivateKey {
    /// Returns the private key as a byte array reference
    fn as_bytes(&self) -> &[u8; 32];
    
    /// Returns the private key as a Vec<u8>
    fn to_bytes(&self) -> Vec<u8>;
    
    /// Converts the private key to a hexadecimal string with 0x prefix
    fn to_hex(&self) -> String;
    
    /// Generates the Ethereum address for this private key
    fn get_address(&self) -> String;
}

/// Trait for converting types to hexadecimal representation
pub trait ToHex {
    /// Converts the type to a hexadecimal string with 0x prefix
    fn to_hex(&self) -> String;
}

/// Trait for types that can generate Ethereum addresses
pub trait GetAddress {
    /// Generates the Ethereum address for this private key
    fn get_address(&self) -> String;
}

/// Trait for generating 32 random bytes for private key generation
pub trait RandomBytes32 {
    /// Generates 32 random bytes
    fn random_bytes_32(&mut self) -> [u8; 32];
}

// Implement ToHex for common types
impl ToHex for [u8; 32] {
    fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self))
    }
}

impl ToHex for Vec<u8> {
    fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self))
    }
}

impl ToHex for &[u8] {
    fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self))
    }
}

// Implement RandomBytes32 for any type that implements RngCore
impl<T: rand::RngCore> RandomBytes32 for T {
    fn random_bytes_32(&mut self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.fill_bytes(&mut bytes);
        bytes
    }
}
