//! Core trait defining the interface for blockchain private keys
//!
//! This module provides the [`PrivateKey`] trait which defines a common interface
//! for private keys across different blockchain networks. The trait is designed to be
//! blockchain-agnostic, allowing the same generator and utilities to work with
//! keys from different networks.

/// Core trait defining the interface for blockchain private keys
///
/// This trait provides a common interface for private keys across different
/// blockchain networks. Each blockchain implementation (EVM, Solana, etc.)
/// implements this trait with its specific requirements.
///
/// # Type Parameters
///
/// The trait defines an associated type `Address` which represents the
/// blockchain-specific address format derived from the private key.
///
/// # Design
///
/// The trait uses `Option` for fallible operations rather than `Result` to keep
/// the interface simple. Invalid keys return `None`.
///
/// # Examples
///
/// ```rust
/// use evm_account_generator::{PrivateKey, evm::PrivateKey as EvmKey};
///
/// // Create an EVM private key from bytes
/// let bytes = [1u8; 32];
/// let key = EvmKey::new(&bytes).expect("Valid key");
///
/// // Get the address
/// let address = key.derive_address();
/// println!("Address: {}", address);
///
/// // Convert to hex string
/// println!("Private Key: {}", key.to_string());
/// ```
pub trait PrivateKey: Sized + Clone {
    /// The type of address this private key generates
    ///
    /// Each blockchain has its own address format (e.g., Ethereum uses 20-byte
    /// addresses, Solana uses 32-byte public keys as addresses).
    type Address: std::fmt::Display;

    /// Creates a new private key from raw bytes
    ///
    /// Validates the bytes according to blockchain-specific rules and returns
    /// a private key if valid.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice representing the private key (length must match `key_size()`)
    ///
    /// # Returns
    ///
    /// `Some(Self)` if the bytes represent a valid private key, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use evm_account_generator::{PrivateKey, evm::PrivateKey as EvmKey};
    ///
    /// let bytes = [1u8; 32];
    /// let key = EvmKey::new(&bytes).expect("Valid key");
    /// ```
    fn new(bytes: &[u8]) -> Option<Self>;

    /// Creates a new private key from a hexadecimal string
    ///
    /// Parses a hex string (with or without "0x" prefix) and creates a private key.
    ///
    /// # Arguments
    ///
    /// * `string` - A hexadecimal string representing the private key
    ///
    /// # Returns
    ///
    /// `Some(Self)` if the string is valid hex and represents a valid key, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use evm_account_generator::{PrivateKey, evm::PrivateKey as EvmKey};
    ///
    /// let key = EvmKey::from_string(
    ///     "0x0101010101010101010101010101010101010101010101010101010101010101"
    /// ).expect("Valid key");
    /// ```
    fn from_string(string: &str) -> Option<Self>;

    /// Validates if the byte slice is a valid private key for this blockchain
    ///
    /// This is a static method that checks if bytes could represent a valid key
    /// without creating the key structure.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The bytes to validate
    ///
    /// # Returns
    ///
    /// `true` if valid, `false` otherwise.
    fn is_valid(bytes: &[u8]) -> bool;

    /// Returns the expected size in bytes for this key type
    ///
    /// Different blockchains use different key sizes:
    /// - EVM (Ethereum): 32 bytes
    /// - Solana: 64 bytes
    ///
    /// # Returns
    ///
    /// The number of bytes required for this key type.
    fn key_size() -> usize;

    /// Returns the private key as a byte slice reference
    ///
    /// # Returns
    ///
    /// A byte slice containing the raw private key bytes.
    fn as_bytes(&self) -> &[u8];

    /// Converts the private key to a hexadecimal string
    ///
    /// The string includes the "0x" prefix.
    ///
    /// # Returns
    ///
    /// A hex-encoded string representation of the private key.
    fn to_string(&self) -> String;

    /// Derives the blockchain-specific address from this private key
    ///
    /// Each blockchain has its own address derivation method:
    /// - EVM: secp256k1 public key → Keccak-256 hash → last 20 bytes
    /// - Solana: Ed25519 public key (simplified in this implementation)
    ///
    /// # Returns
    ///
    /// The address derived from this private key.
    fn derive_address(&self) -> Self::Address;
}
