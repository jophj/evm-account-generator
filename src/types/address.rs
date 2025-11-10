//! Ethereum address generation trait

/// Trait for types that can generate Ethereum addresses
pub trait GetAddress {
    /// Generates the Ethereum address for this private key
    fn get_address(&self) -> String;
}
