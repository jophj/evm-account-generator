//! Hexadecimal conversion trait and implementations

/// Trait for converting types to hexadecimal representation
pub trait ToHex {
    /// Converts the type to a hexadecimal string with 0x prefix
    fn to_hex(&self) -> String;
}

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
