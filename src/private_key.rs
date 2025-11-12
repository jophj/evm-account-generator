pub trait PrivateKey2: Sized + Clone {
    /// The type of address this private key generates
    type Address: std::fmt::Display;

    /// Creates a new private key from raw bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice representing the private key
    ///
    /// # Returns
    ///
    /// Result containing the private key or an error if invalid
    fn new(bytes: &[u8]) -> Option<Self>;

    /// Creates a new private key from a human readable string
    ///
    /// # Arguments
    ///
    /// * `string` - A string representing the private key
    ///
    /// # Returns
    ///
    /// Result containing the private key or an error if invalid
    fn from_string(string: &str) -> Option<Self>;

    /// Returns the private key as a byte slice reference
    fn as_bytes(&self) -> &[u8];

    /// Converts the private key to a hexadecimal string
    fn to_string(&self) -> String;

    /// Derives the address from this private key
    fn derive_address(&self) -> Self::Address;

    /// Validates if the byte slice is a valid private key for this blockchain
    fn is_valid(bytes: &[u8]) -> bool;

    /// Returns the expected size in bytes for this key type
    fn key_size() -> usize;
}