//! Optimized EVM key generator using incremental EC point addition
//!
//! Standard key generation requires a full secp256k1 scalar multiplication
//! per key (~256 EC doublings + additions). This generator instead performs
//! one initial scalar multiplication and then uses cheap EC point additions
//! for subsequent keys, achieving ~5x throughput improvement.
//!
//! # How it works
//!
//! Given a starting secret key `k` with public key `P = k * G`:
//! - The next key is `k+1` with public key `P + G` (a single point addition)
//! - Point addition is ~100x cheaper than full scalar multiplication
//!
//! # Examples
//!
//! ```
//! use evm_account_generator::{PrivateKey, evm::EvmIncrementalGenerator};
//!
//! let mut gen = EvmIncrementalGenerator::new();
//! let (key, address) = gen.generate();
//! println!("Key: {}", key.to_string());
//! println!("Address: {}", address);
//! ```

use super::private_key::{EvmAddress, EvmPrivateKey};
use crate::private_key_generator::FillBytes;
use crate::rng::ThreadRngFillBytes;
use crate::PrivateKey;
use keccak_asm::{Digest, Keccak256};
use secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey};
use std::sync::LazyLock;

static SECP: LazyLock<Secp256k1<All>> = LazyLock::new(Secp256k1::new);

static G_POINT: LazyLock<PublicKey> = LazyLock::new(|| {
    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    let sk = SecretKey::from_slice(&bytes).unwrap();
    PublicKey::from_secret_key(&SECP, &sk)
});

static ONE_SCALAR: LazyLock<Scalar> = LazyLock::new(|| {
    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    Scalar::from_be_bytes(bytes).unwrap()
});

/// Optimized EVM key-address pair generator.
///
/// Uses incremental secp256k1 point addition instead of full scalar
/// multiplication for each key, making it ideal for high-throughput
/// use cases like vanity address search.
pub struct EvmIncrementalGenerator {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl EvmIncrementalGenerator {
    /// Creates a new generator seeded from the thread-local CSPRNG.
    pub fn new() -> Self {
        let mut rng = ThreadRngFillBytes::new();
        Self::from_rng(&mut rng)
    }

    /// Creates a new generator seeded from the provided RNG.
    pub fn from_rng(rng: &mut impl FillBytes) -> Self {
        // One expensive EC scalar multiplication for the random starting point
        let (secret_key, public_key) = loop {
            let mut key_bytes = [0u8; 32];
            rng.fill_bytes(&mut key_bytes);
            if let Ok(sk) = SecretKey::from_slice(&key_bytes) {
                let pk = PublicKey::from_secret_key(&SECP, &sk);
                break (sk, pk);
            }
        };

        Self {
            secret_key,
            public_key,
        }
    }

    /// Generates the next `(EvmPrivateKey, EvmAddress)` pair and advances
    /// the internal state using a cheap EC point addition.
    pub fn generate(&mut self) -> (EvmPrivateKey, EvmAddress) {
        let pk_bytes = self.public_key.serialize_uncompressed();
        let hash = Keccak256::digest(&pk_bytes[1..]);
        let addr_bytes: [u8; 20] = hash[12..32].try_into().unwrap();

        let key = EvmPrivateKey::new(&self.secret_key.secret_bytes())
            .expect("SecretKey always produces a valid EvmPrivateKey");
        let address = EvmAddress::new(addr_bytes);

        self.secret_key = self.secret_key.add_tweak(&ONE_SCALAR)
            .expect("secret key wrapped to zero");
        self.public_key = self.public_key.combine(&G_POINT)
            .expect("point addition yielded infinity");

        (key, address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_produces_valid_keys_and_addresses() {
        let mut gen = EvmIncrementalGenerator::new();
        for _ in 0..10 {
            let (key, address) = gen.generate();
            assert!(EvmPrivateKey::is_valid(key.as_bytes()));
            let addr_str = address.to_string();
            assert!(addr_str.starts_with("0x"));
            assert_eq!(addr_str.len(), 42);
        }
    }

    #[test]
    fn test_matches_standard_derivation() {
        let mut gen = EvmIncrementalGenerator::new();
        for _ in 0..10 {
            let (key, address) = gen.generate();
            let standard_address = key.derive_address();
            assert_eq!(address, standard_address);
        }
    }

    #[test]
    fn test_produces_sequential_unique_keys() {
        let mut gen = EvmIncrementalGenerator::new();
        let pairs: Vec<_> = (0..5).map(|_| gen.generate()).collect();

        for i in 0..pairs.len() {
            for j in (i + 1)..pairs.len() {
                assert_ne!(pairs[i].0.to_string(), pairs[j].0.to_string());
                assert_ne!(pairs[i].1.to_string(), pairs[j].1.to_string());
            }
        }
    }
}
