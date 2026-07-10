//! Bitcoin blockchain support (P2WPKH / native SegWit)
//!
//! This module provides private key generation and address derivation for
//! Bitcoin using the P2WPKH (Pay-to-Witness-Public-Key-Hash) address format,
//! also known as native SegWit.
//!
//! # Key Features
//!
//! - 32-byte ECDSA secp256k1 private keys
//! - WIF (Wallet Import Format) encoding for private keys
//! - P2WPKH address derivation: compressed pubkey → HASH160 → Bech32
//! - Bech32-encoded `bc1q…` addresses (BIP-173)
//!
//! # Examples
//!
//! ```rust
//! use multichain_keygen::{
//!     RngPrivateKeyGenerator, PrivateKeyGenerator, ThreadRngFillBytes,
//!     PrivateKey, bitcoin::PrivateKey as BitcoinKey,
//! };
//!
//! let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
//! let key: BitcoinKey = generator.generate();
//!
//! println!("Private Key (WIF): {}", key.to_string());
//! println!("Address (P2WPKH):  {}", key.derive_address());
//! ```

mod private_key;

pub use private_key::{BitcoinPrivateKey as PrivateKey, BitcoinAddress as Address};
