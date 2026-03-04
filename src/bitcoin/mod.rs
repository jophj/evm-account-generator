//! Bitcoin blockchain support
//!
//! Provides P2WPKH (native SegWit/Bech32) address derivation and WIF private key
//! encoding for Bitcoin mainnet.

mod private_key;

pub use private_key::{BitcoinPrivateKey as PrivateKey, BitcoinAddress as Address};
