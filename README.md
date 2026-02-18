# EVM Account Generator

A Rust library and CLI for generating cryptographically secure blockchain private keys with a composable, type-safe architecture. Supports EVM (Ethereum) and Solana.

## Features

- **Type-Safe Key Generation**: Compile-time guarantees for different blockchain key types
- **Multi-Blockchain Support**: Generate keys for EVM and Solana with the same API
- **Flexible RNG Options**: Use thread-local RNG or system entropy (`/dev/random`)
- **Automatic Validation**: Built-in validation with automatic retry for invalid keys
- **Composable Architecture**: Trait-based design for easy extension to new blockchains
- **CLI with Vanity Search**: Generate, derive, and search for vanity addresses

## CLI Usage

```bash
cargo build --release
```

### Generate a private key

```bash
# EVM (default)
evm-account-generator generate

# Solana
evm-account-generator generate --type solana

# With /dev/random entropy (Unix only)
evm-account-generator generate --type evm --rng dev-random

# Quiet mode (key only, no extra output)
evm-account-generator generate --type solana -q
```

### Derive an address from a private key

```bash
# EVM (hex)
evm-account-generator derive 0x1234...abcdef

# Solana (base58 keypair)
evm-account-generator derive --type solana <base58-keypair>

# Read from stdin
echo "0x1234...abcdef" | evm-account-generator derive
```

### Vanity address search

```bash
# EVM: hex prefix/suffix
evm-account-generator vanity --prefix dead
evm-account-generator vanity --suffix beef
evm-account-generator vanity --prefix dead --suffix beef --threads 8

# Solana: base58 prefix/suffix
evm-account-generator vanity --type solana --prefix jop
evm-account-generator vanity --type solana --suffix xyz
```

## Library Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
evm-account-generator = "0.1.0"
```

### Basic Usage - EVM Private Key

```rust
use evm_account_generator::{
    RngPrivateKeyGenerator, PrivateKeyGenerator, ThreadRngFillBytes,
    PrivateKey, evm::PrivateKey as EvmKey,
};

fn main() {
    let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
    let private_key: EvmKey = generator.generate();

    println!("Private key: {}", private_key.to_string());
    println!("Address: {}", private_key.derive_address());
}
```

### Multi-Blockchain Support

```rust
use evm_account_generator::{
    RngPrivateKeyGenerator, PrivateKeyGenerator, ThreadRngFillBytes,
    PrivateKey,
    evm::PrivateKey as EvmKey,
    solana::PrivateKey as SolanaKey,
};

fn main() {
    let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());

    let evm_key: EvmKey = generator.generate();       // 32-byte secp256k1 key
    let solana_key: SolanaKey = generator.generate();  // 32-byte Ed25519 seed

    println!("EVM Key: {}", evm_key.to_string());
    println!("EVM Address: {}", evm_key.derive_address());

    println!("Solana Key: {}", solana_key.to_string());
    println!("Solana Address: {}", solana_key.derive_address());
}
```

### Using DevRandomRng (Unix/Linux/macOS)

```rust
use evm_account_generator::{
    DevRandomRng, RngPrivateKeyGenerator, PrivateKeyGenerator,
    PrivateKey, evm::PrivateKey as EvmKey,
};

fn main() {
    let rng = DevRandomRng::new();
    let mut generator = RngPrivateKeyGenerator::new(rng);
    let private_key: EvmKey = generator.generate();

    println!("Private key: {}", private_key.to_string());
}
```

## Architecture

The library uses a trait-based, type-safe architecture that separates concerns and enables easy extension to new blockchain networks.

### Core Traits

#### `PrivateKey` - Blockchain-Agnostic Private Key Trait

Defines the common interface for all blockchain private keys:

```rust
pub trait PrivateKey: Sized + Clone {
    type Address: std::fmt::Display;

    fn new(bytes: &[u8]) -> Option<Self>;
    fn from_string(string: &str) -> Option<Self>;
    fn is_valid(bytes: &[u8]) -> bool;
    fn key_size() -> usize;
    fn as_bytes(&self) -> &[u8];
    fn to_string(&self) -> String;
    fn derive_address(&self) -> Self::Address;
}
```

#### `PrivateKeyGenerator<T>` - Generic Key Generation

```rust
pub trait PrivateKeyGenerator<T: PrivateKey> {
    fn generate(&mut self) -> T;
}
```

#### `FillBytes` - Random Byte Generation

```rust
pub trait FillBytes {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}
```

### Module Structure

#### `private_key` - Core Trait Definitions
- `PrivateKey` trait defining the common interface for all blockchain keys

#### `private_key_generator` - Generic Key Generation
- `PrivateKeyGenerator<T>` trait for generating keys of type T
- `RngPrivateKeyGenerator<R>` concrete implementation using any RNG
- `SequentialPrivateKeyGenerator<K>` for deterministic sequential generation
- `FillBytes` trait for byte buffer filling
- Automatic validation and retry for invalid keys

#### `evm` - Ethereum Virtual Machine Support
- 32-byte ECDSA secp256k1 private keys
- 20-byte Ethereum addresses (Keccak-256 derivation)
- secp256k1 curve order validation

#### `solana` - Solana Blockchain Support
- 32-byte Ed25519 signing keys (seeds)
- Base58-encoded addresses (Ed25519 public keys via `ed25519-dalek`)
- Import/export compatible with Phantom wallet (base58 64-byte keypair)

#### `rng` - Random Number Generation
- `ThreadRngFillBytes` - Wrapper around `rand::thread_rng()`
- `DevRandomRng` - System entropy from `/dev/random` (Unix-like systems)

### Design Benefits

- **Type Safety**: Compile-time guarantees prevent mixing keys from different blockchains
- **Extensibility**: Add new blockchains by implementing `PrivateKey`
- **Testability**: Mock RNG implementations for deterministic testing
- **Composability**: Mix and match different RNG sources with different key types
- **Zero-Cost Abstractions**: Traits compile down to direct function calls

## API Reference

### Core Types

#### `RngPrivateKeyGenerator<R: FillBytes>`

The main generator that creates private keys using any RNG:

```rust
let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
let key: EvmKey = generator.generate();
```

#### `EvmPrivateKey` (re-exported as `evm::PrivateKey`)

EVM/Ethereum private key (32 bytes, secp256k1):

- `new(bytes: &[u8]) -> Option<Self>` - Create from 32 bytes
- `from_string(string: &str) -> Option<Self>` - Parse from `0x`-prefixed hex
- `to_string(&self) -> String` - Hex string with `0x` prefix
- `derive_address(&self) -> EvmAddress` - Derive 20-byte Ethereum address
- `as_bytes(&self) -> &[u8]` - Raw 32 bytes

#### `SolanaPrivateKey` (re-exported as `solana::PrivateKey`)

Solana private key (32-byte Ed25519 seed):

- `new(bytes: &[u8]) -> Option<Self>` - Create from 32 bytes
- `from_string(string: &str) -> Option<Self>` - Parse from base58 keypair, base58 seed, or `0x`-prefixed hex
- `to_string(&self) -> String` - Base58-encoded 64-byte keypair (Phantom-compatible)
- `derive_address(&self) -> SolanaAddress` - Base58-encoded Ed25519 public key
- `to_keypair_bytes(&self) -> [u8; 64]` - Full keypair (seed + public key)

#### `ThreadRngFillBytes`

Cryptographically secure thread-local RNG (cross-platform):

```rust
let rng = ThreadRngFillBytes::new();
```

#### `DevRandomRng`

System entropy source using `/dev/random` (Unix only, may block):

```rust
let rng = DevRandomRng::new();
```

## Examples

See the `examples/` directory for complete, runnable examples:

```bash
cargo run --example basic_usage
cargo run --example comprehensive
cargo run --example dev_random
cargo run --example multi_blockchain_generator
cargo run --example sequential_generator
cargo run --example compare_generators
cargo run --example benchmark
cargo run --example vanity
```

### Custom RNG Implementation

```rust
use evm_account_generator::{
    FillBytes, RngPrivateKeyGenerator, PrivateKeyGenerator,
    PrivateKey, evm::PrivateKey as EvmKey,
};

struct CounterRng { counter: u8 }

impl FillBytes for CounterRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            *byte = self.counter;
            self.counter = self.counter.wrapping_add(1);
        }
    }
}

fn main() {
    let mut generator = RngPrivateKeyGenerator::new(CounterRng { counter: 1 });
    let key: EvmKey = generator.generate();
    println!("Generated key: {}", key.to_string());
}
```

### Working with Existing Keys

```rust
use evm_account_generator::{PrivateKey, evm::PrivateKey as EvmKey};

fn main() {
    let hex_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    match EvmKey::from_string(hex_key) {
        Some(key) => {
            println!("Valid key: {}", key.to_string());
            println!("Address: {}", key.derive_address());
        }
        None => println!("Invalid private key"),
    }
}
```

### Generic Function for Multiple Blockchains

```rust
use evm_account_generator::{
    PrivateKey, PrivateKeyGenerator, RngPrivateKeyGenerator, FillBytes,
};

fn generate_and_print<T, R>(generator: &mut RngPrivateKeyGenerator<R>)
where
    T: PrivateKey,
    R: FillBytes,
{
    let key: T = generator.generate();
    println!("Private Key: {}", key.to_string());
    println!("Address: {}", key.derive_address());
    println!("Key Size: {} bytes", T::key_size());
}
```

## Security Considerations

### Cryptographic Security
- **Entropy Quality**: Uses cryptographically secure random number generators
  - `ThreadRngFillBytes` uses `rand::thread_rng()` (ChaCha20-based CSPRNG)
  - `DevRandomRng` reads from `/dev/random` for kernel-level entropy
- **Key Validation**: All generated keys are validated before being returned
  - EVM keys: Must be non-zero and within secp256k1 curve order
  - Solana keys: Must be non-zero 32-byte arrays
- **Automatic Retry**: Invalid keys are automatically discarded and regenerated

### Operational Security
- **Blocking Behavior**: `DevRandomRng` will block until sufficient entropy is available
- **No Key Persistence**: Private keys exist only in memory; your application must handle storage
- **Memory Safety**: Rust's ownership system prevents common memory vulnerabilities
- **No Network Access**: All operations are local and offline

### Best Practices
1. Always use cryptographically secure RNGs (`ThreadRngFillBytes` or `DevRandomRng`)
2. Never log or print private keys in production
3. Store private keys encrypted at rest
4. Consider using hardware security modules (HSMs) for production key storage
5. Test key generation thoroughly but never use test keys in production

## Platform Support

| RNG Type | Linux | macOS | Windows | BSD |
|----------|-------|-------|---------|-----|
| ThreadRngFillBytes | Yes | Yes | Yes | Yes |
| DevRandomRng | Yes | Yes | No | Yes |

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run tests for a specific module
cargo test private_key_generator

# Run documentation tests
cargo test --doc
```

## Dependencies

### Core
- `hex` - Hexadecimal encoding/decoding
- `secp256k1` - ECDSA secp256k1 operations (EVM)
- `keccak-asm` - Keccak-256 hashing (Ethereum address derivation)
- `rand` - Random number generation
- `ed25519-dalek` - Ed25519 signing keys (Solana)
- `bs58` - Base58 encoding/decoding (Solana addresses)
- `clap` - CLI argument parsing
- `sysinfo` - System information (vanity search CPU display)

## Extending to New Blockchains

Implement the `PrivateKey` trait for your blockchain:

```rust
use evm_account_generator::PrivateKey;

#[derive(Debug, Clone, PartialEq)]
pub struct MyChainKey([u8; 32]);

#[derive(Debug, Clone, PartialEq)]
pub struct MyChainAddress(String);

impl std::fmt::Display for MyChainAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PrivateKey for MyChainKey {
    type Address = MyChainAddress;

    fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 || bytes.iter().all(|&b| b == 0) {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Some(Self(key))
    }

    fn from_string(string: &str) -> Option<Self> { todo!() }
    fn is_valid(bytes: &[u8]) -> bool { bytes.len() == 32 && !bytes.iter().all(|&b| b == 0) }
    fn key_size() -> usize { 32 }
    fn as_bytes(&self) -> &[u8] { &self.0 }
    fn to_string(&self) -> String { format!("0x{}", hex::encode(&self.0)) }
    fn derive_address(&self) -> Self::Address { todo!() }
}
```

Then use it with the existing generator:

```rust
let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
let key: MyChainKey = generator.generate();
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
