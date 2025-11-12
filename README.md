# EVM Account Generator

A Rust library for generating cryptographically secure blockchain private keys with a composable, type-safe architecture. Supports multiple blockchain networks including EVM (Ethereum Virtual Machine) and Solana.

## Features

- **🔐 Type-Safe Key Generation**: Compile-time guarantees for different blockchain key types
- **🌐 Multi-Blockchain Support**: Generate keys for EVM (32 bytes) and Solana (64 bytes) with the same API
- **🎲 Flexible RNG Options**: Use thread-local RNG or system entropy (/dev/random)
- **✅ Automatic Validation**: Built-in validation for secp256k1 curve compliance (EVM)
- **🧩 Composable Architecture**: Trait-based design for easy extension to new blockchains
- **📦 Zero External Dependencies for Core**: Optional dependencies for specific RNG implementations

## Quick Start

Run the binary:
```bash
cargo run
```

Or use as a library - add this to your `Cargo.toml`:

```toml
[dependencies]
evm-account-generator = "0.1.0"
```

### Basic Usage - EVM Private Key

```rust
use evm_account_generator::{
    RngPrivateKeyGenerator, PrivateKeyGenerator, ThreadRngFillBytes,
    PrivateKey2, evm::evm_private_key::EVMPrivateKey2,
};

fn main() {
    // Create a generator using thread RNG
    let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
    
    // Generate an EVM private key
    let private_key: EVMPrivateKey2 = generator.generate();
    
    println!("Private key: {}", private_key.to_string());
    println!("Address: {}", private_key.derive_address());
}
```

### Multi-Blockchain Support

```rust
use evm_account_generator::{
    RngPrivateKeyGenerator, PrivateKeyGenerator, ThreadRngFillBytes,
    PrivateKey2,
    evm::evm_private_key::EVMPrivateKey2,
    solana::solana_private_key::SolanaPrivateKey2,
};

fn main() {
    // Create a single generator
    let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
    
    // Generate keys for different blockchains
    let evm_key: EVMPrivateKey2 = generator.generate();      // 32 bytes
    let solana_key: SolanaPrivateKey2 = generator.generate(); // 64 bytes
    
    println!("EVM Key: {}", evm_key.to_string());
    println!("Solana Key: {}", solana_key.to_string());
}
```

### Using DevRandomRng (Unix/Linux/macOS)

```rust
use evm_account_generator::{
    DevRandomRng, RngPrivateKeyGenerator, PrivateKeyGenerator,
    PrivateKey2, evm::evm_private_key::EVMPrivateKey2,
};

fn main() {
    // Use system entropy from /dev/random
    let rng = DevRandomRng::new();
    let mut generator = RngPrivateKeyGenerator::new(rng);
    
    let private_key: EVMPrivateKey2 = generator.generate();
    
    println!("Private key: {}", private_key.to_string());
}
```

## Architecture

The library uses a trait-based, type-safe architecture that separates concerns and enables easy extension to new blockchain networks.

### Core Traits

#### 1. `PrivateKey2` - Blockchain-Agnostic Private Key Trait

Defines the common interface for all blockchain private keys:

```rust
pub trait PrivateKey2: Sized + Clone {
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

#### 2. `PrivateKeyGenerator<T>` - Generic Key Generation

Defines how to generate private keys of any type:

```rust
pub trait PrivateKeyGenerator<T: PrivateKey2> {
    fn generate(&mut self) -> T;
}
```

#### 3. `FillBytes` - Random Byte Generation

Simple trait for filling buffers with random data:

```rust
pub trait FillBytes {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}
```

### Module Structure

#### `private_key` - Core Trait Definitions
- `PrivateKey2` trait defining the common interface for all blockchain keys

#### `private_key_generator` - Generic Key Generation
- `PrivateKeyGenerator<T>` trait for generating keys of type T
- `RngPrivateKeyGenerator<R>` concrete implementation using any RNG
- `FillBytes` trait for byte buffer filling
- Automatic validation and retry for invalid keys

#### `evm` - Ethereum Virtual Machine Support
- `EVMPrivateKey2` - 32-byte ECDSA secp256k1 private keys
- `EVMAddress` - 20-byte Ethereum addresses
- secp256k1 curve validation
- Keccak-256 address derivation

#### `solana` - Solana Blockchain Support
- `SolanaPrivateKey2` - 64-byte Ed25519 keypairs
- `SolanaAddress` - Solana public key addresses
- Ed25519 validation (simplified)

#### `rng` - Random Number Generation
- `ThreadRngFillBytes` - Wrapper around `rand::thread_rng()`
- `DevRandomRng` - System entropy from `/dev/random` (Unix-like systems)

### Design Benefits

- **Type Safety**: Compile-time guarantees prevent mixing keys from different blockchains
- **Extensibility**: Add new blockchains by implementing `PrivateKey2`
- **Testability**: Mock RNG implementations for deterministic testing
- **Composability**: Mix and match different RNG sources with different key types
- **Zero-Cost Abstractions**: Traits compile down to direct function calls

## API Reference

### Core Types

#### `RngPrivateKeyGenerator<R: FillBytes>`

The main generator that creates private keys using any RNG:

```rust
impl<R: FillBytes> RngPrivateKeyGenerator<R> {
    pub fn new(rng: R) -> Self;
}

impl<T: PrivateKey2, R: FillBytes> PrivateKeyGenerator<T> for RngPrivateKeyGenerator<R> {
    fn generate(&mut self) -> T;
}
```

**Usage:**
```rust
let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
let key: EVMPrivateKey2 = generator.generate();
```

#### `EVMPrivateKey2`

EVM/Ethereum private key implementation:

```rust
impl EVMPrivateKey2 {
    pub fn is_valid(bytes: &[u8]) -> bool;  // Static validation
}

// Implements PrivateKey2
impl PrivateKey2 for EVMPrivateKey2 {
    type Address = EVMAddress;
    fn key_size() -> usize { 32 }
    // ... other PrivateKey2 methods
}
```

**Key Methods:**
- `new(bytes: &[u8]) -> Option<Self>` - Create from bytes
- `from_string(string: &str) -> Option<Self>` - Parse from hex string
- `to_string(&self) -> String` - Convert to hex string with 0x prefix
- `derive_address(&self) -> EVMAddress` - Derive Ethereum address
- `as_bytes(&self) -> &[u8]` - Get raw bytes

#### `SolanaPrivateKey2`

Solana private key implementation (64 bytes for Ed25519):

```rust
impl PrivateKey2 for SolanaPrivateKey2 {
    type Address = SolanaAddress;
    fn key_size() -> usize { 64 }
    // ... other PrivateKey2 methods
}
```

**Key Methods:** Same as `EVMPrivateKey2` but operates on 64-byte keys

#### `ThreadRngFillBytes`

Wrapper around `rand::thread_rng()`:

```rust
impl ThreadRngFillBytes {
    pub fn new() -> Self;
}

impl FillBytes for ThreadRngFillBytes {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}
```

#### `DevRandomRng`

System entropy source using `/dev/random`:

```rust
impl DevRandomRng {
    pub fn new() -> Self;
}

impl FillBytes for DevRandomRng {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}
```

**Note:** Will panic if `/dev/random` is not available (non-Unix systems)

## Examples

See the `examples/` directory for complete, runnable examples:

- `basic_usage.rs` - Simple EVM key generation with ThreadRng
- `comprehensive.rs` - Comprehensive example showing all features
- `dev_random.rs` - Using /dev/random for system entropy
- `multi_blockchain_generator.rs` - Generating keys for multiple blockchains

### Example: Custom RNG Implementation

You can create your own RNG by implementing the `FillBytes` trait:

```rust
use evm_account_generator::{
    FillBytes, RngPrivateKeyGenerator, PrivateKeyGenerator,
    PrivateKey2, evm::evm_private_key::EVMPrivateKey2,
};

struct MockRng {
    counter: u8,
}

impl FillBytes for MockRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            *byte = self.counter;
            self.counter = self.counter.wrapping_add(1);
        }
    }
}

fn main() {
    let mut generator = RngPrivateKeyGenerator::new(MockRng { counter: 1 });
    let key: EVMPrivateKey2 = generator.generate();
    println!("Generated key: {}", key.to_string());
}
```

### Example: Working with Existing Keys

```rust
use evm_account_generator::{PrivateKey2, evm::evm_private_key::EVMPrivateKey2};

fn main() {
    let hex_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    
    // Parse from hex string
    match EVMPrivateKey2::from_string(hex_key) {
        Some(key) => {
            println!("Valid key: {}", key.to_string());
            println!("Address: {}", key.derive_address());
        }
        None => println!("Invalid private key"),
    }
}
```

### Example: Generic Function for Multiple Blockchains

```rust
use evm_account_generator::{
    PrivateKey2, PrivateKeyGenerator, RngPrivateKeyGenerator, FillBytes,
};

// This function works with any blockchain's private key
fn generate_and_print<T, R>(generator: &mut RngPrivateKeyGenerator<R>)
where
    T: PrivateKey2,
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
  - `ThreadRngFillBytes` uses `rand::thread_rng()` which is cryptographically secure
  - `DevRandomRng` reads from `/dev/random` for kernel-level entropy
- **Key Validation**: All generated keys are validated before being returned
  - EVM keys: Must be non-zero and within secp256k1 curve order
  - Solana keys: Must be non-zero 64-byte arrays
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

- **Unix/Linux**: Full support including `DevRandomRng` via `/dev/random`
- **macOS**: Full support including `DevRandomRng` via `/dev/random`
- **Windows**: Core functionality with `ThreadRngFillBytes` works; `DevRandomRng` not available
- **Other POSIX**: Should work wherever `/dev/random` exists

### RNG Availability by Platform

| RNG Type | Linux | macOS | Windows | BSD |
|----------|-------|-------|---------|-----|
| ThreadRngFillBytes | ✅ | ✅ | ✅ | ✅ |
| DevRandomRng | ✅ | ✅ | ❌ | ✅ |

## Testing

Run the comprehensive test suite:

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

### Test Coverage

The test suite includes:
- **Unit Tests**: Each module has comprehensive unit tests
- **Integration Tests**: Tests for end-to-end key generation workflows
- **Mock RNG Tests**: Deterministic tests using mock RNG implementations
- **Validation Tests**: Extensive validation of key formats and ranges
- **Multi-Blockchain Tests**: Tests for EVM and Solana key generation
- **Documentation Tests**: All code examples in docs are tested

### Running Examples

```bash
# Run the basic usage example
cargo run --example basic_usage

# Run the comprehensive example
cargo run --example comprehensive

# Run the dev_random example (Unix-like only)
cargo run --example dev_random

# Run the multi-blockchain example
cargo run --example multi_blockchain_generator
```

## Building

```bash
# Build the library and binary
cargo build

# Build with optimizations
cargo build --release

# Build documentation
cargo doc --open

# Run the main binary
cargo run

# Check for errors without building
cargo check
```

## Dependencies

The library uses several well-maintained crates:

### Core Dependencies
- `hex = "0.4"` - Hexadecimal encoding/decoding for key display
- `secp256k1 = "0.29"` - ECDSA secp256k1 elliptic curve operations for EVM
- `keccak-asm = "0.1.4"` - Keccak-256 hashing for Ethereum address derivation
- `rand = "0.8"` - Random number generation (for ThreadRngFillBytes)

### Why These Dependencies?

- **secp256k1**: Industry-standard library for Bitcoin/Ethereum cryptography
- **keccak-asm**: Optimized Keccak-256 implementation using assembly when available
- **rand**: The de-facto standard RNG library for Rust
- **hex**: Simple and widely-used hex encoding/decoding

All dependencies are widely used, well-audited, and actively maintained.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Extending to New Blockchains

Adding support for a new blockchain is straightforward. Here's a template:

```rust
use crate::private_key::PrivateKey2;

/// Your blockchain's private key type
#[derive(Debug, Clone, PartialEq)]
pub struct MyBlockchainPrivateKey([u8; KEY_SIZE]);

/// Your blockchain's address type
#[derive(Debug, Clone, PartialEq)]
pub struct MyBlockchainAddress(String);

impl std::fmt::Display for MyBlockchainAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PrivateKey2 for MyBlockchainPrivateKey {
    type Address = MyBlockchainAddress;
    
    fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != KEY_SIZE || !Self::is_valid(bytes) {
            return None;
        }
        let mut key_bytes = [0u8; KEY_SIZE];
        key_bytes.copy_from_slice(bytes);
        Some(Self(key_bytes))
    }
    
    fn from_string(string: &str) -> Option<Self> {
        // Implement hex string parsing
        todo!()
    }
    
    fn is_valid(bytes: &[u8]) -> bool {
        // Implement your blockchain's validation rules
        bytes.len() == KEY_SIZE && !bytes.iter().all(|&b| b == 0)
    }
    
    fn key_size() -> usize {
        KEY_SIZE
    }
    
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    
    fn to_string(&self) -> String {
        format!("0x{}", hex::encode(&self.0))
    }
    
    fn derive_address(&self) -> Self::Address {
        // Implement your blockchain's address derivation
        todo!()
    }
}
```

Then use it with the existing generator:

```rust
let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
let key: MyBlockchainPrivateKey = generator.generate();
```

## Changelog

### v0.1.0
- Initial release
- Trait-based composable architecture
- Multi-blockchain support (EVM and Solana)
- `RngPrivateKeyGenerator` with `FillBytes` trait
- `ThreadRngFillBytes` and `DevRandomRng` implementations
- Comprehensive test suite with mock RNG support
- Type-safe `PrivateKey2` trait system
- Automatic key validation and retry mechanism
