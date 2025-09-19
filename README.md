# EVM Account Generator

A Rust experiment for generating cryptographically secure EVM (Ethereum Virtual Machine) private keys with composable random number generation.

## Quick Start

`cargo run` or:

Add this to your `Cargo.toml`:

```toml
[dependencies]
evm-account-generator = "0.1.0"
rand = "0.8"  # Optional, for thread_rng
```

### Basic Usage

```rust
use evm_account_generator::{generate_private_key_with_rng, ToHex};
use rand::thread_rng;

fn main() {
    // Generate a private key using thread RNG
    let mut rng = thread_rng();
    let private_key = generate_private_key_with_rng(&mut rng);
    
    println!("Private key: {}", private_key.to_hex());
}
```

### Using DevRandomRng (Unix systems)

```rust
use evm_account_generator::{DevRandomRng, generate_private_key_with_rng, ToHex};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a private key using /dev/random
    let mut rng = DevRandomRng::new()?;
    let private_key = generate_private_key_with_rng(&mut rng);
    
    println!("Private key: {}", private_key.to_hex());
    Ok(())
}
```

## Architecture

The library is organized into three main modules:

### 1. `rng` - Random Number Generation Trait

Defines the `RandomBytes32` trait for composable random number generation:

```rust
pub trait RandomBytes32 {
    fn random_bytes_32(&mut self) -> [u8; 32];
}
```

Any type implementing `rand::RngCore` automatically implements `RandomBytes32`.

### 2. `evm_key_generator` - EVM Private Key Generation

Core functionality for generating and validating EVM private keys:

- `PrivateKey` - Type-safe wrapper for 32-byte private keys
- `ToHex` - Trait for hexadecimal string conversion
- `generate_private_key_with_rng()` - Main key generation function
- secp256k1 validation to ensure generated keys are valid

### 3. `dev_random_rng` - System Entropy RNG

Zero-dependency RNG implementation that reads from `/dev/random`:

```rust
let mut rng = DevRandomRng::new()?;
let key = generate_private_key_with_rng(&mut rng);
```

## API Reference

### Core Functions

#### `generate_private_key_with_rng<R: RandomBytes32>(rng: &mut R) -> PrivateKey`

Generates a cryptographically secure EVM private key using the provided RNG.

**Parameters:**
- `rng`: Mutable reference to any type implementing `RandomBytes32`

**Returns:**
- `PrivateKey`: A validated secp256k1 private key

#### `generate_private_key_bytes() -> Vec<u8>`

Legacy function that generates a private key as raw bytes using thread RNG.

#### `is_valid_private_key(key: &str) -> bool`

Validates if a hex string represents a valid EVM private key.

### Types

#### `PrivateKey`

Type-safe wrapper for EVM private keys with the following methods:

- `from_hex(hex_str: &str) -> Result<Self, String>` - Create from hex string
- `from_bytes(bytes: [u8; 32]) -> Self` - Create from byte array
- `to_bytes(&self) -> Vec<u8>` - Convert to byte vector
- `to_hex(&self) -> String` - Convert to hex string (via `ToHex` trait)

#### `DevRandomRng`

System entropy RNG that reads from `/dev/random`:

- `new() -> Result<Self, std::io::Error>` - Create new instance
- Implements `RandomBytes32` trait

### Traits

#### `RandomBytes32`

Core trait for 32-byte random number generation:

```rust
pub trait RandomBytes32 {
    fn random_bytes_32(&mut self) -> [u8; 32];
}
```

#### `ToHex`

Trait for hexadecimal string conversion:

```rust
pub trait ToHex {
    fn to_hex(&self) -> String;
}
```

## Examples

### Custom RNG Implementation

```rust
use evm_account_generator::{RandomBytes32, generate_private_key_with_rng, ToHex};

struct MockRng {
    counter: u8,
}

impl RandomBytes32 for MockRng {
    fn random_bytes_32(&mut self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[31] = self.counter;
        self.counter += 1;
        bytes
    }
}

fn main() {
    let mut rng = MockRng { counter: 1 };
    let key = generate_private_key_with_rng(&mut rng);
    println!("Generated key: {}", key.to_hex());
}
```

### Key Validation

```rust
use evm_account_generator::{PrivateKey, is_valid_private_key, ToHex};

fn main() {
    let hex_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    
    // Validate hex string
    if is_valid_private_key(hex_key) {
        // Create PrivateKey from validated hex
        let key = PrivateKey::from_hex(hex_key).unwrap();
        println!("Valid key: {}", key.to_hex());
    }
}
```

### Error Handling

```rust
use evm_account_generator::{DevRandomRng, generate_private_key_with_rng, ToHex};

fn generate_key() -> Result<String, Box<dyn std::error::Error>> {
    let mut rng = DevRandomRng::new()
        .map_err(|e| format!("Failed to initialize DevRandomRng: {}", e))?;
    
    let key = generate_private_key_with_rng(&mut rng);
    Ok(key.to_hex())
}
```

## Security Considerations

- **Entropy Quality**: The library validates that generated keys are not zero and fall within the valid secp256k1 curve range
- **Blocking Behavior**: `DevRandomRng` will block until sufficient entropy is available from `/dev/random`
- **No Key Persistence**: Private keys are only held in memory and must be explicitly saved by the application
- **Secure Defaults**: All RNG implementations provide cryptographically secure randomness

## Platform Support

- **Unix/Linux**: Full support including `DevRandomRng`
- **macOS**: Full support including `DevRandomRng`
- **Windows**: Core functionality supported, `DevRandomRng` not available (gracefully handled)

## Testing

Run the test suite:

```bash
cargo test
```

Run with verbose output:

```bash
cargo test -- --nocapture
```

The test suite includes:
- Unit tests for all modules
- Integration tests
- Cross-platform compatibility tests
- Documentation tests

## Building

```bash
# Build the library
cargo build

# Build with optimizations
cargo build --release

# Run the example application
cargo run
```

## Dependencies

### Required
- `hex = "0.4"` - For hexadecimal encoding/decoding

### Optional
- `rand = "0.8"` - For `thread_rng()` and other standard RNG implementations

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Changelog

### v0.1.0
- Initial release
- Composable RNG architecture
- `DevRandomRng` implementation
- Comprehensive test suite
- Type-safe `PrivateKey` implementation
