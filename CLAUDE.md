# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build release binary
cargo build --release

# Run tests
cargo test

# Run tests for a specific module
cargo test private_key_generator

# Run doc tests
cargo test --doc

# Run an example
cargo run --example basic_usage
cargo run --example benchmark
```

## Architecture

This is a dual-purpose Rust project: a **library** (`src/lib.rs`) and a **CLI binary** (`src/main.rs`).

### Core trait hierarchy

Three traits form the foundation:

1. **`PrivateKey`** (`src/private_key.rs`) — Implemented by each blockchain key type. Provides `new()`, `from_string()`, `is_valid()`, `key_size()`, `as_bytes()`, `to_string()`, `derive_address()`. The associated type `Address: Display` is blockchain-specific.

2. **`FillBytes`** (`src/private_key_generator.rs`) — Fills a `&mut [u8]` buffer with random bytes. Implemented by `ThreadRngFillBytes` and `DevRandomRng`.

3. **`PrivateKeyGenerator<T: PrivateKey>`** (`src/private_key_generator.rs`) — Generic over the key type `T`. `RngPrivateKeyGenerator<R>` uses any `FillBytes` source, queries `T::key_size()`, and retries on invalid keys. `SequentialPrivateKeyGenerator<K>` increments bytes deterministically (used for testing).

### Blockchain modules

- **`src/evm/`** — `EvmPrivateKey` (32-byte secp256k1), `EvmAddress` (20-byte Keccak-256 derived). Also contains `EvmIncrementalGenerator` which starts from a random key and uses cheap EC point additions (`P + G`) for subsequent keys instead of full scalar multiplications — ~5x faster for vanity search.

- **`src/solana/`** — `SolanaPrivateKey` (32-byte Ed25519 seed), address is base58-encoded public key. `to_string()` outputs a Phantom-compatible base58 64-byte keypair.

### RNG module (`src/rng/`)

- `ThreadRngFillBytes` — wraps `rand::thread_rng()` (ChaCha20 CSPRNG, cross-platform)
- `DevRandomRng` — reads `/dev/random` (Unix only, may block)

### CLI (`src/main.rs`)

Three subcommands: `generate`, `derive`, `vanity`. The vanity search spawns worker threads communicating via `mpsc` channels, with an `AtomicBool` flag to signal when a result is found. EVM vanity matching works on raw address bytes using a bitmask to handle odd-length hex patterns.

### Adding a new blockchain

Implement `PrivateKey` for the new key type. The existing `RngPrivateKeyGenerator` works immediately with the new type via generics — no changes needed to the generator.
