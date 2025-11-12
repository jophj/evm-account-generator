//! Integration tests for EVM account generator

use evm_account_generator::{
    EVMPrivateKey, FromHex, GetAddress, PrivateKey2, RandomBytes32, ToHex, generate_private_key_bytes, generate_private_key_with_rng, is_valid_private_key, traits::PrivateKey
};
use rand::thread_rng;

#[test]
fn test_end_to_end_key_generation() {
    let mut rng = thread_rng();
    let private_key = generate_private_key_with_rng(&mut rng);
    
    // Test that we can convert to hex and back
    let hex = private_key.to_hex();
    assert!(is_valid_private_key(&hex));
    
    let reconstructed = EVMPrivateKey::from_hex(&hex).unwrap();
    assert_eq!(private_key.to_hex(), reconstructed.to_hex());
}

#[test]
fn test_address_generation() {
    let private_key = EVMPrivateKey::from_hex(
        "0x126824047ad2ca09f61950ca590520caa7247871ac15e0ccc931ebab91a1037c"
    ).unwrap();
    
    let address = private_key.get_address();
    assert!(address.starts_with("0x"));
    assert_eq!(address.len(), 42); // 0x + 40 hex chars
}

#[test]
fn test_multiple_rng_implementations() {
    // Test with thread RNG
    let mut thread_rng = thread_rng();
    let key1 = generate_private_key_with_rng(&mut thread_rng);
    assert!(is_valid_private_key(&key1.to_hex()));
    
    // Test with legacy function
    let bytes = generate_private_key_bytes();
    assert_eq!(bytes.len(), 32);
    
    let hex_string = format!("0x{}", hex::encode(&bytes));
    assert!(is_valid_private_key(&hex_string));
}

#[test]
fn test_key_uniqueness() {
    let mut rng = thread_rng();
    let mut keys = std::collections::HashSet::new();
    
    // Generate 100 keys and ensure they're all unique
    for _ in 0..100 {
        let key = generate_private_key_with_rng(&mut rng);
        let hex = key.to_hex();
        assert!(keys.insert(hex), "Generated duplicate key!");
    }
}

#[test]
fn test_error_handling() {
    // Test various invalid inputs
    assert!(!is_valid_private_key(""));
    assert!(!is_valid_private_key("0x"));
    assert!(!is_valid_private_key("0x123"));
    assert!(!is_valid_private_key("invalid"));
    assert!(!is_valid_private_key("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefg"));
    
    // Test PrivateKey creation errors
    assert!(EVMPrivateKey::from_hex("").is_err());
    assert!(EVMPrivateKey::from_hex("0x123").is_err());
    assert!(EVMPrivateKey::from_hex("invalid").is_err());
}

/// Mock RNG for deterministic testing
struct TestRng {
    value: u8,
}

impl TestRng {
    fn new(value: u8) -> Self {
        Self { value }
    }
}

impl RandomBytes32 for TestRng {
    fn random_bytes_32(&mut self) -> [u8; 32] {
        [self.value; 32]
    }
}

#[test]
fn test_deterministic_generation() {
    let mut rng1 = TestRng::new(1);
    let mut rng2 = TestRng::new(1);
    
    // Same RNG should produce same result
    let key1 = generate_private_key_with_rng(&mut rng1);
    let key2 = generate_private_key_with_rng(&mut rng2);
    
    assert_eq!(key1.to_hex(), key2.to_hex());
}

#[cfg(unix)]
#[test]
fn test_dev_random_integration() {
    use evm_account_generator::DevRandomRng;
    
    if let Ok(mut rng) = DevRandomRng::new() {
        let key = generate_private_key_with_rng(&mut rng);
        assert!(is_valid_private_key(&key.to_hex()));
        
        let address = key.get_address();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }
    // If DevRandomRng fails to initialize, that's okay for this test
}
