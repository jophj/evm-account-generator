use evm_account_generator::{DevRandomRng, PrivateKeyGenerator, RngPrivateKeyGenerator, ThreadRngFillBytes};
use evm_account_generator::evm::evm_private_key::EVMPrivateKey2;
use evm_account_generator::private_key::PrivateKey2;

fn main() {
    println!("EVM Account Generator");
    println!("====================");

    let private_key = EVMPrivateKey2::new(&[0x12u8; 32]).expect("Valid key");
    println!("Generated private key: {}", private_key.to_string());
    println!("Address: {}", private_key.derive_address());

    // Generate a private key using explicit RNG
    let mut thread_rng_generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
    let private_key: EVMPrivateKey2 = thread_rng_generator.generate();
    println!("Generated private key: {}", private_key.to_string());
    println!("Address: {}", private_key.derive_address());


    // Demonstrate DevRandomRng (if available on this system)
    println!("\nDevRandomRng demonstration:");
    let dev_random_rng = DevRandomRng::new();
    let mut dev_random_generator = RngPrivateKeyGenerator::new(dev_random_rng);
    let private_key_dev: EVMPrivateKey2 = dev_random_generator.generate();
    println!("Generated with /dev/random: {}", private_key_dev.to_string());
    
    // Test validation with some examples
    println!("\nValidation tests:");
    let valid_key = EVMPrivateKey2::from_string("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    println!("Valid key: {}", valid_key.unwrap().to_string());
    // println!("Invalid key (too short): {}", is_valid_private_key("0x123"));
    // println!("Invalid key (bad hex): {}", is_valid_private_key("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefg"));
    
    // Demonstrate error handling
    println!("\nError handling tests:");
    match EVMPrivateKey2::from_string("0x123") {
        Some(key) => println!("Unexpected success: {}", key.to_string()),
        None => println!("Expected error for short key"),
    }
    
    match EVMPrivateKey2::from_string("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefg") {
        Some(key) => println!("Unexpected success: {}", key.to_string()),
        None => println!("Expected error for invalid hex"),
    }
}
