use evm_account_generator::{
    PrivateKey, ToHex, GetAddress, 
    generate_private_key_with_rng, generate_private_key_bytes, is_valid_private_key,
    DevRandomRng
};

fn main() {
    println!("EVM Account Generator");
    println!("====================");
    
    // Generate a private key using explicit RNG
    let mut rng = rand::thread_rng();
    let private_key = generate_private_key_with_rng(&mut rng);
    println!("Generated private key: {}", private_key.to_hex());
    println!("Address: {}", private_key.get_address());


    // Demonstrate ToHex trait usage
    println!("Using ToHex trait: {}", private_key.to_hex());

    // Demonstrate composable RNG usage with different RNG instance
    println!("\nComposable RNG demonstration:");
    let mut rng2 = rand::thread_rng();
    let private_key_with_rng = generate_private_key_with_rng(&mut rng2);
    println!("Generated with thread RNG: {}", private_key_with_rng.to_hex());

    // Demonstrate DevRandomRng (if available on this system)
    println!("\nDevRandomRng demonstration:");
    match DevRandomRng::new() {
        Ok(mut dev_rng) => {
            let private_key_dev = generate_private_key_with_rng(&mut dev_rng);
            println!("Generated with /dev/random: {}", private_key_dev.to_hex());
        }
        Err(e) => {
            println!("DevRandomRng not available on this system: {}", e);
        }
    }
    
    // Generate private key as bytes (legacy function)
    let private_key_bytes = generate_private_key_bytes();
    println!("Private key as bytes: {:?}", private_key_bytes);
    println!("Private key length: {} bytes", private_key_bytes.len());
    
    // Access bytes directly from PrivateKey
    let direct_bytes = private_key.to_bytes();
    println!("Direct bytes from PrivateKey: {:?}", direct_bytes);
    
    // Validate the generated key
    let is_valid = is_valid_private_key(&private_key.to_hex());
    println!("Is valid private key: {}", is_valid);
    
    // Test creating PrivateKey from hex
    println!("\nPrivateKey creation tests:");
    match PrivateKey::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef") {
        Ok(key) => println!("Created PrivateKey from hex: {}", key.to_hex()),
        Err(e) => println!("Error creating PrivateKey: {}", e),
    }
    
    // Test validation with some examples
    println!("\nValidation tests:");
    println!("Valid key: {}", is_valid_private_key("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"));
    println!("Invalid key (too short): {}", is_valid_private_key("0x123"));
    println!("Invalid key (bad hex): {}", is_valid_private_key("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefg"));
    
    // Demonstrate error handling
    println!("\nError handling tests:");
    match PrivateKey::from_hex("0x123") {
        Ok(key) => println!("Unexpected success: {}", key.to_hex()),
        Err(e) => println!("Expected error for short key: {}", e),
    }
    
    match PrivateKey::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefg") {
        Ok(key) => println!("Unexpected success: {}", key.to_hex()),
        Err(e) => println!("Expected error for invalid hex: {}", e),
    }
}
