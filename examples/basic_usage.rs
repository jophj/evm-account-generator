//! Basic usage example for EVM account generator

use evm_account_generator::{generate_private_key_with_rng, ToHex, GetAddress};
use rand::thread_rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("EVM Account Generator - Basic Usage Example");
    println!("==========================================");

    // Generate a private key using thread RNG
    let mut rng = thread_rng();
    let private_key = generate_private_key_with_rng(&mut rng);
    
    println!("Generated private key: {}", private_key.to_hex());
    println!("Corresponding address: {}", private_key.get_address());
    
    Ok(())
}
