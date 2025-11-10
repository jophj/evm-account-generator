//! DevRandomRng usage example (Unix systems only)

use evm_account_generator::{DevRandomRng, generate_private_key_with_rng, ToHex, GetAddress};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("EVM Account Generator - DevRandomRng Example");
    println!("============================================");
    
    #[cfg(unix)]
    {
        println!("Attempting to use /dev/random for key generation...");
        
        match DevRandomRng::new() {
            Ok(mut rng) => {
                println!("Successfully opened /dev/random");
                println!("Note: This may block until sufficient entropy is available");
                
                let private_key = generate_private_key_with_rng(&mut rng);
                
                println!("Generated private key: {}", private_key.to_hex());
                println!("Corresponding address: {}", private_key.get_address());
                println!("Key generated using system entropy from /dev/random");
            }
            Err(e) => {
                println!("Failed to open /dev/random: {}", e);
                println!("This is expected on some systems or in sandboxed environments");
            }
        }
    }
    
    #[cfg(not(unix))]
    {
        println!("DevRandomRng is only available on Unix-like systems");
        println!("This example cannot run on the current platform");
    }
    
    Ok(())
}
