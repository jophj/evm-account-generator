//! EVM Account Generator CLI
//!
//! A command-line application for generating, deriving, and searching for
//! EVM private keys with various entropy sources.

use clap::{Parser, Subcommand, ValueEnum};
use evm_account_generator::{
    DevRandomRng, 
    RngPrivateKeyGenerator, 
    PrivateKeyGenerator,
    ThreadRngFillBytes,
    PrivateKey,
    evm::PrivateKey as EvmKey,
};

#[derive(Parser)]
#[command(name = "evm-account-generator")]
#[command(version = "0.1.0")]
#[command(about = "Generate EVM private keys", long_about = None)]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Generate a new random EVM private key
    Generate {
        /// Random number generator to use
        #[arg(short, long, value_enum, default_value_t = RngType::ThreadRng)]
        rng: RngType,
        
        /// Suppress extra output, show only key and address
        #[arg(short, long, default_value_t = false)]
        quiet: bool,
    },
    /// Derive address from an existing private key (TODO)
    Derive,
    /// Search for vanity addresses (TODO)
    Vanity,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum RngType {
    /// Use thread-local RNG (cross-platform, recommended)
    ThreadRng,
    /// Use /dev/random (Unix only, highest entropy quality)
    DevRandom,
}

fn main() {
    let cli = Cli::parse();

    match cli.mode {
        Mode::Generate { rng, quiet } => {
            generate_key(rng, quiet);
        }
        Mode::Derive => {
            println!("Derive mode is not yet implemented.");
            println!("This mode will allow you to derive an address from an existing private key.");
            std::process::exit(1);
        }
        Mode::Vanity => {
            println!("Vanity mode is not yet implemented.");
            println!("This mode will allow you to search for vanity addresses.");
            std::process::exit(1);
        }
    }
}

fn generate_key(rng_type: RngType, quiet: bool) {
    if !quiet {
        println!("EVM Account Generator");
        println!("====================\n");
    }

    match rng_type {
        RngType::ThreadRng => {
            if !quiet {
                println!("Using: ThreadRng (thread-local RNG)");
                println!("  - Cross-platform compatible");
                println!("  - Cryptographically secure (ChaCha20)");
                println!("  - Non-blocking\n");
                println!("Generating private key...");
            }

            let thread_rng = ThreadRngFillBytes::new();
            let mut generator = RngPrivateKeyGenerator::new(thread_rng);
            let private_key: EvmKey = generator.generate();
            
            display_key_info(&private_key, quiet);
        }
        RngType::DevRandom => {
            #[cfg(not(target_family = "unix"))]
            {
                eprintln!("Error: /dev/random is only available on Unix-like systems");
                eprintln!("Please use --rng thread-rng instead");
                std::process::exit(1);
            }

            #[cfg(target_family = "unix")]
            {
                if !quiet {
                    println!("Using: /dev/random (kernel entropy pool)");
                    println!("  - Maximum entropy source");
                    println!("  - Unix/Linux/macOS only");
                    println!("  - May block if entropy is low\n");
                    println!("Opening /dev/random...");
                }

                let rng = DevRandomRng::new();
                let mut generator = RngPrivateKeyGenerator::new(rng);
                
                if !quiet {
                    println!("Generating private key (this may take a moment)...");
                }
                
                let private_key: EvmKey = generator.generate();
                display_key_info(&private_key, quiet);
            }
        }
    }

    if !quiet {
        println!("\n⚠️  SECURITY WARNING:");
        println!("   Never share your private key with anyone!");
        println!("   Anyone with your private key has full control of your account.");
        println!("   Store it securely and never expose it in logs or version control.");
    }
}

fn display_key_info(private_key: &EvmKey, quiet: bool) {
    if quiet {
        // Quiet mode: only show key
        println!("{}", private_key.to_string());
    } else {
        // Normal mode: show full details
        println!("\n✓ Successfully generated EVM account!\n");
        println!("Private Key: {}", private_key.to_string());
        println!("Address:     {}\n", private_key.derive_address());
        
        println!("Key Details:");
        println!("  Length:  {} bytes", private_key.as_bytes().len());
        println!("  Format:  0x-prefixed hexadecimal");
        println!("  Curve:   secp256k1");
    }
}
