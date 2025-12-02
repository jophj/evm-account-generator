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
use std::io::{self, BufRead, IsTerminal, Write};
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::System;

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
    /// Derive address from an existing private key
    Derive {
        /// Private key (0x-prefixed hex string). If not provided, reads from stdin
        private_key: Option<String>,
        
        /// Suppress extra output, show only address
        #[arg(short, long, default_value_t = false)]
        quiet: bool,
    },
    /// Search for vanity addresses with custom prefix/suffix
    Vanity {
        /// Address prefix to match (hex, without 0x)
        #[arg(long)]
        prefix: Option<String>,
        
        /// Address suffix to match (hex, without 0x)
        #[arg(long)]
        suffix: Option<String>,
        
        /// Number of threads to use (default: CPU count)
        #[arg(long)]
        threads: Option<usize>,
        
        /// Suppress progress output, show only result
        #[arg(short, long, default_value_t = false)]
        quiet: bool,
    },
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
        Mode::Derive { private_key, quiet } => {
            derive_address(private_key, quiet);
        }
        Mode::Vanity { prefix, suffix, threads, quiet } => {
            search_vanity(prefix, suffix, threads, quiet);
        }
    }
}

fn generate_key(rng_type: RngType, quiet: bool) {
    match rng_type {
        RngType::ThreadRng => {
            if !quiet {
                println!("Using: ThreadRng (ChaCha20)");
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
                    println!("Using: /dev/random (may block if entropy is low)");
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
}

fn search_vanity(
    prefix: Option<String>,
    suffix: Option<String>,
    threads: Option<usize>,
    quiet: bool,
) {
    // Validate that at least one pattern is provided
    if prefix.is_none() && suffix.is_none() {
        eprintln!("Error: Must specify at least --prefix or --suffix");
        eprintln!("Example: evm-account-generator vanity --prefix dead");
        std::process::exit(1);
    }

    // Parse and validate hex patterns to (bytes, mask) tuples
    let prefix_pattern = prefix.as_ref().map(|p| parse_hex_pattern(p, true));
    let suffix_pattern = suffix.as_ref().map(|s| parse_hex_pattern(s, false));

    // Determine number of threads
    let num_threads = threads.unwrap_or_else(|| {
        thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });

    // Calculate search space and expected attempts for 50% probability
    let search_space = calculate_search_space(&prefix, &suffix);
    let expected_attempts = (search_space as f64 * 0.693).ceil() as u64;
    
    if !quiet {
        display_cpu_info(num_threads);
        println!();

        println!("Searching for vanity address...");
        if let Some(ref p) = prefix {
            println!("  Prefix: {} ({} hex chars)", p, p.len());
        }
        if let Some(ref s) = suffix {
            println!("  Suffix: {} ({} hex chars)", s, s.len());
        }
        println!("  Threads: {}", num_threads);
        println!("  Expected attempts (50% probability): {}", format_number(expected_attempts));
        
        println!();
    }

    let (result_tx, result_rx) = mpsc::channel();
    let (stats_tx, stats_rx) = mpsc::channel();
    let found = Arc::new(AtomicBool::new(false));
    let mut report_senders = vec![];

    // Spawn worker threads
    let start_time = Instant::now();
    let mut handles = vec![];
    
    for thread_id in 0..num_threads {
        let result_tx = result_tx.clone();
        let stats_tx = stats_tx.clone();
        let found = Arc::clone(&found);
        let prefix_pattern = prefix_pattern.clone();
        let suffix_pattern = suffix_pattern.clone();
        
        let (report_tx, report_rx) = mpsc::channel();
        report_senders.push(report_tx);
        
        let handle = thread::spawn(move || {
            let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
            let mut count = 0u64;
            
            loop {
                if found.load(Ordering::Relaxed) {
                    return;
                }
                
                let private_key: EvmKey = generator.generate();
                let address = private_key.derive_address();
                let addr_bytes = address.as_bytes();
                
                // Check prefix match using byte-level comparison
                let prefix_match = prefix_pattern.as_ref().map_or(true, |(pattern, mask)| {
                    is_matching(&addr_bytes[..pattern.len()], pattern, mask)
                });
                
                // Check suffix match using byte-level comparison
                let suffix_match = suffix_pattern.as_ref().map_or(true, |(pattern, mask)| {
                    let start = addr_bytes.len() - pattern.len();
                    is_matching(&addr_bytes[start..], pattern, mask)
                });
                
                if prefix_match && suffix_match {
                    found.store(true, Ordering::Relaxed);
                    result_tx.send((private_key, thread_id, count)).unwrap();
                    return;
                }
                
                count += 1;
                
                // Check for report request
                if let Ok(_) = report_rx.try_recv() {
                    stats_tx.send(count).ok();
                    count = 0;
                }
            }
        });
        
        handles.push(handle);
    }

    drop(result_tx);
    drop(stats_tx);

    // Progress reporting loop
    let mut last_report = Instant::now();
    let mut total_checked = 0u64;
    
    loop {
        // Check if we found a result
        if let Ok((private_key, thread_id, final_count)) = result_rx.try_recv() {
            let elapsed = start_time.elapsed();
            total_checked += final_count;
            
            if !quiet {
                println!("\n✓ Found by thread {}!", thread_id);
                println!("Time elapsed: {:.1} seconds", elapsed.as_secs_f64());
                println!("Keys checked: {}\n", format_number(total_checked));
                println!("Private Key: {}", private_key.to_string());
                println!("Address:     {}", private_key.derive_address());
            } else {
                println!("{}", private_key.to_string());
            }
            break;
        }

        // Send report requests
        if !quiet && last_report.elapsed() >= Duration::from_millis(500) {
            for sender in &report_senders {
                sender.send(()).ok();
            }

            thread::sleep(Duration::from_millis(50));

            let mut interval_count = 0u64;
            while let Ok(count) = stats_rx.try_recv() {
                interval_count += count;
            }

            if interval_count > 0 {
                total_checked += interval_count;
                let elapsed = last_report.elapsed();
                let keys_per_sec = (interval_count as f64 / elapsed.as_secs_f64()) as u64;
                
                // Calculate ETA for 50% probability
                let remaining = if total_checked < expected_attempts {
                    expected_attempts - total_checked
                } else {
                    0
                };
                
                let eta_str = if keys_per_sec > 0 && remaining > 0 {
                    let eta_secs = remaining / keys_per_sec;
                    format_duration(eta_secs)
                } else {
                    "unlucky".to_string()
                };
                
                print!("\r{} keys/sec | {} checked | ETA 50%: {}", 
                    format_number(keys_per_sec), 
                    format_number(total_checked),
                    eta_str);
                io::stdout().flush().ok();
                last_report = Instant::now();
            }
        } else if !quiet {
            thread::sleep(Duration::from_millis(100));
        }
    }

    // Wait for all threads to finish
    for handle in handles {
        handle.join().ok();
    }
}

fn parse_hex_pattern(pattern: &str, is_prefix: bool) -> (Vec<u8>, Vec<u8>) {
    // Remove 0x prefix if present
    let clean = pattern.strip_prefix("0x").unwrap_or(pattern);
    
    // Validate hex characters
    if !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        eprintln!("Error: Invalid hex pattern: {}", pattern);
        eprintln!("Pattern must contain only hex characters (0-9, a-f, A-F)");
        std::process::exit(1);
    }
    
    let is_odd_length = clean.len() % 2 == 1;
    
    // Pad with 0 if odd length
    // For prefix: pad at the end (e.g., "69420" -> "694200", mask FFFFF0)
    // For suffix: pad at the beginning (e.g., "69420" -> "069420", mask 0FFFFF)
    let padded = if is_odd_length {
        if is_prefix {
            format!("{}0", clean)
        } else {
            format!("0{}", clean)
        }
    } else {
        clean.to_string()
    };
    
    // Convert hex string to bytes
    let bytes: Vec<u8> = (0..padded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&padded[i..i+2], 16).unwrap())
        .collect();
    
    // Generate bitmask
    let mut mask = vec![0xFF; bytes.len()];
    if is_odd_length {
        if is_prefix {
            // For prefix with odd length: mask last byte's upper nibble only (0xF0)
            // e.g., "69420" -> bytes=[0x69, 0x42, 0x00], mask=[0xFF, 0xFF, 0xF0]
            *mask.last_mut().unwrap() = 0xF0;
        } else {
            // For suffix with odd length: mask first byte's lower nibble only (0x0F)
            // e.g., "69420" -> bytes=[0x06, 0x94, 0x20], mask=[0x0F, 0xFF, 0xFF]
            mask[0] = 0x0F;
        }
    }
    
    (bytes, mask)
}

/// Checks if bits in `test` match bits in `pattern` where `bitmask` has 1s.
fn is_matching(test: &[u8], pattern: &[u8], bitmask: &[u8]) -> bool {
    // All arrays should have the same length
    if test.len() != pattern.len() || test.len() != bitmask.len() {
        return false;
    }
    
    // Check if masked bits match for each byte
    test.iter()
        .zip(pattern.iter())
        .zip(bitmask.iter())
        .all(|((t, p), m)| (t & m) == (p & m))
}

fn display_cpu_info(_threads_used: usize) {
    let mut sys = System::new();
    sys.refresh_cpu_all();
    
    // Get CPU information
    let cpus = sys.cpus();
    if let Some(cpu) = cpus.first() {
        let cpu_name = cpu.brand().trim();
        let frequency = cpu.frequency(); // MHz
        
        // Get architecture
        let arch = std::env::consts::ARCH;
        
        // Get core counts
        let physical_cores = System::physical_core_count().unwrap_or(0);
        let logical_cores = cpus.len();
        
        println!();
        println!("System Information:");
        println!("  CPU: {} ({})", cpu_name, arch);
        
        if frequency > 0 {
            println!("  Frequency: {:.2} GHz", frequency as f64 / 1000.0);
        }
        
        if physical_cores > 0 {
            println!("  Cores: {} physical, {} logical", physical_cores, logical_cores);
        } else {
            println!("  Cores: {} logical", logical_cores);
        }
    }
}

fn calculate_search_space(prefix: &Option<String>, suffix: &Option<String>) -> u64 {
    let mut space = 1u64;
    
    if let Some(p) = prefix {
        // Each hex character represents 4 bits (16 possibilities)
        // For odd-length patterns, the last character is wildcarded (already 16x larger)
        let hex_chars = p.len();
        space = space.saturating_mul(16u64.saturating_pow(hex_chars as u32));
    }
    
    if let Some(s) = suffix {
        let hex_chars = s.len();
        space = space.saturating_mul(16u64.saturating_pow(hex_chars as u32));
    }
    
    space
}

fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        let mins = seconds / 60;
        let secs = seconds % 60;
        format!("{}m {}s", mins, secs)
    } else if seconds < 86400 {
        let hours = seconds / 3600;
        let mins = (seconds % 3600) / 60;
        format!("{}h {}m", hours, mins)
    } else {
        let days = seconds / 86400;
        let hours = (seconds % 86400) / 3600;
        format!("{}d {}h", days, hours)
    }
}

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let mut count = 0;
    
    for c in s.chars().rev() {
        if count == 3 {
            result.push(',');
            count = 0;
        }
        result.push(c);
        count += 1;
    }
    
    result.chars().rev().collect()
}

fn derive_address(private_key_opt: Option<String>, quiet: bool) {
    // Get the private key from argument or stdin
    let private_key_str = match private_key_opt {
        Some(key) => key,
        None => {
            // Read from stdin
            let stdin = io::stdin();
            
            // Show prompt if stdin is a terminal (interactive mode)
            if stdin.is_terminal() {
                eprint!("Enter private key: ");
                // Flush stderr to ensure prompt is displayed immediately
                use std::io::Write;
                let _ = io::stderr().flush();
            }
            
            let mut line = String::new();
            match stdin.lock().read_line(&mut line) {
                Ok(_) => line.trim().to_string(),
                Err(e) => {
                    eprintln!("Error reading from stdin: {}", e);
                    std::process::exit(1);
                }
            }
        }
    };
    
    // Parse the private key
    let private_key = match EvmKey::from_string(&private_key_str) {
        Some(key) => key,
        None => {
            eprintln!("Error: Invalid private key format");
            eprintln!("\nExpected format: 0x-prefixed 64-character hex string");
            eprintln!("Example: 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
            std::process::exit(1);
        }
    };
    
    // Derive the address
    let address = private_key.derive_address();
    
    if quiet {
        // Quiet mode: only show address
        println!("{}", address);
    } else {
        // Normal mode: show full details
        println!("Private Key: {}", private_key.to_string());
        println!("Address:     {}\n", address);
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
    }
}
