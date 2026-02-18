//! Account Generator CLI
//!
//! A command-line application for generating, deriving, and searching for
//! private keys on EVM and Solana blockchains with various entropy sources.

use clap::{Parser, Subcommand, ValueEnum};
use evm_account_generator::{
    DevRandomRng,
    EvmIncrementalGenerator,
    RngPrivateKeyGenerator,
    PrivateKeyGenerator,
    ThreadRngFillBytes,
    PrivateKey,
    evm::PrivateKey as EvmKey,
    evm::Address as EvmAddress,
    solana::PrivateKey as SolanaKey,
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
#[command(about = "Generate blockchain private keys", long_about = None)]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Generate a new random private key
    Generate {
        /// Blockchain type
        #[arg(short = 't', long = "type", value_enum, default_value_t = ChainType::Evm)]
        chain: ChainType,

        /// Random number generator to use
        #[arg(short, long, value_enum, default_value_t = RngType::ThreadRng)]
        rng: RngType,

        /// Suppress extra output, show only key and address
        #[arg(short, long, default_value_t = false)]
        quiet: bool,
    },
    /// Derive address from an existing private key
    Derive {
        /// Blockchain type
        #[arg(short = 't', long = "type", value_enum, default_value_t = ChainType::Evm)]
        chain: ChainType,

        /// Private key (hex for EVM, base58 keypair for Solana). Reads from stdin if omitted
        private_key: Option<String>,

        /// Suppress extra output, show only address
        #[arg(short, long, default_value_t = false)]
        quiet: bool,
    },
    /// Search for vanity addresses with custom prefix/suffix
    Vanity {
        /// Blockchain type
        #[arg(short = 't', long = "type", value_enum, default_value_t = ChainType::Evm)]
        chain: ChainType,

        /// Address prefix to match (hex for EVM, base58 for Solana)
        #[arg(long)]
        prefix: Option<String>,

        /// Address suffix to match (hex for EVM, base58 for Solana)
        #[arg(long)]
        suffix: Option<String>,

        /// Number of threads to use (default: CPU count)
        #[arg(long)]
        threads: Option<usize>,

        /// Random number generator to use
        #[arg(short, long, value_enum, default_value_t = RngType::ThreadRng)]
        rng: RngType,

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
    /// Use incremental EC point addition (EVM only, fastest for vanity search)
    Incremental,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum ChainType {
    /// EVM-compatible (Ethereum, Polygon, BSC, etc.)
    Evm,
    /// Solana
    Solana,
}

fn main() {
    let cli = Cli::parse();

    match cli.mode {
        Mode::Generate { chain, rng, quiet } => {
            generate_key(chain, rng, quiet);
        }
        Mode::Derive { chain, private_key, quiet } => {
            derive_address(chain, private_key, quiet);
        }
        Mode::Vanity { chain, prefix, suffix, threads, rng, quiet } => {
            search_vanity(chain, prefix, suffix, threads, rng, quiet);
        }
    }
}

fn generate_key(chain: ChainType, rng_type: RngType, quiet: bool) {
    match rng_type {
        RngType::ThreadRng => {
            if !quiet {
                println!("Using: ThreadRng (ChaCha20)");
            }

            let thread_rng = ThreadRngFillBytes::new();
            let mut generator = RngPrivateKeyGenerator::new(thread_rng);

            match chain {
                ChainType::Evm => {
                    let key: EvmKey = generator.generate();
                    display_evm_key(&key, quiet);
                }
                ChainType::Solana => {
                    let key: SolanaKey = generator.generate();
                    display_solana_key(&key, quiet);
                }
            }
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

                match chain {
                    ChainType::Evm => {
                        let key: EvmKey = generator.generate();
                        display_evm_key(&key, quiet);
                    }
                    ChainType::Solana => {
                        let key: SolanaKey = generator.generate();
                        display_solana_key(&key, quiet);
                    }
                }
            }
        }
        RngType::Incremental => {
            match chain {
                ChainType::Evm => {
                    if !quiet {
                        println!("Using: Incremental (secp256k1 point addition)");
                    }
                    let mut generator = EvmIncrementalGenerator::new();
                    let (key, _) = generator.generate();
                    display_evm_key(&key, quiet);
                }
                ChainType::Solana => {
                    eprintln!("Error: --rng incremental is only supported for EVM (secp256k1)");
                    eprintln!("Use --rng thread-rng or --rng dev-random for Solana");
                    std::process::exit(1);
                }
            }
        }
    }
}

fn derive_address(chain: ChainType, private_key_opt: Option<String>, quiet: bool) {
    let private_key_str = match private_key_opt {
        Some(key) => key,
        None => {
            let stdin = io::stdin();

            if stdin.is_terminal() {
                eprint!("Enter private key: ");
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

    match chain {
        ChainType::Evm => {
            let private_key = match EvmKey::from_string(&private_key_str) {
                Some(key) => key,
                None => {
                    eprintln!("Error: Invalid EVM private key format");
                    eprintln!("\nExpected format: 0x-prefixed 64-character hex string");
                    eprintln!("Example: 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
                    std::process::exit(1);
                }
            };

            let address = private_key.derive_address();
            if quiet {
                println!("{}", address);
            } else {
                println!("Private Key: {}", private_key.to_string());
                println!("Address:     {}\n", address);
            }
        }
        ChainType::Solana => {
            let private_key = match SolanaKey::from_string(&private_key_str) {
                Some(key) => key,
                None => {
                    eprintln!("Error: Invalid Solana private key format");
                    eprintln!("\nAccepted formats:");
                    eprintln!("  - Base58-encoded 64-byte keypair (Phantom wallet export)");
                    eprintln!("  - Base58-encoded 32-byte seed");
                    eprintln!("  - 0x-prefixed 64-character hex string");
                    std::process::exit(1);
                }
            };

            let address = private_key.derive_address();
            if quiet {
                println!("{}", address);
            } else {
                println!("Private Key: {}", private_key.to_string());
                println!("Address:     {}\n", address);
            }
        }
    }
}

fn search_vanity(
    chain: ChainType,
    prefix: Option<String>,
    suffix: Option<String>,
    threads: Option<usize>,
    rng_type: RngType,
    quiet: bool,
) {
    if prefix.is_none() && suffix.is_none() {
        eprintln!("Error: Must specify at least --prefix or --suffix");
        eprintln!("Example: evm-account-generator vanity --prefix dead");
        std::process::exit(1);
    }

    #[cfg(not(target_family = "unix"))]
    if rng_type == RngType::DevRandom {
        eprintln!("Error: /dev/random is only available on Unix-like systems");
        eprintln!("Please use --rng thread-rng instead");
        std::process::exit(1);
    }

    if rng_type == RngType::Incremental && chain == ChainType::Solana {
        eprintln!("Error: --rng incremental is only supported for EVM (secp256k1)");
        eprintln!("Use --rng thread-rng or --rng dev-random for Solana");
        std::process::exit(1);
    }

    match chain {
        ChainType::Evm => search_vanity_evm(prefix, suffix, threads, rng_type, quiet),
        ChainType::Solana => search_vanity_solana(prefix, suffix, threads, rng_type, quiet),
    }
}

// ---------------------------------------------------------------------------
// EVM vanity search
// ---------------------------------------------------------------------------

fn search_vanity_evm(
    prefix: Option<String>,
    suffix: Option<String>,
    threads: Option<usize>,
    rng_type: RngType,
    quiet: bool,
) {
    let prefix_pattern = prefix.as_ref().map(|p| parse_hex_pattern(p, true));
    let suffix_pattern = suffix.as_ref().map(|s| parse_hex_pattern(s, false));

    let num_threads = threads.unwrap_or_else(|| {
        thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    });

    let search_space = calculate_hex_search_space(&prefix, &suffix);
    let expected_attempts = (search_space as f64 * 0.693).ceil() as u64;

    if !quiet {
        display_cpu_info(num_threads);
        println!();
        println!("Searching for EVM vanity address...");
        if let Some(ref p) = prefix {
            println!("  Prefix: {} ({} hex chars)", p, p.len());
        }
        if let Some(ref s) = suffix {
            println!("  Suffix: {} ({} hex chars)", s, s.len());
        }
        println!("  Threads: {}", num_threads);
        println!("  RNG: {}", rng_display_name(rng_type));
        println!("  Expected attempts (50% probability): {}", format_number(expected_attempts));
        println!();
    }

    let (result_tx, result_rx) = mpsc::channel();
    let (stats_tx, stats_rx) = mpsc::channel();
    let found = Arc::new(AtomicBool::new(false));
    let mut report_senders = vec![];

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
            let mut generate: Box<dyn FnMut() -> (EvmKey, EvmAddress)> = match rng_type {
                RngType::Incremental => {
                    let mut gen = EvmIncrementalGenerator::new();
                    Box::new(move || gen.generate())
                }
                RngType::ThreadRng => {
                    let mut gen = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
                    Box::new(move || {
                        let key: EvmKey = gen.generate();
                        let addr = key.derive_address();
                        (key, addr)
                    })
                }
                RngType::DevRandom => {
                    let mut gen = RngPrivateKeyGenerator::new(DevRandomRng::new());
                    Box::new(move || {
                        let key: EvmKey = gen.generate();
                        let addr = key.derive_address();
                        (key, addr)
                    })
                }
            };
            let mut count = 0u64;

            loop {
                if found.load(Ordering::Relaxed) {
                    return;
                }

                let (private_key, address) = generate();
                let addr_bytes = address.as_bytes();

                let prefix_match = prefix_pattern.as_ref().map_or(true, |(pattern, mask)| {
                    is_matching(&addr_bytes[..pattern.len()], pattern, mask)
                });

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

                if report_rx.try_recv().is_ok() {
                    stats_tx.send(count).ok();
                    count = 0;
                }
            }
        });

        handles.push(handle);
    }

    drop(result_tx);
    drop(stats_tx);

    vanity_progress_loop(
        result_rx,
        &stats_rx,
        &report_senders,
        start_time,
        expected_attempts,
        quiet,
        |key, quiet_mode| {
            if quiet_mode {
                println!("{}", key.to_string());
            } else {
                println!("Private Key: {}", key.to_string());
                println!("Address:     {}", key.derive_address());
            }
        },
    );

    for handle in handles {
        handle.join().ok();
    }
}

// ---------------------------------------------------------------------------
// Solana vanity search
// ---------------------------------------------------------------------------

const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn search_vanity_solana(
    prefix: Option<String>,
    suffix: Option<String>,
    threads: Option<usize>,
    rng_type: RngType,
    quiet: bool,
) {
    // Validate base58 characters
    if let Some(ref p) = prefix {
        validate_base58_pattern(p);
    }
    if let Some(ref s) = suffix {
        validate_base58_pattern(s);
    }

    let num_threads = threads.unwrap_or_else(|| {
        thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    });

    let search_space = calculate_base58_search_space(&prefix, &suffix);
    let expected_attempts = (search_space as f64 * 0.693).ceil() as u64;

    if !quiet {
        display_cpu_info(num_threads);
        println!();
        println!("Searching for Solana vanity address...");
        if let Some(ref p) = prefix {
            println!("  Prefix: {} ({} base58 chars)", p, p.len());
        }
        if let Some(ref s) = suffix {
            println!("  Suffix: {} ({} base58 chars)", s, s.len());
        }
        println!("  Threads: {}", num_threads);
        println!("  RNG: {}", rng_display_name(rng_type));
        println!("  Expected attempts (50% probability): {}", format_number(expected_attempts));
        println!();
    }

    let (result_tx, result_rx) = mpsc::channel();
    let (stats_tx, stats_rx) = mpsc::channel();
    let found = Arc::new(AtomicBool::new(false));
    let mut report_senders = vec![];

    let start_time = Instant::now();
    let mut handles = vec![];

    for thread_id in 0..num_threads {
        let result_tx = result_tx.clone();
        let stats_tx = stats_tx.clone();
        let found = Arc::clone(&found);
        let prefix = prefix.clone();
        let suffix = suffix.clone();

        let (report_tx, report_rx) = mpsc::channel();
        report_senders.push(report_tx);

        let handle = thread::spawn(move || {
            let mut generate: Box<dyn FnMut() -> SolanaKey> = match rng_type {
                RngType::ThreadRng => {
                    let mut gen = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());
                    Box::new(move || gen.generate())
                }
                RngType::DevRandom => {
                    let mut gen = RngPrivateKeyGenerator::new(DevRandomRng::new());
                    Box::new(move || gen.generate())
                }
                RngType::Incremental => unreachable!("validated in search_vanity"),
            };
            let mut count = 0u64;

            loop {
                if found.load(Ordering::Relaxed) {
                    return;
                }

                let private_key: SolanaKey = generate();
                let address = private_key.derive_address();
                let addr_str = address.to_string();

                let prefix_match = prefix.as_ref().map_or(true, |p| addr_str.starts_with(p.as_str()));
                let suffix_match = suffix.as_ref().map_or(true, |s| addr_str.ends_with(s.as_str()));

                if prefix_match && suffix_match {
                    found.store(true, Ordering::Relaxed);
                    result_tx.send((private_key, thread_id, count)).unwrap();
                    return;
                }

                count += 1;

                if report_rx.try_recv().is_ok() {
                    stats_tx.send(count).ok();
                    count = 0;
                }
            }
        });

        handles.push(handle);
    }

    drop(result_tx);
    drop(stats_tx);

    vanity_progress_loop(
        result_rx,
        &stats_rx,
        &report_senders,
        start_time,
        expected_attempts,
        quiet,
        |key, quiet_mode| {
            if quiet_mode {
                println!("{}", key.to_string());
            } else {
                println!("Private Key: {}", key.to_string());
                println!("Address:     {}", key.derive_address());
            }
        },
    );

    for handle in handles {
        handle.join().ok();
    }
}

fn validate_base58_pattern(pattern: &str) {
    for c in pattern.chars() {
        if !BASE58_ALPHABET.contains(c) {
            eprintln!("Error: Invalid base58 character '{}' in pattern: {}", c, pattern);
            eprintln!("Valid base58 characters: {}", BASE58_ALPHABET);
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Shared vanity progress loop
// ---------------------------------------------------------------------------

fn vanity_progress_loop<K>(
    result_rx: mpsc::Receiver<(K, usize, u64)>,
    stats_rx: &mpsc::Receiver<u64>,
    report_senders: &[mpsc::Sender<()>],
    start_time: Instant,
    expected_attempts: u64,
    quiet: bool,
    display_result: impl Fn(&K, bool),
) {
    let mut last_report = Instant::now();
    let mut total_checked = 0u64;

    loop {
        if let Ok((private_key, thread_id, final_count)) = result_rx.try_recv() {
            let elapsed = start_time.elapsed();
            total_checked += final_count;

            if !quiet {
                println!("\n\u{2713} Found by thread {}!", thread_id);
                println!("Time elapsed: {:.1} seconds", elapsed.as_secs_f64());
                println!("Keys checked: {}\n", format_number(total_checked));
            }
            display_result(&private_key, quiet);
            break;
        }

        if !quiet && last_report.elapsed() >= Duration::from_millis(500) {
            for sender in report_senders {
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
}

// ---------------------------------------------------------------------------
// EVM hex pattern matching helpers
// ---------------------------------------------------------------------------

fn parse_hex_pattern(pattern: &str, is_prefix: bool) -> (Vec<u8>, Vec<u8>) {
    let clean = pattern.strip_prefix("0x").unwrap_or(pattern);

    if !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        eprintln!("Error: Invalid hex pattern: {}", pattern);
        eprintln!("Pattern must contain only hex characters (0-9, a-f, A-F)");
        std::process::exit(1);
    }

    let is_odd_length = clean.len() % 2 == 1;

    let padded = if is_odd_length {
        if is_prefix {
            format!("{}0", clean)
        } else {
            format!("0{}", clean)
        }
    } else {
        clean.to_string()
    };

    let bytes: Vec<u8> = (0..padded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&padded[i..i+2], 16).unwrap())
        .collect();

    let mut mask = vec![0xFF; bytes.len()];
    if is_odd_length {
        if is_prefix {
            *mask.last_mut().unwrap() = 0xF0;
        } else {
            mask[0] = 0x0F;
        }
    }

    (bytes, mask)
}

fn is_matching(test: &[u8], pattern: &[u8], bitmask: &[u8]) -> bool {
    if test.len() != pattern.len() || test.len() != bitmask.len() {
        return false;
    }

    test.iter()
        .zip(pattern.iter())
        .zip(bitmask.iter())
        .all(|((t, p), m)| (t & m) == (p & m))
}

// ---------------------------------------------------------------------------
// Search space calculations
// ---------------------------------------------------------------------------

fn calculate_hex_search_space(prefix: &Option<String>, suffix: &Option<String>) -> u64 {
    let mut space = 1u64;
    if let Some(p) = prefix {
        space = space.saturating_mul(16u64.saturating_pow(p.len() as u32));
    }
    if let Some(s) = suffix {
        space = space.saturating_mul(16u64.saturating_pow(s.len() as u32));
    }
    space
}

fn calculate_base58_search_space(prefix: &Option<String>, suffix: &Option<String>) -> u64 {
    let mut space = 1u64;
    if let Some(p) = prefix {
        space = space.saturating_mul(58u64.saturating_pow(p.len() as u32));
    }
    if let Some(s) = suffix {
        space = space.saturating_mul(58u64.saturating_pow(s.len() as u32));
    }
    space
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

fn rng_display_name(rng_type: RngType) -> &'static str {
    match rng_type {
        RngType::ThreadRng => "ThreadRng (ChaCha20)",
        RngType::DevRandom => "/dev/random",
        RngType::Incremental => "Incremental (secp256k1 point addition)",
    }
}

fn display_evm_key(private_key: &EvmKey, quiet: bool) {
    if quiet {
        println!("{}", private_key.to_string());
    } else {
        println!("\n\u{2713} Successfully generated EVM account!\n");
        println!("Private Key: {}", private_key.to_string());
        println!("Address:     {}\n", private_key.derive_address());
    }
}

fn display_solana_key(private_key: &SolanaKey, quiet: bool) {
    if quiet {
        println!("{}", private_key.to_string());
    } else {
        println!("\n\u{2713} Successfully generated Solana account!\n");
        println!("Private Key (base58 keypair): {}", private_key.to_string());
        println!("Address:                      {}\n", private_key.derive_address());
    }
}

fn display_cpu_info(_threads_used: usize) {
    let mut sys = System::new();
    sys.refresh_cpu_all();

    let cpus = sys.cpus();
    if let Some(cpu) = cpus.first() {
        let cpu_name = cpu.brand().trim();
        let frequency = cpu.frequency();
        let arch = std::env::consts::ARCH;
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

fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else if seconds < 86400 {
        format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
    } else {
        format!("{}d {}h", seconds / 86400, (seconds % 86400) / 3600)
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
