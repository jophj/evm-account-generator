use evm_account_generator::{
    evm::PrivateKey as EvmKey, PrivateKey, PrivateKeyGenerator, RngPrivateKeyGenerator,
    ThreadRngFillBytes,
};
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};
use std::thread;
use std::{
    sync::mpsc,
    time::{Duration, Instant},
};

fn main() {
    let num_threads = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    
    println!("Spawning {} threads (one per CPU core)", num_threads);

    let (result_tx, result_rx) = mpsc::channel();
    let (stats_tx, stats_rx) = mpsc::channel();
    
    let found = Arc::new(AtomicBool::new(false));

    // Create report request channels for each thread
    let mut report_senders = vec![];

    // Spawn worker threads
    let mut handles = vec![];
    for thread_id in 0..num_threads {
        let result_tx = result_tx.clone();
        let stats_tx = stats_tx.clone();
        let found = Arc::clone(&found);
        
        // Create a channel for report requests to this specific thread
        let (report_tx, report_rx) = mpsc::channel();
        report_senders.push(report_tx);
        
        let handle = thread::spawn(move || {
            let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());

            let prefix = [0x69, 0x42, 0x20];
            let prefix_mask = [0xFF, 0xFF, 0xF0];
            let suffix = [0x04, 0x20];
            let suffix_mask = [0x0F, 0xFF];

            let mut private_key: EvmKey = generator.generate();
            let mut count = 0;
            
            loop {
                // Check if another thread already found a match
                if found.load(Ordering::Relaxed) {
                    return;
                }
                
                let address = private_key.derive_address();
                let addr_bytes = address.as_bytes();

                // Check prefix (first bytes)
                let prefix_match = is_matching(&addr_bytes[..prefix.len()], &prefix, &prefix_mask);
                // Check suffix (last bytes)
                let suffix_match = is_matching(&addr_bytes[addr_bytes.len() - suffix.len()..], &suffix, &suffix_mask);

                if prefix_match && suffix_match {
                    found.store(true, Ordering::Relaxed);
                    result_tx.send((private_key.clone(), thread_id)).unwrap();
                    return;
                }
                
                private_key = generator.generate();
                count += 1;

                // Check for report request from main thread
                match report_rx.try_recv() {
                    Ok(_) => {
                        stats_tx.send(count).ok();
                        count = 0;
                    }
                    Err(_) => (),
                }
            }
        });
        
        handles.push(handle);
    }

    // Drop the original senders so channels close when all threads are done
    drop(result_tx);
    drop(stats_tx);

    // Stats reporting loop
    let mut time_start = Instant::now();
    loop {
        // Check if we found a result
        if let Ok((private_key, thread_id)) = result_rx.try_recv() {
            println!("\n✓ Found by thread {}!", thread_id);
            println!("Private key: {}", private_key.to_string());
            println!("Address: {}", private_key.derive_address());
            break;
        }

        // Send report requests to all threads
        for sender in &report_senders {
            sender.send(()).ok();
        }

        thread::sleep(Duration::from_millis(500));

        // Collect stats from all threads
        let mut total_count = 0;
        while let Ok(count) = stats_rx.try_recv() {
            total_count += count;
        }

        if total_count > 0 {
            let time_now = Instant::now();
            let duration = time_now.duration_since(time_start);
            let keys_per_sec = (total_count as u128 * 1000) / duration.as_millis().max(1);
            println!("{} keys/sec across {} threads", keys_per_sec, num_threads);
            time_start = time_now;
        }
    }

    // Wait for all threads to finish
    for handle in handles {
        handle.join().ok();
    }
}

/// Checks if bits in `test` match bits in `pattern` where `bitmask` has 1s.
/// 
/// For each byte position:
/// - (test[i] & bitmask[i]) == (pattern[i] & bitmask[i])
/// 
/// Returns false if arrays have different lengths.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitmask() {
        // Exact match with full mask
        assert_eq!(is_matching(&[0x04], &[0x04], &[0xFF]), true);
        
        // Match only lower nibble (0x0F mask)
        assert_eq!(is_matching(&[0x04], &[0x14], &[0x0F]), true);
        assert_eq!(is_matching(&[0x14], &[0x24], &[0x0F]), true);
        
        // Match with empty mask (all bits ignored)
        assert_eq!(is_matching(&[0xA4], &[0x4A], &[0x00]), true);
        assert_eq!(is_matching(&[0x12], &[0x34], &[0x00]), true);
        
        // No match with full mask
        assert_eq!(is_matching(&[0x14], &[0x04], &[0xFF]), false);
        assert_eq!(is_matching(&[0x04], &[0x05], &[0xFF]), false);

        // Multi-byte matching
        assert_eq!(
            is_matching(&[0xA4, 0x20], &[0xF4, 0x20], &[0x0F, 0xFF]),
            true
        );

        // Match only upper nibble (0xF0 mask)
        assert_eq!(is_matching(&[0xA4], &[0xA0], &[0xF0]), true);
        assert_eq!(is_matching(&[0xA4], &[0xB0], &[0xF0]), false);
        
        // Different lengths should return false
        assert_eq!(is_matching(&[0x04, 0x05], &[0x04], &[0xFF]), false);
    }
}
