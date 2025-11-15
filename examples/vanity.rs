use evm_account_generator::{
    evm::PrivateKey as EvmKey, PrivateKey, PrivateKeyGenerator, RngPrivateKeyGenerator,
    ThreadRngFillBytes,
};
use std::thread;
use std::{
    sync::mpsc,
    time::{Duration, Instant},
};

fn main() {
    let (tx, rx) = mpsc::channel();
    let (tx2, rx2) = mpsc::channel();

    thread::spawn(move || {
        let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());

        let prefix = [0x69];
        let prefix_mask = [0xFF];
        let suffix = [0x04, 0x20];
        let suffix_mask = [0x0F, 0xFF];

        let mut private_key: EvmKey = generator.generate();
        let mut count = 0;
        loop {
            let address = private_key.derive_address();
            let addr_bytes = address.as_bytes();

            // Check prefix (first bytes)
            let prefix_match = is_matching(&addr_bytes[..prefix.len()], &prefix, &prefix_mask);
            // Check suffix (last bytes)
            let suffix_match = is_matching(&addr_bytes[addr_bytes.len() - suffix.len()..], &suffix, &suffix_mask);

            if prefix_match && suffix_match {
                break;
            }
            private_key = generator.generate();

            count += 1;
            match rx2.try_recv() {
                Ok(_) => {
                    tx.send(count).unwrap();
                    count = 0;
                }
                Err(_) => (),
            }
        }

        println!("Found key: {}", private_key.to_string());
        println!("Address: {}", private_key.derive_address());
    });

    let mut time_start = Instant::now();
    while tx2.send(0).is_ok() {
        thread::sleep(Duration::from_millis(500));
        let received = rx.recv().unwrap();
        let time_now = Instant::now();
        let duration = time_now.duration_since(time_start);
        println!("{} keys per second", received * 1000 / duration.as_millis());
        time_start = time_now;
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
