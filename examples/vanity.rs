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
        let suffix = [0x69];

        let mut private_key: EvmKey = generator.generate();
        let mut count = 0;
        loop {
            let address = private_key.derive_address();

            if is_matching(address.as_bytes(), &prefix, &[0xF0], false)
                && is_matching(address.as_bytes(), &suffix, &[0x0F], true)
            {
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
    while (tx2.send(0).is_ok()) {
        thread::sleep(Duration::from_millis(500));
        let received = rx.recv().unwrap();
        let time_now = Instant::now();
        let duration = time_now.duration_since(time_start);
        println!("{} keys per second", received * 1000 / duration.as_millis());
        time_start = time_now;
    }
}

fn is_matching(test: &[u8], pattern: &[u8], bitmask: &[u8], from_right: bool) -> bool {
    let slice = if from_right {
        &test[pattern.len()..]
    } else {
        &test[..pattern.len()]
    };

    let nor = slice
        .iter()
        .zip(pattern.iter())
        .map(|(a, b)| !(a ^ b))
        .collect::<Vec<u8>>();
    let masked = nor
        .iter()
        .zip(bitmask.iter())
        .map(|(a, b)| a & b)
        .collect::<Vec<u8>>();

    let mut is_matching = true;

    if from_right {
        let mut current = 0x00;
        for b in masked {
            if b == current {
                continue;
            } else if b == 0x0F || b == 0xFF {
                current = 0xFF;
                continue;
            } else {
                is_matching = false;
                break;
            }
        }
        return is_matching;
    } else {
        let mut current = 0xFF;
        for b in masked {
            if b == current {
                continue;
            } else if b == 0xF0 || b == 0x00 {
                current = 0x00;
                continue;
            } else {
                is_matching = false;
                break;
            }
        }
        return is_matching;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitmask() {
        assert_eq!(is_matching(&[0x04], &[0x04], &[0xFF], true), true);
        assert_eq!(is_matching(&[0x04], &[0x14], &[0x0F], true), true);
        // assert_eq!(is_matching(&[0x14], &[0x14], &[0x0F], true), true);
        // assert_eq!(is_matching(&[0xA4], &[0x4A], &[0x00], true), true);
        // assert_eq!(is_matching(&[0x14], &[0x04], &[0xFF], true), false);
        // assert_eq!(is_matching(&[0x04], &[0x05], &[0xFF], true), false);

        // assert_eq!(is_matching(&[0x12], &[0x34], &[0x00], true), true);
        // assert_eq!(is_matching(&[0x12], &[0x34], &[0x00], false), true);

        // assert_eq!(
        //     is_matching(&[0xA4, 0x20], &[0xF4, 0x20], &[0x0f, 0xff], true),
        //     true
        // );

        // assert_eq!(is_matching(&[0xA4], &[0xA0], &[0xF0], false), true);
        // assert_eq!(is_matching(&[0xA4], &[0xA0], &[0xF0], true), false);
    }
}
