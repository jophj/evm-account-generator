use evm_account_generator::{
    evm::{Address, PrivateKey as EvmKey},
    PrivateKey, PrivateKeyGenerator, RngPrivateKeyGenerator, ThreadRngFillBytes,
};
use std::{sync::mpsc, time::{Duration, Instant}};
use std::thread;

fn main() {
    let (tx, rx) = mpsc::channel();
    let (tx2, rx2) = mpsc::channel();

    thread::spawn(move || {
        let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());

        // let mut generator = SequentialPrivateKeyGenerator::new(random_generator.generate());

        let test_address: Address = Address::new([0u8; 20]);

        let mut count = 0;
        for i in 0..1500000 {
            let private_key: EvmKey = generator.generate();
            let address = private_key.derive_address();

            if address.eq(&test_address) {
                panic!("This should never happen");
            }
            // if (i % 10000) == 0 {
            //     tx.send(i).unwrap();
            // }

            count += 1;
            match rx2.try_recv() {
                Ok(_) => {
                    tx.send(count).unwrap();
                    count = 0;
                },
                Err(_) => continue,
            }
        }
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

    // for received in rx {
    //     let time_now = Instant::now();
    //     let duration = time_now.duration_since(time_start);
    //     println!("{} keys per second", received * 1000 / duration.as_millis());
    // }
}
