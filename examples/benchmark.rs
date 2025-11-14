use evm_account_generator::{
    PrivateKey, PrivateKeyGenerator, RngPrivateKeyGenerator, ThreadRngFillBytes, evm::{Address, PrivateKey as EvmKey}
};


fn main() {
    let mut generator = RngPrivateKeyGenerator::new(ThreadRngFillBytes::new());

    // let mut generator = SequentialPrivateKeyGenerator::new(random_generator.generate());
    let mut private_key: EvmKey = generator.generate();

    
    let test_address: Address = Address::new([0u8; 20]);
    
    for i in 0..1500000 {
        private_key = generator.generate();
        let address = private_key.derive_address();
        
        if address.eq(&test_address) {
            panic!("This should never happen");
        }
    }

    println!("{}", private_key.to_string());
}