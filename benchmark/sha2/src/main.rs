#![no_std]
#![no_main]

use sha2::{Digest, Sha256};
extern crate alloc;
use alloc::vec::Vec;

zkm_zkvm::entrypoint!(main);

pub fn main() {
    let input: Vec<u8> = zkm_zkvm::io::read();

    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();

    zkm_zkvm::io::commit::<[u8; 32]>(&result.into());
}
