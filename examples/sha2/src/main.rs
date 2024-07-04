#![no_std]
#![no_main]

use sha2::{Digest, Sha256};
extern crate alloc;
use alloc::vec::Vec;

zkm_runtime::entrypoint!(main);

pub fn main() {
    let input: Vec<u8> = zkm_runtime::io::read();

    let mut hasher = Sha256::new();
    hasher.update(input);
    let _result = hasher.finalize();
}
