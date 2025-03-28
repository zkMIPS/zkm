#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;
use guest::verify_revm_tx;

zkm_runtime::entrypoint!(main);

pub fn main() {
    let input: Vec<u8> = zkm_runtime::io::read_vec();
    assert!(verify_revm_tx(&input));
}
