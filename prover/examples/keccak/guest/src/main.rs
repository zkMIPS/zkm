#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;

zkm_runtime::entrypoint!(main);

pub fn main() {
    let public_input: Vec<u8> = zkm_runtime::io::read();
    let input: Vec<u8> = zkm_runtime::io::read();

    let output = zkm_runtime::io::keccak(&input.as_slice()); 
    assert_eq!(output.to_vec(), public_input);
    zkm_runtime::io::commit::<[u8; 32]>(&output);
}
