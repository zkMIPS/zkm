#![no_std]
#![no_main]

use sha2::{Digest, Sha256};
extern crate alloc;
use alloc::vec::Vec;

zkm_runtime::entrypoint!(main);
const SHA_ELF:[u8; 32] = [129, 12, 162, 243, 13, 71, 77, 130, 253, 215, 203, 135, 109, 246, 146, 134, 227, 92, 220, 161, 120, 228, 132, 97, 48, 91, 180, 2, 192, 82, 162, 109];

pub fn main() {
    let public_input: Vec<u8> = zkm_runtime::io::read();
    let input: [u8; 32] = zkm_runtime::io::read();


    zkm_runtime::io::verify(SHA_ELF.to_vec(), &input);
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();

    let output: [u8; 32] = result.into();
    assert_eq!(output.to_vec(), public_input);

    zkm_runtime::io::commit::<[u8; 32]>(&output);
}
