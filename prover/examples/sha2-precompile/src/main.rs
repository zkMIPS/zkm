#![no_std]
#![no_main]

use sha2::{Digest, Sha256};
extern crate alloc;
use alloc::vec::Vec;

zkm_runtime::entrypoint!(main);
const SHA_ELF:[u8; 32] = [83, 70, 149, 120, 71, 122, 247, 101, 174, 227, 186, 199, 6, 32, 152, 39, 176, 153, 148, 65, 154, 248, 140, 95, 163, 122, 249, 151, 112, 84, 68, 192];

pub fn main() {
    let public_input: Vec<u8> = zkm_runtime::io::read();
    let input: Vec<u8> = zkm_runtime::io::read();


    zkm_runtime::io::verify(SHA_ELF.to_vec(), &input);
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();

    let output: [u8; 32] = result.into();
    assert_eq!(output.to_vec(), public_input);

    zkm_runtime::io::commit::<[u8; 32]>(&output);
}
