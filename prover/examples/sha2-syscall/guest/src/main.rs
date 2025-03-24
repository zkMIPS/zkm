#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;

pub use digest::{self, Digest};

#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
use digest::{
    consts::{U28, U32},
    core_api::{CoreWrapper, CtVariableCoreWrapper},
    impl_oid_carrier,
};

#[rustfmt::skip]
mod consts;
mod core_api;

pub use core_api::{compress256, Sha256VarCore};

impl_oid_carrier!(OidSha256, "2.16.840.1.101.3.4.2.1");
impl_oid_carrier!(OidSha224, "2.16.840.1.101.3.4.2.4");

/// SHA-224 hasher.
pub type Sha224 = CoreWrapper<CtVariableCoreWrapper<Sha256VarCore, U28, OidSha224>>;
/// SHA-256 hasher.
pub type Sha256 = CoreWrapper<CtVariableCoreWrapper<Sha256VarCore, U32, OidSha256>>;


zkm_runtime::entrypoint!(main);

pub fn main() {
    let public_input: Vec<u8> = zkm_runtime::io::read();
    let input: Vec<u8> = zkm_runtime::io::read();

    let result = Sha256::digest(input);

    let output: [u8; 32] = result.into();
    assert_eq!(output.to_vec(), public_input);

    zkm_runtime::io::commit::<[u8; 32]>(&output);
}
