//! Ported from Precompiles for SP1 zkVM.

#![allow(unused_unsafe)]
use crate::syscall_keccak;
use crate::syscall_verify;
use crate::syscall_write;
use crate::{syscall_hint_len, syscall_hint_read};
use crate::{syscall_sha256_compress, syscall_sha256_extend};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::alloc::Layout;
use std::io::Write;

const FD_HINT: u32 = 4;
pub const FD_PUBLIC_VALUES: u32 = 3;
pub const ZERO: [u8; 32] = [0u8; 32];

#[allow(dead_code)]
pub struct SyscallWriter {
    fd: u32,
}

impl std::io::Write for SyscallWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let nbytes = buf.len();
        let write_buf = buf.as_ptr();
        unsafe {
            syscall_write(self.fd, write_buf, nbytes);
        }
        Ok(nbytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn read_vec() -> Vec<u8> {
    let len = unsafe { syscall_hint_len() };
    // Round up to the nearest multiple of 4 so that the memory allocated is in whole words
    let capacity = (len + 3).div_ceil(4) * 4;

    // Allocate a buffer of the required length that is 4 byte aligned
    let layout = Layout::from_size_align(capacity, 4).expect("vec is too large");
    let ptr = unsafe { std::alloc::alloc(layout) };
    // SAFETY:
    // 1. `ptr` was allocated using alloc
    // 2. We assuume that the VM global allocator doesn't dealloc
    // 3/6. Size is correct from above
    // 4/5. Length is 0
    // 7. Layout::from_size_align already checks this
    let mut vec = unsafe { Vec::from_raw_parts(ptr, 0, capacity) };
    // Read the vec into uninitialized memory. The syscall assumes the memory is uninitialized,
    // which should be true because the allocator does not dealloc, so a new alloc should be fresh.
    unsafe {
        syscall_hint_read(ptr, len);
        vec.set_len(len);
    }
    vec
}

pub fn read<T: DeserializeOwned>() -> T {
    let vec = read_vec();
    bincode::deserialize(&vec).expect("deserialization failed")
}

pub fn commit_slice(buf: &[u8]) {
    let mut my_writer: SyscallWriter = SyscallWriter {
        fd: FD_PUBLIC_VALUES,
    };
    my_writer.write_all(buf).unwrap();
}

pub fn commit<T: Serialize>(value: &T) {
    let mut buf = Vec::new();
    bincode::serialize_into(&mut buf, value).expect("serialization failed");
    commit_slice(buf.as_slice());
}

pub fn verify<T: Serialize>(image_id: Vec<u8>, public_input: &T) {
    let mut buf = Vec::new();
    bincode::serialize_into(&mut buf, public_input).expect("serialization failed");

    let mut hasher = Sha256::new();
    hasher.update(image_id);
    hasher.update(buf);
    let digest: [u8; 32] = hasher.finalize().into();

    unsafe { syscall_verify(&digest) }
}

pub fn hint_slice(buf: &[u8]) {
    let mut my_reader: SyscallWriter = SyscallWriter { fd: FD_HINT };
    my_reader.write_all(buf).unwrap();
}

pub fn hint<T: Serialize>(value: &T) {
    let mut buf = Vec::new();
    bincode::serialize_into(&mut buf, value).expect("serialization failed");
    hint_slice(buf.as_slice());
}

/// Write the data `buf` to the file descriptor `fd` using `Write::write_all` .
pub fn write(fd: u32, buf: &[u8]) {
    SyscallWriter { fd }.write_all(buf).unwrap();
}

/// Write the data `buf` to the file descriptor `fd` using `Write::write_all` .
pub fn print(buf: Vec<u8>) {
    SyscallWriter { fd: 2u32 }
        .write_all(buf.as_slice())
        .unwrap();
}

pub fn keccak(data: &[u8]) -> [u8; 32] {
    let len = data.len();
    let mut u32_array = Vec::new();

    if len == 0 {
        return [
            0xC5, 0xD2, 0x46, 0x01, 0x86, 0xF7, 0x23, 0x3C, 0x92, 0x7E, 0x7D, 0xB2, 0xDC, 0xC7,
            0x03, 0xC0, 0xE5, 0, 0xB6, 0x53, 0xCA, 0x82, 0x27, 0x3B, 0x7B, 0xFA, 0xD8, 0x04, 0x5D,
            0x85, 0xA4, 0x70,
        ];
    }

    // covert to u32 to align the memory
    for i in (0..len).step_by(4) {
        if i + 4 <= len {
            let u32_value = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            u32_array.push(u32_value);
        } else {
            let mut padded_chunk = [0u8; 4];
            padded_chunk[..len - i].copy_from_slice(&data[i..]);
            padded_chunk[len - i] = 1;
            let end = len % 136;
            if end + 4 > 136 {
                padded_chunk[3] |= 0x80;
            }
            let u32_value = u32::from_be_bytes(padded_chunk);
            u32_array.push(u32_value);
        }
    }

    let mut result = [0u8; 32];
    // Read the vec into uninitialized memory. The syscall assumes the memory is uninitialized,
    // which should be true because the allocator does not dealloc, so a new alloc should be fresh.
    unsafe {
        syscall_keccak(u32_array.as_ptr(), len, result.as_mut_ptr());
    }
    result
}

pub fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    unsafe {
        for block in blocks {
            let mut w = [0u32; 64];
            for (j, item) in w.iter_mut().enumerate().take(16) {
                *item = u32::from_be_bytes([
                    block[j * 4],
                    block[j * 4 + 1],
                    block[j * 4 + 2],
                    block[j * 4 + 3],
                ]);
            }
            syscall_sha256_extend(w.as_mut_ptr());
            syscall_sha256_compress(w.as_mut_ptr(), state.as_mut_ptr());
        }
    }
}
