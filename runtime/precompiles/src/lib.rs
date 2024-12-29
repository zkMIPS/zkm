//! Ported from Precompiles for SP1 zkVM.
//!
//! Specifically, this crate contains user-friendly functions that call SP1 syscalls. Syscalls are
//! also declared here for convenience. In order to avoid duplicate symbol errors, the syscall
//! function impls must live in sp1-zkvm, which is only imported into the end user program crate.
//! In contrast, sp1-precompiles can be imported into any crate in the dependency tree.

pub mod io;
pub mod utils;

pub const BIGINT_WIDTH_WORDS: usize = 8;

extern "C" {
    pub fn syscall_halt(exit_code: u8) -> !;
    pub fn syscall_write(fd: u32, write_buf: *const u8, nbytes: usize);
    pub fn syscall_hint_len() -> usize;
    pub fn syscall_hint_read(ptr: *mut u8, len: usize);
    pub fn sys_alloc_aligned(bytes: usize, align: usize) -> *mut u8;
    pub fn syscall_verify(claim_digest: &[u8; 32]);
}
