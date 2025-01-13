#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Executes the Keccak256 permutation on the given state.
///
/// ### Safety
///
/// The caller must ensure that `state` is valid pointer to data that is aligned along a four
/// byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_sha256_compress(w: *mut u32, state: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "syscall",
            in("$2") crate::syscalls::SHA_COMPRESS,
            in("$4") w,
            in("$5") state,
        );
    }
}

#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_sha256_extend(w: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "syscall",
            in("$2") crate::syscalls::SHA_EXTEND,
            in("$4") w,
            in("$5") 0
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
