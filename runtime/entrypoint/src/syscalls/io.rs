//! Ported from Entrypoint for SP1 zkVM.

cfg_if::cfg_if! {
    if #[cfg(target_os = "zkvm")] {
        use core::arch::asm;
    }
}

/// Write data to the prover.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_write(fd: u32, write_buf: *const u8, nbytes: usize) {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "zkvm")] {
            unsafe {
                asm!(
                    "syscall",
                    in("$2") crate::syscalls::WRITE,
                    in("$4") fd,
                    in("$5") write_buf,
                    in("$6") nbytes,
                );
            }
        } else {
            unreachable!()
        }
    }
}

#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_hint_len() -> usize {
    #[cfg(target_os = "zkvm")]
    unsafe {
        let len;
        asm!(
            "syscall",
            in("$2") crate::syscalls::HINT_LEN,
            lateout("$2") len,
        );
        len
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_hint_read(ptr: *mut u8, len: usize) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "syscall",
            in("$2") crate::syscalls::HINT_READ,
            in("$4") ptr,
            in("$5") len,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_verify(claim_digest: &[u8; 32]) {
    let mut to_host = [0u8; 32];
    to_host[..32].copy_from_slice(claim_digest);

    cfg_if::cfg_if! {
        if #[cfg(target_os = "zkvm")] {
            unsafe {
                asm!(
                    "syscall",
                    in("$2") crate::syscalls::VERIFY,
                    in("$5") to_host.as_ptr() as u32,
                    in("$6") 32u32,
                )
            }
        } else {
            unreachable!()
        }
    }
}
