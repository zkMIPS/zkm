use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(target_os = "zkvm")] {
        use core::arch::asm;
        use sha2::Digest;
        use crate::zkvm;
        use crate::{PV_DIGEST_NUM_WORDS, POSEIDON_NUM_WORDS};
    }
}

/// Halts the program.
#[allow(unused_variables)]
pub extern "C" fn syscall_halt(exit_code: u8) -> ! {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "syscall",
            in("v0") crate::syscalls::HALT,
            in("a0") exit_code
        );
        unreachable!()
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
