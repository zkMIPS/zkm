//! Ported from Entrypoint for SP1 zkVM.

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(target_os = "zkvm")] {
        use core::arch::asm;
    }
}

/// Halts the program.
#[allow(unused_variables)]
pub extern "C" fn syscall_halt(exit_code: u8) -> ! {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "syscall",
            in("$2") crate::syscalls::HALT,
            in("$4") exit_code
        );
        unreachable!()
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
