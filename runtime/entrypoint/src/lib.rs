//! Ported from Entrypoint for SP1 zkVM.
#![feature(asm_experimental_arch)]
pub mod heap;
pub mod syscalls;
pub mod io {
    pub use zkm_precompiles::io::*;
}
pub mod precompiles {
    pub use zkm_precompiles::*;
}

extern crate alloc;

#[macro_export]
macro_rules! entrypoint {
    ($path:path) => {
        const ZKVM_ENTRY: fn() = $path;

        use $crate::heap::SimpleAlloc;

        #[global_allocator]
        static HEAP: SimpleAlloc = SimpleAlloc;

        mod zkvm_generated_main {

            #[no_mangle]
            fn start() {
                super::ZKVM_ENTRY()
            }
        }
    };
}

mod libm;

/// The number of 32 bit words that the public values digest is composed of.
pub const PV_DIGEST_NUM_WORDS: usize = 8;
pub const POSEIDON_NUM_WORDS: usize = 8;

#[cfg(target_os = "zkvm")]
mod zkvm {
    use crate::syscalls::{sys_rand, syscall_halt};

    use bytemuck;
    use getrandom::{register_custom_getrandom, Error};
    use sha2::{Digest, Sha256};

    pub static mut PUBLIC_VALUES_HASHER: Option<Sha256> = None;

    #[cfg(not(feature = "interface"))]
    #[no_mangle]
    fn main() {
        unsafe {
            PUBLIC_VALUES_HASHER = Some(Sha256::new());

            extern "C" {
                fn start();
            }
            start()
        }

        syscall_halt(0);
    }

    core::arch::global_asm!(include_str!("memset.s"));
    core::arch::global_asm!(include_str!("memcpy.s"));

    fn zkvm_getrandom(s: &mut [u8]) -> Result<(), Error> {
        if s.is_empty() {
            return Ok(());
        }

        let (head, aligned, tail) = bytemuck::pod_align_to_mut::<_, u32>(s);

        // Fill the aligned portion of the dest buffer with random words.
        // sys_rand uses copy-in to fill the buffer at 4-words per cycle.
        if aligned.len() > 0 {
            unsafe {
                sys_rand(aligned.as_mut_ptr(), aligned.len());
            }
        }

        // Up to 4 bytes may be split between the head and tail.
        // Sample an additional word and do an unaligned write to fill the last parts.
        if head.len() > 0 || tail.len() > 0 {
            assert!(head.len() < 4);
            assert!(tail.len() < 4);

            let mut words = [0u32; 2];
            unsafe {
                sys_rand(words.as_mut_ptr(), 2);
            }

            head.copy_from_slice(&words[0].to_ne_bytes()[..head.len()]);
            tail.copy_from_slice(&words[1].to_ne_bytes()[..tail.len()]);
        }
        Ok(())
    }

    register_custom_getrandom!(zkvm_getrandom);
}
