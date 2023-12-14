use crate::cpu::kernel::KERNEL;

const KERNEL_CONTEXT: usize = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistersState {
    pub gprs: [usize; 32],
    pub lo: usize,
    pub hi: usize,
    pub heap: usize,
    pub program_counter: usize,
    pub is_kernel: bool,
    pub context: usize,
    pub exited: bool,
    pub exit_code: u8,
}

impl RegistersState {
    pub(crate) fn code_context(&self) -> usize {
        if self.is_kernel {
            KERNEL_CONTEXT
        } else {
            self.context
        }
    }
}

impl Default for RegistersState {
    fn default() -> Self {
        Self {
            gprs: KERNEL.program.gprs,
            lo: KERNEL.program.lo,
            hi: KERNEL.program.hi,
            heap: KERNEL.program.heap,
            program_counter: KERNEL.program.entry as usize,
            is_kernel: true,
            context: 0,
            exited: false,
            exit_code: 0u8,
        }
    }
}
