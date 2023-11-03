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
            // FIXME: fill in pc
            gprs: Default::default(),
            lo: 0,
            hi: 0,
            heap: 0,
            program_counter: KERNEL.program.entry as usize,
            is_kernel: true,
            context: 0,
        }
    }
}
