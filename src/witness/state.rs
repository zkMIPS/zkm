use crate::cpu::kernel::KERNEL;

const KERNEL_CONTEXT: usize = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistersState {
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
            program_counter: 0,
            is_kernel: true,
            context: 0,
        }
    }
}
