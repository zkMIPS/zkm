use crate::cpu::kernel::assembler::Kernel;
const KERNEL_CONTEXT: usize = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistersState {
    pub gprs: [usize; 32],
    pub lo: usize,
    pub hi: usize,
    pub heap: usize,
    pub program_counter: usize,
    pub next_pc: usize,
    pub brk: usize,
    pub local_user: usize,
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

impl RegistersState {
    pub fn new(kernel: &Kernel) -> Self {
        Self {
            gprs: kernel.program.gprs,
            lo: kernel.program.lo,
            hi: kernel.program.hi,
            heap: kernel.program.heap,
            program_counter: kernel.program.entry as usize,
            next_pc: kernel.program.next_pc,
            brk: kernel.program.brk,
            local_user: kernel.program.local_user,
            is_kernel: true,
            context: 0,
            exited: false,
            exit_code: 0u8,
        }
    }
}
