// use keccak_hash::keccak;
use plonky2::field::types::Field;

use crate::cpu::kernel::assembler::Kernel;
use crate::witness::errors::ProgramError;
use crate::witness::memory::MemoryState;
use crate::witness::state::RegistersState;
use crate::witness::traces::{TraceCheckpoint, Traces};

pub(crate) struct GenerationStateCheckpoint {
    pub(crate) registers: RegistersState,
    pub(crate) traces: TraceCheckpoint,
}

#[derive(Clone)]
pub(crate) struct GenerationState<F: Field> {
    pub(crate) registers: RegistersState,
    pub(crate) memory: MemoryState,
    pub(crate) traces: Traces<F>,
    pub(crate) step: usize,
}

impl<F: Field> GenerationState<F> {
    pub(crate) fn new(step: usize, kernel: &Kernel) -> Result<Self, ProgramError> {
        Ok(GenerationState {
            registers: RegistersState::new(kernel),
            memory: MemoryState::new(&[]), // FIXME
            traces: Traces::default(),
            step,
        })
    }

    pub fn checkpoint(&self) -> GenerationStateCheckpoint {
        GenerationStateCheckpoint {
            registers: self.registers,
            traces: self.traces.checkpoint(),
        }
    }

    pub fn rollback(&mut self, checkpoint: GenerationStateCheckpoint) {
        self.registers = checkpoint.registers;
        self.traces.rollback(checkpoint.traces);
    }

    /// Updates `program_counter`, and potentially adds some extra handling if we're jumping to a
    /// special location.
    pub fn jump_to(&mut self, dst: usize) {
        self.registers.program_counter = self.registers.next_pc;
        self.registers.next_pc = dst;
    }
}
