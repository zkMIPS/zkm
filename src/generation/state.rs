use std::collections::HashMap;

use ethereum_types::{Address, BigEndianHash, H160, H256, U256};
// use keccak_hash::keccak;
use plonky2::field::types::Field;

// use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::context_metadata::ContextMetadata;
use crate::generation::GenerationInputs;
use crate::memory::segments::Segment;
use crate::witness::errors::ProgramError;
use crate::witness::memory::{MemoryAddress, MemoryState};
use crate::witness::state::RegistersState;
use crate::witness::traces::{TraceCheckpoint, Traces};

pub(crate) struct GenerationStateCheckpoint {
    pub(crate) registers: RegistersState,
    pub(crate) traces: TraceCheckpoint,
}

pub(crate) struct GenerationState<F: Field> {
    pub(crate) inputs: GenerationInputs,
    pub(crate) registers: RegistersState,
    pub(crate) memory: MemoryState,
    pub(crate) traces: Traces<F>,
}

impl<F: Field> GenerationState<F> {
    pub(crate) fn new(inputs: GenerationInputs, kernel_code: &[u8]) -> Result<Self, ProgramError> {
        Ok(GenerationState {
            inputs,
            registers: Default::default(),
            memory: MemoryState::new(kernel_code),
            traces: Traces::default(),
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
}
