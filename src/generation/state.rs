use std::collections::HashMap;

use ethereum_types::{Address, BigEndianHash, H160, H256, U256};
use keccak_hash::keccak;
use plonky2::field::types::Field;

use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::context_metadata::ContextMetadata;
use crate::generation::mpt::all_mpt_prover_inputs_reversed;
use crate::generation::rlp::all_rlp_prover_inputs_reversed;
use crate::generation::GenerationInputs;
use crate::memory::segments::Segment;
use crate::witness::errors::ProgramError;
use crate::witness::memory::{MemoryAddress, MemoryState};
use crate::witness::state::RegistersState;
use crate::witness::traces::{TraceCheckpoint, Traces};

pub(crate) struct GenerationState {
    pub(crate) inputs: GenerationInputs,
    pub(crate) traces: Traces<F>,
}
