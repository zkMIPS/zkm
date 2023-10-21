pub(crate) mod outputs;
use crate::generation::outputs::GenerationOutputs;
use crate::proof::{BlockHashes, BlockMetadata, ExtraBlockData, PublicValues, TrieRoots};
use anyhow::anyhow;
use ethereum_types::{Address, BigEndianHash, H256, U256};
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::RichField;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::all_stark::{AllStark, NUM_TABLES};
use crate::config::StarkConfig;
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::bootstrap_kernel::generate_bootstrap_kernel;
use crate::cpu::kernel::KERNEL;
use crate::generation::state::GenerationState;

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct TraceRecord {
    curr: MipsTrace,
    next: MipsTrace,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct MipsTrace {
	pub cycle: u32,
	pub pc: u32,
	pub next_pc: u32,
	pub lo: u32,
	pub hi: u32,
	pub regs: [u32; 32],
	pub heap: u32,
	pub exit_code: u8,
	pub exited: bool,
	pub mem_addr: u32,
	pub insn_addr: u32,
}


/// Inputs needed for trace generation. Wrap the trace record.
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct GenerationInputs {
    mips_traces: Vec<TraceRecord>
}

pub fn generate_traces<F: RichField + Extendable<D>, const D: usize>(
    all_stark: &AllStark<F, D>,
    inputs: GenerationInputs,
    config: &StarkConfig,
    timing: &mut TimingTree,
) -> anyhow::Result<(
    [Vec<PolynomialValues<F>>; NUM_TABLES],
    PublicValues,
    GenerationOutputs,
)> {
    panic!("Unimpls");
    // Decode the trace record
    // 1. Decode instruction and fill in cpu columns
    // 2. Decode memory and fill in memory columns
    let mut state = GenerationState::<F>::new(&inputs.clone(), &KERNEL.code);
    generate_bootstrap_kernel(&mut state);

    // Execute the trace record

    // Generate the public values and outputs
}
