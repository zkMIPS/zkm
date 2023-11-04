pub(crate) mod outputs;
pub(crate) mod state;
// use crate::proof::{BlockHashes, BlockMetadata, ExtraBlockData, PublicValues, MemsRoot};
use crate::proof::{MemsRoot, PublicValues};
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
use crate::cpu::bootstrap_kernel::generate_bootstrap_kernel;
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::kernel::KERNEL;
use crate::generation::outputs::{get_outputs, GenerationOutputs};
use crate::generation::state::GenerationState;
use crate::witness::transition::transition;

/// Inputs needed for trace generation. Wrap the trace record.
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct GenerationInputs {
    // Code, does not need to be trace record, can be a whole MIPS ELF?
    // Memory image
    // pre_image: HashMap<>,
    // memory: Vec<u8>,
    // mem_root: [u32; 8],
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
    // Decode the trace record
    // 1. Decode instruction and fill in cpu columns
    // 2. Decode memory and fill in memory columns
    let mut state = GenerationState::<F>::new(inputs.clone(), &KERNEL.code, 2).unwrap();
    generate_bootstrap_kernel::<F>(&mut state);

    timed!(timing, "simulate CPU", simulate_cpu(&mut state)?);

    log::info!(
        "Trace lengths (before padding): {:?}",
        state.traces.get_lengths()
    );

    let outputs = get_outputs(&mut state)
        .map_err(|err| anyhow!("Failed to generate post-state info: {:?}", err))?;

    // Execute the trace record

    // Generate the public values and outputs
    // FIXME: get the right merkle root
    let public_values = PublicValues {
        roots_before: MemsRoot { root: 0 },
        roots_after: MemsRoot { root: 0 },
    };
    let tables = timed!(
        timing,
        "convert trace data to tables",
        state.traces.into_tables(all_stark, config, timing)
    );
    Ok((tables, public_values, outputs))
}

/// Perform MIPS instruction and transit state
fn simulate_cpu<F: RichField + Extendable<D>, const D: usize>(
    state: &mut GenerationState<F>,
) -> anyhow::Result<()> {
    let mut step = 0;
    loop {
        // If we've reached the kernel's halt routine, and our trace length is a power of 2, stop.
        let pc = state.registers.program_counter;
        let halt = state.registers.is_kernel && step == state.step;
        println!("PC: {pc}");
        if halt {
            log::info!("CPU halted after {} cycles", state.traces.clock());

            // Padding
            let mut row = CpuColumnsView::<F>::default();
            row.clock = F::from_canonical_usize(state.traces.clock());
            row.context = F::from_canonical_usize(state.registers.context);
            row.program_counter = F::from_canonical_usize(pc);
            row.is_kernel_mode = F::ONE;

            loop {
                state.traces.push_cpu(row);
                row.clock += F::ONE;
                if state.traces.clock().is_power_of_two() {
                    break;
                }
            }
            log::info!("CPU trace padded to {} cycles", state.traces.clock());

            return Ok(());
        }

        transition(state)?;
        step += 1;
    }
}
