pub(crate) mod outputs;
pub mod state;
use crate::generation::state::{AssumptionReceipts, AssumptionUsage};
use crate::proof::{MemRoots, PublicValues};
use anyhow::anyhow;
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::GenericConfig;
use plonky2::timed;
use plonky2::util::timing::TimingTree;

use crate::all_stark::NUM_PUBLIC_INPUT_USERDATA;
use crate::all_stark::{AllStark, NUM_TABLES};
use crate::config::StarkConfig;
use crate::cpu::bootstrap_kernel::generate_bootstrap_kernel;
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::kernel::assembler::Kernel;
use crate::generation::outputs::{get_outputs, GenerationOutputs};
use crate::generation::state::GenerationState;
use crate::witness::transition::transition;

use std::{cell::RefCell, rc::Rc};

pub fn generate_traces<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    all_stark: &AllStark<F, D>,
    kernel: &Kernel,
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
    let mut state = GenerationState::<F, C, D>::new(kernel.program.step, kernel).unwrap();
    generate_bootstrap_kernel::<F, C, D>(&mut state, kernel);

    timed!(timing, "simulate CPU", simulate_cpu(&mut state, kernel)?);

    log::info!(
        "Trace lengths (before padding): {:?}",
        state.traces.get_lengths()
    );

    let outputs = get_outputs(&mut state)
        .map_err(|err| anyhow!("Failed to generate post-state info: {:?}", err))?;

    // Execute the trace record

    // Generate the public values and outputs
    // let mut userdata = kernel.read_public_inputs();
    // assert!(userdata.len() <= NUM_PUBLIC_INPUT_USERDATA);
    // userdata.resize(NUM_PUBLIC_INPUT_USERDATA, 0u8);
    let userdata = kernel.read_public_inputs();

    assert!(userdata.len() == NUM_PUBLIC_INPUT_USERDATA);

    let public_values = PublicValues {
        roots_before: MemRoots {
            root: unsafe { std::mem::transmute::<[u8; 32], [u32; 8]>(kernel.program.pre_image_id) },
        },
        roots_after: MemRoots {
            root: unsafe { std::mem::transmute::<[u8; 32], [u32; 8]>(kernel.program.image_id) },
        },
        userdata,
    };
    let tables = timed!(
        timing,
        "convert trace data to tables",
        state.traces.into_tables(all_stark, config, timing)
    );
    Ok((tables, public_values, outputs))
}

pub fn generate_traces_with_assumptions<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    all_stark: &AllStark<F, D>,
    kernel: &Kernel,
    config: &StarkConfig,
    timing: &mut TimingTree,
    assumptions: AssumptionReceipts<F, C, D>,
) -> anyhow::Result<(
    [Vec<PolynomialValues<F>>; NUM_TABLES],
    PublicValues,
    GenerationOutputs,
    Rc<RefCell<AssumptionUsage<F, C, D>>>,
)> {
    // Decode the trace record
    // 1. Decode instruction and fill in cpu columns
    // 2. Decode memory and fill in memory columns
    let mut state = GenerationState::<F, C, D>::new(kernel.program.step, kernel).unwrap();
    for assumption in assumptions.iter() {
        state.add_assumption(assumption.clone());
    }
    generate_bootstrap_kernel::<F, C, D>(&mut state, kernel);

    timed!(timing, "simulate CPU", simulate_cpu(&mut state, kernel)?);

    log::info!(
        "Trace lengths (before padding): {:?}",
        state.traces.get_lengths()
    );

    let outputs = get_outputs(&mut state)
        .map_err(|err| anyhow!("Failed to generate post-state info: {:?}", err))?;

    // Execute the trace record

    // Generate the public values and outputs
    // let mut userdata = kernel.read_public_inputs();
    // assert!(userdata.len() <= NUM_PUBLIC_INPUT_USERDATA);
    // userdata.resize(NUM_PUBLIC_INPUT_USERDATA, 0u8);
    let userdata = kernel.read_public_inputs();

    assert!(userdata.len() == NUM_PUBLIC_INPUT_USERDATA);

    let public_values = PublicValues {
        roots_before: MemRoots {
            root: unsafe { std::mem::transmute::<[u8; 32], [u32; 8]>(kernel.program.pre_image_id) },
        },
        roots_after: MemRoots {
            root: unsafe { std::mem::transmute::<[u8; 32], [u32; 8]>(kernel.program.image_id) },
        },
        userdata,
    };
    let tables = timed!(
        timing,
        "convert trace data to tables",
        state.traces.into_tables(all_stark, config, timing)
    );
    Ok((tables, public_values, outputs, state.assumptions_used))
}

/// Perform MIPS instruction and transit state
pub(crate) fn simulate_cpu<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    state: &mut GenerationState<F, C, D>,
    kernel: &Kernel,
) -> anyhow::Result<()> {
    let mut step = 0;
    loop {
        // If we've reached the kernel's halt routine, and our trace length is a power of 2, stop.
        let pc = state.registers.program_counter;
        let halt = state.registers.is_kernel && (step == state.step || state.registers.exited);
        log::trace!("pc: {:X}", pc);
        if halt {
            log::info!("CPU halted after {} cycles", state.traces.clock());

            // FIXME: should be quit if not matching
            if step == state.step && pc != kernel.program.end_pc {
                log::error!(
                    "Segment split {} error at {:X} expected: {:X}",
                    step,
                    pc,
                    kernel.program.end_pc
                )
            }

            //generate_exit_kernel::<F>(state, kernel);

            // Padding
            let mut row = CpuColumnsView::<F>::default();
            row.clock = F::from_canonical_usize(state.traces.clock());
            row.context = F::from_canonical_usize(state.registers.context);
            row.program_counter = F::from_canonical_usize(pc);
            row.next_program_counter = F::from_canonical_usize(state.registers.next_pc);
            row.is_exit_kernel = F::ONE;

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

        transition(state, kernel)?;
        step += 1;
    }
}
