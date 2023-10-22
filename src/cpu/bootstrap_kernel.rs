use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::kernel::KERNEL;
use crate::cpu::membus::NUM_GP_CHANNELS;
use crate::generation::state::GenerationState;
use crate::memory::segments::Segment;
use crate::witness::memory::MemoryAddress;
use crate::witness::util::mem_write_gp_log_and_fill;

pub(crate) fn generate_bootstrap_kernel<F: Field>(state: &mut GenerationState<F>) {
    // Iterate through chunks of the code, such that we can write one chunk to memory per row.
    for chunk in &KERNEL.code.iter().enumerate().chunks(NUM_GP_CHANNELS) {
        let mut cpu_row = CpuColumnsView::default();
        cpu_row.clock = F::from_canonical_usize(state.traces.clock());
        cpu_row.is_bootstrap_kernel = F::ONE;

        // Write this chunk to memory, while simultaneously packing its bytes into a u32 word.
        for (channel, (addr, &byte)) in chunk.enumerate() {
            let address = MemoryAddress::new(0, Segment::Code, addr);
            let write =
                mem_write_gp_log_and_fill(channel, address, state, &mut cpu_row, byte.into());
            state.traces.push_memory(write);
        }

        state.traces.push_cpu(cpu_row);
    }

    let mut final_cpu_row = CpuColumnsView::default();
    final_cpu_row.clock = F::from_canonical_usize(state.traces.clock());
    final_cpu_row.is_bootstrap_kernel = F::ONE;
    final_cpu_row.is_keccak_sponge = F::ONE;
    // The Keccak sponge CTL uses memory value columns for its inputs and outputs.
    final_cpu_row.mem_channels[0].value[0] = F::ZERO; // context
    final_cpu_row.mem_channels[1].value[0] = F::from_canonical_usize(Segment::Code as usize); // segment
    final_cpu_row.mem_channels[2].value[0] = F::ZERO; // virt
    final_cpu_row.mem_channels[3].value[0] = F::from_canonical_usize(KERNEL.code.len()); // len

    // final_cpu_row.mem_channels[4].value = KERNEL.code_hash.map(F::from_canonical_u32);
    // final_cpu_row.mem_channels[4].value.reverse();
    /*
    keccak_sponge_log(
        state,
        MemoryAddress::new(0, Segment::Code, 0),
        KERNEL.code.clone(),
    );
    */
    state.traces.push_cpu(final_cpu_row);
    state.traces.push_cpu(final_cpu_row);
    log::info!("Bootstrapping took {} cycles", state.traces.clock());
}
