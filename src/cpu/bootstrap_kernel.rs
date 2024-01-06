use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::witness::util::keccak_sponge_log;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::kernel::assembler::Kernel;
use crate::cpu::membus::NUM_GP_CHANNELS;
use crate::generation::state::GenerationState;

use crate::memory::segments::Segment;
use crate::witness::memory::MemoryAddress;
use crate::witness::util::mem_write_gp_log_and_fill;

pub(crate) fn generate_bootstrap_kernel<F: Field>(state: &mut GenerationState<F>, kernel: &Kernel) {
    // Iterate through chunks of the code, such that we can write one chunk to memory per row.
    for chunk in &kernel.program.image.iter().chunks(NUM_GP_CHANNELS) {
        let mut cpu_row = CpuColumnsView::default();
        cpu_row.clock = F::from_canonical_usize(state.traces.clock());
        cpu_row.is_bootstrap_kernel = F::ONE;

        // Write this chunk to memory, while simultaneously packing its bytes into a u32 word.
        for (channel, (addr, val)) in chunk.enumerate() {
            // Both instruction and memory data are located in code section for MIPS
            let address = MemoryAddress::new(0, Segment::Code, *addr as usize);
            let write =
                mem_write_gp_log_and_fill(channel, address, state, &mut cpu_row, (*val).to_be());
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
    final_cpu_row.mem_channels[3].value[0] = F::from_canonical_usize(kernel.code.len()); // len
    final_cpu_row.mem_channels[4].value = kernel.code_hash.map(F::from_canonical_u32);
    final_cpu_row.mem_channels[4].value.reverse();
    keccak_sponge_log(
        state,
        MemoryAddress::new(0, Segment::Code, 0),
        kernel.code.clone(),
    );
    state.traces.push_cpu(final_cpu_row);

    state.memory.apply_ops(&state.traces.memory_ops);
    log::info!("Bootstrapping took {} cycles", state.traces.clock());
}

pub(crate) fn eval_bootstrap_kernel_packed<F: Field, P: PackedField<Scalar = F>>(
    local_values: &CpuColumnsView<P>,
    next_values: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    // IS_BOOTSTRAP_KERNEL must have an init value of 1, a final value of 0, and a delta in {0, -1}.
    let local_is_bootstrap = local_values.is_bootstrap_kernel;
    let next_is_bootstrap = next_values.is_bootstrap_kernel;
    yield_constr.constraint_first_row(local_is_bootstrap - P::ONES);
    yield_constr.constraint_last_row(local_is_bootstrap);
    let delta_is_bootstrap = next_is_bootstrap - local_is_bootstrap;
    yield_constr.constraint_transition(delta_is_bootstrap * (delta_is_bootstrap + P::ONES));

    // If this is a bootloading row and the i'th memory channel is used, it must have the right
    // address, name context = 0, segment = Code, virt + 4 = next_virt
    let code_segment = F::from_canonical_usize(Segment::Code as usize);
    for (_i, channel) in local_values.mem_channels.iter().enumerate() {
        let filter = local_is_bootstrap * channel.used;
        yield_constr.constraint(filter * channel.addr_context);
        yield_constr.constraint(filter * (channel.addr_segment - code_segment));
        /* FIXME
        let delta_virt = channel.addr_virtual + P::from(F::from_canonical_u32(32)) - next_values.mem_channels[i].addr_virtual;
        log::debug!("virt {:?} {:?} {:?} {:?} {}", channel.addr_virtual, delta_virt, local_values.clock, NUM_GP_CHANNELS, i);
        yield_constr.constraint_transition(filter * delta_virt);
        */
    }

    // If this is the final bootstrap row (i.e. delta_is_bootstrap = 1), check that
    // - all memory channels are disabled
    // - the current kernel hash matches a precomputed one
    for channel in local_values.mem_channels.iter() {
        yield_constr.constraint_transition(delta_is_bootstrap * channel.used);
    }
    /*
    for (&expected, actual) in KERNEL
        .code_hash
        .iter()
        .rev()
        .zip(local_values.mem_channels.last().unwrap().value)
    {
        let expected = P::from(F::from_canonical_u32(expected));
        let diff = expected - actual;
        yield_constr.constraint_transition(delta_is_bootstrap * diff);
    }
    */
}

pub(crate) fn eval_bootstrap_kernel_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    local_values: &CpuColumnsView<ExtensionTarget<D>>,
    next_values: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let one = builder.one_extension();

    // IS_BOOTSTRAP_KERNEL must have an init value of 1, a final value of 0, and a delta in {0, -1}.
    let local_is_bootstrap = local_values.is_bootstrap_kernel;
    let next_is_bootstrap = next_values.is_bootstrap_kernel;
    let constraint = builder.sub_extension(local_is_bootstrap, one);
    yield_constr.constraint_first_row(builder, constraint);
    yield_constr.constraint_last_row(builder, local_is_bootstrap);
    let delta_is_bootstrap = builder.sub_extension(next_is_bootstrap, local_is_bootstrap);
    let constraint =
        builder.mul_add_extension(delta_is_bootstrap, delta_is_bootstrap, delta_is_bootstrap);
    yield_constr.constraint_transition(builder, constraint);

    // If this is a bootloading row and the i'th memory channel is used, it must have the right
    // address, name context = 0, segment = Code, virt + 4 = next_virt
    let code_segment =
        builder.constant_extension(F::Extension::from_canonical_usize(Segment::Code as usize));
    for (_i, channel) in local_values.mem_channels.iter().enumerate() {
        let filter = builder.mul_extension(local_is_bootstrap, channel.used);
        let constraint = builder.mul_extension(filter, channel.addr_context);
        yield_constr.constraint(builder, constraint);

        let segment_diff = builder.sub_extension(channel.addr_segment, code_segment);
        let constraint = builder.mul_extension(filter, segment_diff);
        yield_constr.constraint(builder, constraint);

        /*
        let i_ext = builder.constant_extension(F::Extension::from_canonical_u32(32));
        let prev_virt = builder.add_extension(channel.addr_virtual, i_ext);
        let virt_diff = builder.sub_extension(prev_virt, next_values.mem_channels[i].addr_virtual);
        let constraint = builder.mul_extension(filter, virt_diff);
        yield_constr.constraint_transition(builder, constraint);
        */
    }

    // If this is the final bootstrap row (i.e. delta_is_bootstrap = 1), check that
    // - all memory channels are disabled
    // - the current kernel hash matches a precomputed one
    for channel in local_values.mem_channels.iter() {
        let constraint = builder.mul_extension(delta_is_bootstrap, channel.used);
        yield_constr.constraint_transition(builder, constraint);
    }
    /*
    for (&expected, actual) in KERNEL
        .code_hash
        .iter()
        .rev()
        .zip(local_values.mem_channels.last().unwrap().value)
    {
        let expected = builder.constant_extension(F::Extension::from_canonical_u32(expected));
        let diff = builder.sub_extension(expected, actual);
        let constraint = builder.mul_extension(delta_is_bootstrap, diff);
        yield_constr.constraint_transition(builder, constraint);
    }
    */
}
