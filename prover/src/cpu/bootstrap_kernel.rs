use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::kernel::assembler::Kernel;
use crate::generation::state::GenerationState;
use crate::memory::segments::Segment;
use crate::poseidon::constants::SPONGE_RATE;
use crate::poseidon_sponge::columns::POSEIDON_RATE_BYTES;
use crate::poseidon_sponge::poseidon_sponge_stark::poseidon;
use crate::witness::memory::MemoryAddress;
use crate::witness::util::mem_write_gp_log_and_fill;
use crate::witness::util::poseidon_sponge_log;
use zkm_emulator::memory::{
    END_PC_ADDRESS, HASH_ADDRESS_BASE, HASH_ADDRESS_END, ROOT_HASH_ADDRESS_BASE,
};
use zkm_emulator::page::{PAGE_ADDR_MASK, PAGE_SIZE};

pub(crate) fn generate_bootstrap_kernel<F: RichField>(
    state: &mut GenerationState<F>,
    kernel: &Kernel,
) {
    // Iterate through chunks of the code, such that we can write one chunk to memory per row.
    let mut image_addr_value = vec![];
    let mut image_addr = vec![];
    let mut page_addr = vec![];
    // handle 8 memory for each cpu instruction
    for chunk in &kernel.program.image.iter().chunks(8) {
        let mut cpu_row = CpuColumnsView::default();
        cpu_row.clock = F::from_canonical_usize(state.traces.clock());
        cpu_row.is_bootstrap_kernel = F::ONE;

        // Write this chunk to memory, while simultaneously packing its bytes into a u32 word.
        for (channel, (addr, val)) in chunk.enumerate() {
            // Both instruction and memory data are located in code section for MIPS
            let address = MemoryAddress::new(0, Segment::Code, *addr as usize);
            image_addr.push(address);
            image_addr_value.push(*val); // BE

            if (addr & PAGE_ADDR_MASK as u32) == 0 {
                page_addr.push(*addr);
            }

            let write =
                mem_write_gp_log_and_fill(channel, address, state, &mut cpu_row, (*val).to_be());
            state.traces.push_memory(write);
        }

        state.traces.push_cpu(cpu_row);
    }

    state.memory.apply_ops(&state.traces.memory_ops);

    for addr in page_addr {
        check_memory_page_hash(state, kernel, addr, false);
    }

    check_image_id(state, kernel, false);

    log::info!("Bootstrapping took {} cycles", state.traces.clock());
}

pub(crate) fn check_image_id<F: RichField>(
    state: &mut GenerationState<F>,
    kernel: &Kernel,
    post: bool,
) {
    // push mem root and pc
    let mut root_u32s: [u32; 9] = [kernel.program.entry; 9];

    if post {
        root_u32s[8] = kernel.program.end_pc as u32;
    }
    for i in 0..8 {
        let start = i * 4;
        if post {
            root_u32s[i] = u32::from_be_bytes(
                kernel.program.page_hash_root[start..(start + 4)]
                    .try_into()
                    .unwrap(),
            );
        } else {
            root_u32s[i] = u32::from_be_bytes(
                kernel.program.pre_hash_root[start..(start + 4)]
                    .try_into()
                    .unwrap(),
            );
        }
    }
    let root_hash_addr_value: Vec<_> = (ROOT_HASH_ADDRESS_BASE..=END_PC_ADDRESS)
        .step_by(4)
        .collect::<Vec<u32>>();
    let root_hash_addr_value: Vec<_> = root_hash_addr_value.iter().zip(root_u32s).collect();

    let mut root_hash_addr = Vec::new();
    for chunk in &root_hash_addr_value.iter().chunks(8) {
        let mut cpu_row = CpuColumnsView::default();
        cpu_row.clock = F::from_canonical_usize(state.traces.clock());
        if post {
            cpu_row.is_exit_kernel = F::ONE;
            cpu_row.program_counter = F::from_canonical_usize(state.registers.program_counter);
        } else {
            cpu_row.is_bootstrap_kernel = F::ONE;
        }

        // Write this chunk to memory, while simultaneously packing its bytes into a u32 word.
        for (channel, (addr, val)) in chunk.enumerate() {
            // Both instruction and memory data are located in code section for MIPS
            let address = MemoryAddress::new(0, Segment::Code, **addr as usize);
            root_hash_addr.push(address);
            let write =
                mem_write_gp_log_and_fill(channel, address, state, &mut cpu_row, (*val).to_be());
            state.traces.push_memory(write);
        }

        state.traces.push_cpu(cpu_row);
    }

    let mut cpu_row = CpuColumnsView::default();
    cpu_row.clock = F::from_canonical_usize(state.traces.clock());
    if post {
        cpu_row.is_exit_kernel = F::ONE;
        cpu_row.program_counter = F::from_canonical_usize(state.registers.program_counter);
    } else {
        cpu_row.is_bootstrap_kernel = F::ONE;
    }

    cpu_row.is_poseidon_sponge = F::ONE;

    let mut image_addr_value_byte_be = vec![0u8; root_hash_addr_value.len() * 4];
    for (i, (_, v)) in root_hash_addr_value.iter().enumerate() {
        image_addr_value_byte_be[i * 4..(i * 4 + 4)].copy_from_slice(&v.to_le_bytes());
    }

    // The Poseidon sponge CTL uses memory value columns for its inputs and outputs.
    let final_index = root_hash_addr.len() / SPONGE_RATE * SPONGE_RATE;
    cpu_row.mem_channels[0].value = F::ZERO; // context
    cpu_row.mem_channels[1].value = F::from_canonical_usize(Segment::Code as usize);
    cpu_row.mem_channels[2].value = F::from_canonical_usize(root_hash_addr[final_index].virt);
    cpu_row.mem_channels[3].value = F::from_canonical_usize(image_addr_value_byte_be.len()); // len

    let code_hash_u64s = poseidon::<F>(&image_addr_value_byte_be);
    let code_hash_bytes = code_hash_u64s
        .iter()
        .flat_map(|&num| num.to_le_bytes())
        .collect_vec();
    // let code_hash_be = core::array::from_fn(|i| {
    //     u32::from_le_bytes(core::array::from_fn(|j| code_hash_bytes[i * 4 + j]))
    // });
    // let code_hash = code_hash_be.map(u32::from_be);
    if post {
        log::trace!("actual post image id: {:?}", code_hash_bytes);
        log::trace!("expected post image id: {:?}", kernel.program.image_id);
        assert_eq!(code_hash_bytes, kernel.program.image_id);
    } else {
        log::trace!("actual pre image id: {:?}", code_hash_bytes);
        log::trace!("expected pre image id: {:?}", kernel.program.pre_image_id);
        assert_eq!(code_hash_bytes, kernel.program.pre_image_id);
    }

    cpu_row.general.hash_mut().value = code_hash_u64s.map(F::from_canonical_u64);

    poseidon_sponge_log(state, root_hash_addr, image_addr_value_byte_be);
    state.traces.push_cpu(cpu_row);
}

pub(crate) fn check_memory_page_hash<F: RichField>(
    state: &mut GenerationState<F>,
    kernel: &Kernel,
    addr: u32,
    update: bool,
) {
    log::trace!("check page hash, addr: {:X}", addr);
    assert_eq!(addr & PAGE_ADDR_MASK as u32, 0u32);
    let page_data_addr_value: Vec<_> = (addr..addr + PAGE_SIZE as u32)
        .step_by(4)
        .collect::<Vec<u32>>();

    let mut page_data_addr = Vec::new();

    let mut page_addr_value_byte_be = vec![0u8; PAGE_SIZE];
    for (i, addr) in page_data_addr_value.iter().enumerate() {
        let address = MemoryAddress::new(0, Segment::Code, *addr as usize);
        page_data_addr.push(address);
        let v = state.memory.get(address);
        page_addr_value_byte_be[i * 4..(i * 4 + 4)].copy_from_slice(&v.to_le_bytes());
    }

    let code_hash_u64s = poseidon::<F>(&page_addr_value_byte_be);
    let code_hash_bytes = code_hash_u64s
        .iter()
        .flat_map(|&num| num.to_le_bytes())
        .collect_vec();
    let code_hash_be: [u32; 8] = core::array::from_fn(|i| {
        u32::from_le_bytes(core::array::from_fn(|j| code_hash_bytes[i * 4 + j]))
    });
    // let code_hash = code_hash_be.map(u32::from_be);

    if addr == HASH_ADDRESS_END {
        log::debug!("actual root page hash: {:?}", code_hash_bytes);
        if update {
            log::trace!(
                "expected post root page hash: {:?}",
                kernel.program.page_hash_root
            );
            assert_eq!(code_hash_bytes, kernel.program.page_hash_root);
        } else {
            log::trace!(
                "expected pre root page hash: {:?}",
                kernel.program.pre_hash_root
            );
            assert_eq!(code_hash_bytes, kernel.program.pre_hash_root);
        }
    } else if update {
        let start_hash_addr = HASH_ADDRESS_BASE + ((addr >> 12) << 5);
        let hash_addr_value: Vec<_> = (start_hash_addr..=start_hash_addr + 31)
            .step_by(4)
            .collect::<Vec<u32>>();
        let hash_addr_value: Vec<_> = hash_addr_value.iter().zip(code_hash_be).collect();

        for chunk in &hash_addr_value.iter().chunks(8) {
            let mut cpu_row = CpuColumnsView::default();
            cpu_row.clock = F::from_canonical_usize(state.traces.clock());
            cpu_row.is_exit_kernel = F::ONE;
            cpu_row.program_counter = F::from_canonical_usize(state.registers.program_counter);

            // Write this chunk to memory, while simultaneously packing its bytes into a u32 word.
            for (channel, (addr, val)) in chunk.enumerate() {
                // Both instruction and memory data are located in code section for MIPS
                let address = MemoryAddress::new(0, Segment::Code, **addr as usize);
                let write = mem_write_gp_log_and_fill(
                    channel,
                    address,
                    state,
                    &mut cpu_row,
                    (*val).to_be(),
                );
                state.traces.push_memory(write);
            }

            state.traces.push_cpu(cpu_row);
        }

        log::trace!("update page hash: {:?}", code_hash_bytes);
    } else {
        let mut expected_hash_byte = [0u8; 32];
        let hash_addr = HASH_ADDRESS_BASE + ((addr >> 12) << 5);
        for i in 0..8 {
            let addr = hash_addr + (i << 2) as u32;
            let v = kernel.program.image.get(&addr).unwrap();
            expected_hash_byte[i * 4..(i * 4 + 4)].copy_from_slice(&v.to_le_bytes());
        }
        log::trace!("actual page hash: {:?}", code_hash_bytes);
        log::trace!("expected page hash: {:?}", expected_hash_byte);
        assert_eq!(code_hash_bytes, expected_hash_byte);
    }

    let mut cpu_row = CpuColumnsView::default();
    cpu_row.clock = F::from_canonical_usize(state.traces.clock());
    if update {
        cpu_row.is_exit_kernel = F::ONE;
        cpu_row.program_counter = F::from_canonical_usize(state.registers.program_counter);
    } else {
        cpu_row.is_bootstrap_kernel = F::ONE;
    }
    cpu_row.is_poseidon_sponge = F::ONE;

    // The Poseidon sponge CTL uses memory value columns for its inputs and outputs.
    cpu_row.mem_channels[0].value = F::ZERO; // context
    cpu_row.mem_channels[1].value = F::from_canonical_usize(Segment::Code as usize);
    let final_idx = page_addr_value_byte_be.len() / POSEIDON_RATE_BYTES * SPONGE_RATE;
    let virt = if final_idx >= page_data_addr.len() {
        0
    } else {
        page_data_addr[final_idx].virt
    };
    cpu_row.mem_channels[2].value = F::from_canonical_usize(virt);
    cpu_row.mem_channels[3].value = F::from_canonical_usize(page_addr_value_byte_be.len()); // len

    cpu_row.general.hash_mut().value = code_hash_u64s.map(F::from_canonical_u64);

    poseidon_sponge_log(state, page_data_addr, page_addr_value_byte_be);
    state.traces.push_cpu(cpu_row);
    if update {
        state.memory.apply_ops(&state.traces.memory_ops);
    }
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
    for channel in local_values.mem_channels.iter() {
        let filter = local_is_bootstrap * channel.used;
        yield_constr.constraint(filter * channel.addr_context);
        yield_constr.constraint(filter * (channel.addr_segment - code_segment));
        /* FIXME
        let delta_virt = channel.addr_virtual + P::from(F::from_canonical_u32(32)) - next_values.mem_channels[i].addr_virtual;
        log::trace!("virt {:?} {:?} {:?} {:?} {}", channel.addr_virtual, delta_virt, local_values.clock, NUM_GP_CHANNELS, i);
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
    for channel in local_values.mem_channels {
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
