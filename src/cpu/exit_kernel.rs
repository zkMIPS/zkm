use itertools::Itertools;
use keccak_hash::keccak;
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
use crate::keccak_sponge::columns::{KECCAK_RATE_BYTES, KECCAK_RATE_U32S};
use crate::memory::segments::Segment;
use crate::mips_emulator::memory::{
    END_PC_ADDRESS, HASH_ADDRESS_BASE, HASH_ADDRESS_END, ROOT_HASH_ADDRESS_BASE,
};
use crate::mips_emulator::page::{PAGE_ADDR_MASK, PAGE_SIZE};
use crate::witness::memory::MemoryAddress;
use crate::witness::util::keccak_sponge_log;
use crate::witness::util::mem_write_gp_log_and_fill;
use crate::witness::util::reg_zero_write_with_log;

pub(crate) fn generate_exit_kernel<F: Field>(state: &mut GenerationState<F>, kernel: &Kernel) {
    //  check exit pc = end pc
    assert_eq!(kernel.program.end_pc, state.registers.program_counter);
    let mut cpu_row = CpuColumnsView::default();
    cpu_row.clock = F::from_canonical_usize(state.traces.clock());
    cpu_row.is_kernel_mode = F::ONE;
    cpu_row.program_counter = F::from_canonical_usize(state.registers.program_counter);

    let log_end_pc = reg_zero_write_with_log(0, kernel.program.end_pc, state, &mut cpu_row);
    state.traces.push_memory(log_end_pc);
    state.traces.push_cpu(cpu_row);

    // sync registers to memory
    let registers_addr: Vec<_> = (0..=(36 << 2) - 1).step_by(4).collect::<Vec<u32>>();
    let mut registers_value: [u32; 36] = [0; 36];
    for i in 0..32 {
        registers_value[i] = state.registers.gprs[i] as u32;
    }
    registers_value[32] = state.registers.lo as u32;
    registers_value[33] = state.registers.hi as u32;
    registers_value[34] = state.registers.heap as u32;
    registers_value[35] = state.registers.program_counter as u32;

    let register_addr_value: Vec<_> = registers_addr.iter().zip(registers_value).collect();
    for chunk in &register_addr_value.iter().chunks(8) {
        let mut cpu_row = CpuColumnsView::default();
        cpu_row.clock = F::from_canonical_usize(state.traces.clock());
        cpu_row.is_exit_kernel = F::ONE;
        cpu_row.program_counter = F::from_canonical_usize(state.registers.program_counter);

        // Write this chunk to memory, while simultaneously packing its bytes into a u32 word.
        for (channel, (addr, val)) in chunk.enumerate() {
            // Both instruction and memory data are located in code section for MIPS
            let address = MemoryAddress::new(0, Segment::Code, **addr as usize);
            let write = mem_write_gp_log_and_fill(channel, address, state, &mut cpu_row, *val);
            state.traces.push_memory(write);
        }

        state.traces.push_cpu(cpu_row);
    }
    state.memory.apply_ops(&state.traces.memory_ops);

    // update memory hash root
    for (addr, _) in kernel.program.image.iter() {
        if (*addr & PAGE_ADDR_MASK as u32) == 0 {
            update_memory_page_hash(state, kernel, *addr);
        }
    }

    // check post image
    check_post_image_id(state, kernel);
}

pub(crate) fn check_post_image_id<F: Field>(state: &mut GenerationState<F>, kernel: &Kernel) {
    // push mem root and pc
    let mut root_u32s: [u32; 9] = [kernel.program.end_pc as u32; 9];
    for i in 0..8 {
        let start = i * 4;
        root_u32s[i] = u32::from_be_bytes(
            kernel.program.page_hash_root[start..(start + 4)]
                .try_into()
                .unwrap(),
        );
    }
    let root_hash_addr_value: Vec<_> = (ROOT_HASH_ADDRESS_BASE..=END_PC_ADDRESS)
        .step_by(4)
        .collect::<Vec<u32>>();
    let root_hash_addr_value: Vec<_> = root_hash_addr_value.iter().zip(root_u32s).collect();

    let mut root_hash_addr = Vec::new();
    for chunk in &root_hash_addr_value.iter().chunks(8) {
        let mut cpu_row = CpuColumnsView::default();
        cpu_row.clock = F::from_canonical_usize(state.traces.clock());
        cpu_row.is_exit_kernel = F::ONE;
        cpu_row.program_counter = F::from_canonical_usize(state.registers.program_counter);

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
    cpu_row.is_exit_kernel = F::ONE;
    cpu_row.is_keccak_sponge = F::ONE;
    cpu_row.program_counter = F::from_canonical_usize(state.registers.program_counter);

    let mut image_addr_value_byte_be = vec![0u8; root_hash_addr_value.len() * 4];
    for (i, (_, v)) in root_hash_addr_value.iter().enumerate() {
        image_addr_value_byte_be[i * 4..(i * 4 + 4)].copy_from_slice(&v.to_be_bytes());
    }

    // The Keccak sponge CTL uses memory value columns for its inputs and outputs.
    cpu_row.mem_channels[0].value[0] = F::ZERO; // context
    cpu_row.mem_channels[1].value[0] = F::from_canonical_usize(Segment::Code as usize);
    cpu_row.mem_channels[2].value[0] = F::from_canonical_usize(root_hash_addr[0].virt);
    cpu_row.mem_channels[3].value[0] = F::from_canonical_usize(image_addr_value_byte_be.len()); // len

    let code_hash_bytes = keccak(&image_addr_value_byte_be).0;
    log::debug!("actual post image id: {:?}", code_hash_bytes);
    log::debug!("expected post image id: {:?}", kernel.program.image_id);
    let code_hash_be = core::array::from_fn(|i| {
        u32::from_le_bytes(core::array::from_fn(|j| code_hash_bytes[i * 4 + j]))
    });
    let code_hash = code_hash_be.map(u32::from_be);
    assert_eq!(code_hash_bytes, kernel.program.image_id);

    cpu_row.mem_channels[4].value = code_hash.map(F::from_canonical_u32);
    cpu_row.mem_channels[4].value.reverse();

    keccak_sponge_log(state, root_hash_addr, image_addr_value_byte_be);
    state.traces.push_cpu(cpu_row);
}

pub(crate) fn update_memory_page_hash<F: Field>(
    state: &mut GenerationState<F>,
    kernel: &Kernel,
    addr: u32,
) {
    log::debug!("update page hash, addr: {:X}", addr);
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
        page_addr_value_byte_be[i * 4..(i * 4 + 4)].copy_from_slice(&v.to_be_bytes());
    }

    let code_hash_bytes = keccak(&page_addr_value_byte_be).0;
    let code_hash_be = core::array::from_fn(|i| {
        u32::from_le_bytes(core::array::from_fn(|j| code_hash_bytes[i * 4 + j]))
    });
    let code_hash = code_hash_be.map(u32::from_be);

    if addr == HASH_ADDRESS_END {
        log::debug!("actual root page hash: {:?}", code_hash_bytes);
        log::debug!(
            "expected root page hash: {:?}",
            kernel.program.page_hash_root
        );
        assert_eq!(code_hash_bytes, kernel.program.page_hash_root);
    } else {
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
    }

    let mut cpu_row = CpuColumnsView::default();
    cpu_row.clock = F::from_canonical_usize(state.traces.clock());
    cpu_row.is_exit_kernel = F::ONE;
    cpu_row.is_keccak_sponge = F::ONE;
    cpu_row.program_counter = F::from_canonical_usize(state.registers.program_counter);

    // The Keccak sponge CTL uses memory value columns for its inputs and outputs.
    cpu_row.mem_channels[0].value[0] = F::ZERO; // context
    cpu_row.mem_channels[1].value[0] = F::from_canonical_usize(Segment::Code as usize);
    let final_idx = page_addr_value_byte_be.len() / KECCAK_RATE_BYTES * KECCAK_RATE_U32S;
    cpu_row.mem_channels[2].value[0] = F::from_canonical_usize(page_data_addr[final_idx].virt);
    cpu_row.mem_channels[3].value[0] = F::from_canonical_usize(page_addr_value_byte_be.len()); // len

    cpu_row.mem_channels[4].value = code_hash.map(F::from_canonical_u32);
    cpu_row.mem_channels[4].value.reverse();

    keccak_sponge_log(state, page_data_addr, page_addr_value_byte_be);
    state.traces.push_cpu(cpu_row);
    state.memory.apply_ops(&state.traces.memory_ops);
}

pub(crate) fn eval_exit_kernel_packed<F: Field, P: PackedField<Scalar = F>>(
    local_values: &CpuColumnsView<P>,
    next_values: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    // IS_EXIT_KERNEL must have an init value of 0, a final value of 1, and a delta in {0, 1}.
    let local_is_exit = local_values.is_exit_kernel;
    let next_is_exit = next_values.is_exit_kernel;
    yield_constr.constraint_last_row(local_is_exit - P::ONES);
    yield_constr.constraint_first_row(local_is_exit);
    let delta_is_exit = next_is_exit - local_is_exit;
    yield_constr.constraint_transition(delta_is_exit * (delta_is_exit - P::ONES));

    // If this is a exit row and the i'th memory channel is used, it must have the right
    // address, name context = 0, segment = Code, virt + 4 = next_virt
    let code_segment = F::from_canonical_usize(Segment::Code as usize);
    for channel in local_values.mem_channels.iter() {
        let filter = local_is_exit * channel.used;
        yield_constr.constraint(filter * channel.addr_context);
        yield_constr.constraint(filter * (channel.addr_segment - code_segment));
    }

    // for the next is exit, the current pc should be end_pc
    // for the exit row, all the pc should be end_pc
    let input0 = local_values.mem_channels[0].value[0];
    yield_constr.constraint_transition(delta_is_exit * (input0 - local_values.program_counter));

    yield_constr.constraint_transition(
        local_is_exit * (next_values.program_counter - local_values.program_counter),
    );
}

pub(crate) fn eval_exit_kernel_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    local_values: &CpuColumnsView<ExtensionTarget<D>>,
    next_values: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let one = builder.one_extension();

    // IS_EXIT_KERNEL must have an init value of 0, a final value of 1, and a delta in {0, 1}.
    let local_is_exit = local_values.is_exit_kernel;
    let next_is_exit = next_values.is_exit_kernel;
    let constraint = builder.sub_extension(local_is_exit, one);
    yield_constr.constraint_last_row(builder, constraint);
    yield_constr.constraint_first_row(builder, local_is_exit);
    let delta_is_exit = builder.sub_extension(next_is_exit, local_is_exit);
    let constraint = builder.sub_extension(delta_is_exit, one);
    let constraint = builder.mul_extension(delta_is_exit, constraint);
    yield_constr.constraint_transition(builder, constraint);

    // If this is a exit row and the i'th memory channel is used, it must have the right
    // address, name context = 0, segment = Code, virt + 4 = next_virt
    let code_segment =
        builder.constant_extension(F::Extension::from_canonical_usize(Segment::Code as usize));
    for channel in local_values.mem_channels {
        let filter = builder.mul_extension(local_is_exit, channel.used);
        let constraint = builder.mul_extension(filter, channel.addr_context);
        yield_constr.constraint(builder, constraint);

        let segment_diff = builder.sub_extension(channel.addr_segment, code_segment);
        let constraint = builder.mul_extension(filter, segment_diff);
        yield_constr.constraint(builder, constraint);
    }

    // for the next is exit, the current pc should be end_pc
    // for the exit row, all the pc should be end_pc
    let input0 = local_values.mem_channels[0].value[0];
    let pc_constr = builder.sub_extension(input0, local_values.program_counter);
    let pc_constr = builder.mul_extension(delta_is_exit, pc_constr);
    yield_constr.constraint_transition(builder, pc_constr);

    let pc_constr =
        builder.sub_extension(next_values.program_counter, local_values.program_counter);
    let pc_constr = builder.mul_extension(local_values.is_exit_kernel, pc_constr);
    yield_constr.constraint_transition(builder, pc_constr);
}
