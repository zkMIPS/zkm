use plonky2::field::types::Field;

use super::memory::DUMMY_MEMOP;
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::kernel::keccak_util::keccakf_u8s;
use crate::cpu::membus::{NUM_CHANNELS, NUM_GP_CHANNELS};
use crate::generation::state::GenerationState;
use crate::keccak_sponge::columns::{KECCAK_RATE_BYTES, KECCAK_WIDTH_BYTES};
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeOp;
use crate::logic;
use crate::memory::segments::Segment;
use crate::witness::errors::ProgramError;
use crate::witness::memory::{MemoryAddress, MemoryChannel, MemoryOp, MemoryOpKind};
use byteorder::{ByteOrder, LittleEndian};

fn _to_byte_checked(n: u32) -> u8 {
    let res: u8 = n.to_be_bytes()[0];
    assert_eq!(n as u8, res);
    res
}

fn to_bits_le<F: Field>(n: u32) -> [F; 32] {
    let mut res = [F::ZERO; 32];
    for (i, bit) in res.iter_mut().enumerate() {
        *bit = F::from_bool(n & (1 << i) != 0);
    }
    res
}

pub(crate) fn fill_channel_with_value<F: Field>(row: &mut CpuColumnsView<F>, n: usize, val: u32) {
    let channel = &mut row.mem_channels[n];
    channel.value[0] = F::from_canonical_u32(val);
    /*
    let val_limbs: [u64; 4] = val.0;
    for (i, limb) in val_limbs.into_iter().enumerate() {
        channel.value[2 * i] = F::from_canonical_u32(limb as u32);
        channel.value[2 * i + 1] = F::from_canonical_u32((limb >> 32) as u32);
    }
    */
}

pub(crate) fn mem_read_code_with_log_and_fill<F: Field>(
    address: MemoryAddress,
    state: &GenerationState<F>,
    row: &mut CpuColumnsView<F>,
) -> (u32, MemoryOp) {
    let (val, op) = mem_read_with_log(MemoryChannel::Code, address, state);

    //let val_u8 = to_byte_checked(val);
    row.opcode_bits = to_bits_le(val);

    (val, op)
}

pub(crate) fn mem_read_with_log<F: Field>(
    channel: MemoryChannel,
    address: MemoryAddress,
    state: &GenerationState<F>,
) -> (u32, MemoryOp) {
    let val = state.memory.get(address);
    let op = MemoryOp::new(
        channel,
        state.traces.clock(),
        address,
        MemoryOpKind::Read,
        val,
    );
    (val, op)
}

/// Pushes without writing in memory. This happens in opcodes where a push immediately follows a pop.
/// The pushed value may be loaded in a memory channel, without creating a memory operation.
pub(crate) fn push_no_write<F: Field>(
    state: &mut GenerationState<F>,
    row: &mut CpuColumnsView<F>,
    val: u32,
    channel_opt: Option<usize>,
) {
    // state.registers.stack_top = val;
    // state.registers.stack_len += 1;

    if let Some(channel) = channel_opt {
        // let val_limbs: [u64; 4] = val.0;

        let channel = &mut row.mem_channels[channel];
        assert_eq!(channel.used, F::ZERO);
        channel.used = F::ZERO;
        channel.is_read = F::ZERO;
        channel.addr_context = F::from_canonical_usize(0);
        channel.addr_segment = F::from_canonical_usize(0);
        channel.addr_virtual = F::from_canonical_usize(0);
        channel.value[0] = F::from_canonical_u32(val);
        /*
        for (i, limb) in val_limbs.into_iter().enumerate() {
            channel.value[2 * i] = F::from_canonical_u32(limb as u32);
            channel.value[2 * i + 1] = F::from_canonical_u32((limb >> 32) as u32);
        }
        */
    }
}

/// Pushes and (maybe) writes the previous stack top in memory. This happens in opcodes which only push.
pub(crate) fn push_with_write<F: Field>(
    state: &mut GenerationState<F>,
    row: &mut CpuColumnsView<F>,
    val: u32,
) -> Result<(), ProgramError> {
    /*
    if !state.registers.is_kernel && state.registers.stack_len >= MAX_USER_STACK_SIZE {
        return Err(ProgramError::StackOverflow);
    }

    let write = if state.registers.stack_len == 0 {
        None
    } else {
        let address = MemoryAddress::new(
            state.registers.context,
            Segment::Stack,
            state.registers.stack_len - 1,
        );
        let res = mem_write_gp_log_and_fill(
            NUM_GP_CHANNELS - 1,
            address,
            state,
            row,
            state.registers.stack_top,
        );
        Some(res)
    };
    push_no_write(state, row, val, None);
    if let Some(log) = write {
        state.traces.push_memory(log);
    }
    */
    Ok(())
}

pub(crate) fn mem_read_gp_with_log_and_fill<F: Field>(
    n: usize,
    address: MemoryAddress,
    state: &GenerationState<F>,
    row: &mut CpuColumnsView<F>,
) -> (u32, MemoryOp) {
    let (val, op) = mem_read_with_log(MemoryChannel::GeneralPurpose(n), address, state);

    let channel = &mut row.mem_channels[n];
    assert_eq!(channel.used, F::ZERO);
    channel.used = F::ONE;
    channel.is_read = F::ONE;
    channel.addr_context = F::from_canonical_usize(address.context);
    channel.addr_segment = F::from_canonical_usize(address.segment);
    channel.addr_virtual = F::from_canonical_usize(address.virt);
    /*
    let val_limbs: [u64; 4] = val.0;
    for (i, limb) in val_limbs.into_iter().enumerate() {
        channel.value[2 * i] = F::from_canonical_u32(limb as u32);
        channel.value[2 * i + 1] = F::from_canonical_u32((limb >> 32) as u32);
    }
    */

    channel.value[0] = F::from_canonical_u32(val);
    (val, op)
}

pub(crate) fn mem_write_gp_log_and_fill<F: Field>(
    n: usize,
    address: MemoryAddress,
    state: &GenerationState<F>,
    row: &mut CpuColumnsView<F>,
    val: u32,
) -> MemoryOp {
    let op = mem_write_log(MemoryChannel::GeneralPurpose(n), address, state, val);

    let channel = &mut row.mem_channels[n];
    assert_eq!(channel.used, F::ZERO);
    channel.used = F::ONE;
    channel.is_read = F::ZERO;
    channel.addr_context = F::from_canonical_usize(address.context);
    channel.addr_segment = F::from_canonical_usize(address.segment);
    channel.addr_virtual = F::from_canonical_usize(address.virt);
    // let val_limbs: [u64; 4] = val.0;
    // for (i, limb) in val_limbs.into_iter().enumerate() {
    //     channel.value[2 * i] = F::from_canonical_u32(limb as u32);
    //     channel.value[2 * i + 1] = F::from_canonical_u32((limb >> 32) as u32);
    // }
    channel.value[0] = F::from_canonical_u32(val);

    op
}

pub(crate) fn mem_write_log<F: Field>(
    channel: MemoryChannel,
    address: MemoryAddress,
    state: &GenerationState<F>,
    val: u32,
) -> MemoryOp {
    MemoryOp::new(
        channel,
        state.traces.clock(),
        address,
        MemoryOpKind::Write,
        val,
    )
}

pub(crate) fn keccak_sponge_log<F: Field>(
    state: &mut GenerationState<F>,
    base_address: MemoryAddress,
    input: Vec<u8>,
) {
    let clock = state.traces.clock();

    let mut address = base_address;
    let mut input_blocks = input.chunks_exact(KECCAK_RATE_BYTES);
    let mut sponge_state = [0u8; KECCAK_WIDTH_BYTES];
    for block in input_blocks.by_ref() {
        for &byte in block {
            state.traces.push_memory(MemoryOp::new(
                MemoryChannel::Code,
                clock,
                address,
                MemoryOpKind::Read,
                byte.into(),
            ));
            address.increment();
        }
        xor_into_sponge(state, &mut sponge_state, block.try_into().unwrap());
        state
            .traces
            .push_keccak_bytes(sponge_state, clock * NUM_CHANNELS);
        keccakf_u8s(&mut sponge_state);
    }

    for &byte in input_blocks.remainder() {
        state.traces.push_memory(MemoryOp::new(
            MemoryChannel::Code,
            clock,
            address,
            MemoryOpKind::Read,
            byte.into(),
        ));
        address.increment();
    }
    let mut final_block = [0u8; KECCAK_RATE_BYTES];
    final_block[..input_blocks.remainder().len()].copy_from_slice(input_blocks.remainder());
    // pad10*1 rule
    if input_blocks.remainder().len() == KECCAK_RATE_BYTES - 1 {
        // Both 1s are placed in the same byte.
        final_block[input_blocks.remainder().len()] = 0b10000001;
    } else {
        final_block[input_blocks.remainder().len()] = 1;
        final_block[KECCAK_RATE_BYTES - 1] = 0b10000000;
    }
    xor_into_sponge(state, &mut sponge_state, &final_block);
    state
        .traces
        .push_keccak_bytes(sponge_state, clock * NUM_CHANNELS);

    state.traces.push_keccak_sponge(KeccakSpongeOp {
        base_address,
        timestamp: clock * NUM_CHANNELS,
        input,
    });
}

fn xor_into_sponge<F: Field>(
    state: &mut GenerationState<F>,
    sponge_state: &mut [u8; KECCAK_WIDTH_BYTES],
    block: &[u8; KECCAK_RATE_BYTES],
) {
    /// FIXME: why the step does not matter here?
    for i in (0..KECCAK_RATE_BYTES).step_by(4) {
        let range = i..KECCAK_RATE_BYTES.min(i + 4);
        let lhs = LittleEndian::read_u32(&sponge_state[range.clone()]);
        let rhs = LittleEndian::read_u32(&block[range]);
        state
            .traces
            .push_logic(logic::Operation::new(logic::Op::Xor, lhs, rhs));
    }
    for i in 0..KECCAK_RATE_BYTES {
        sponge_state[i] ^= block[i];
    }
}
