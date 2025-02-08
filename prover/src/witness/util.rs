use byteorder::ByteOrder;
use byteorder::LittleEndian;
use itertools::Itertools;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;

use crate::cpu::columns::CpuColumnsView;
use crate::cpu::kernel::keccak_util::keccakf_u8s;
use crate::cpu::membus::NUM_CHANNELS;
use crate::cpu::membus::NUM_GP_CHANNELS;
use crate::generation::state::GenerationState;
use crate::keccak_sponge::columns::KECCAK_RATE_BYTES;
use crate::keccak_sponge::columns::KECCAK_WIDTH_BYTES;
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeOp;
use crate::logic;
use crate::memory::segments::Segment;
use crate::poseidon::constants::{SPONGE_RATE, SPONGE_WIDTH};
use crate::poseidon::poseidon_stark::poseidon_with_witness;
use crate::poseidon_sponge::columns::POSEIDON_RATE_BYTES;
use crate::poseidon_sponge::poseidon_sponge_stark::PoseidonSpongeOp;
use crate::sha_compress_sponge::constants::SHA_COMPRESS_K_LE_BYTES;
use crate::sha_compress_sponge::sha_compress_sponge_stark::ShaCompressSpongeOp;
use crate::sha_extend_sponge::sha_extend_sponge_stark::ShaExtendSpongeOp;
use crate::witness::errors::ProgramError;
use crate::witness::memory::{MemoryAddress, MemoryChannel, MemoryOp, MemoryOpKind};
use plonky2::field::extension::Extendable;
use plonky2::plonk::config::GenericConfig;

fn to_byte_checked(n: u32) -> u8 {
    let res: u8 = n.to_le_bytes()[0];
    assert_eq!(n as u8, res);
    res
}

fn to_bits_le<F: Field, const N: usize>(n: u8) -> [F; N] {
    let mut res = [F::ZERO; N];
    for (i, bit) in res.iter_mut().enumerate() {
        *bit = F::from_bool(n & (1 << i) != 0);
    }
    res
}

fn to_bits32_le<F: Field>(n: u32) -> [F; 32] {
    let mut res = [F::ZERO; 32];
    for (i, bit) in res.iter_mut().enumerate() {
        *bit = F::from_bool(n & (1 << i) != 0);
    }
    res
}

pub(crate) fn fill_channel_with_value<F: Field>(row: &mut CpuColumnsView<F>, n: usize, val: u32) {
    let channel = &mut row.mem_channels[n];
    channel.value = F::from_canonical_u32(val);
}

pub(crate) fn mem_read_code_with_log_and_fill<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    address: MemoryAddress,
    state: &GenerationState<F, C, D>,
    row: &mut CpuColumnsView<F>,
) -> (u32, MemoryOp) {
    let (val, op) = mem_read_with_log(MemoryChannel::Code, address, state);

    let val_func = to_byte_checked(val & 0x3F);
    let val_shamt = to_byte_checked((val >> 6) & 0x1F);
    let val_rd = to_byte_checked((val >> 11) & 0x1F);
    let val_rt = to_byte_checked((val >> 16) & 0x1F);
    let val_rs = to_byte_checked((val >> 21) & 0x1F);
    let val_op = to_byte_checked(val >> 26);

    row.opcode_bits = to_bits_le::<F, 6>(val_op);
    row.func_bits = to_bits_le::<F, 6>(val_func);
    row.rs_bits = to_bits_le::<F, 5>(val_rs);
    row.rt_bits = to_bits_le::<F, 5>(val_rt);
    row.rd_bits = to_bits_le::<F, 5>(val_rd);
    row.shamt_bits = to_bits_le::<F, 5>(val_shamt);

    /*
    // FIXME: hold last channel for code read
     */
    let channel = &mut row.mem_channels[NUM_GP_CHANNELS - 1];
    assert_eq!(channel.used, F::ZERO);
    channel.used = F::ONE;
    channel.is_read = F::ONE;
    channel.addr_context = F::from_canonical_usize(address.context);
    channel.addr_segment = F::from_canonical_usize(address.segment);
    channel.addr_virtual = F::from_canonical_usize(address.virt);
    channel.value = F::from_canonical_u32(val);

    (val, op)
}

pub(crate) fn sign_extend<const N: usize>(value: u32) -> u32 {
    let is_signed = (value >> (N - 1)) != 0;
    let signed = ((1 << (32 - N)) - 1) << N;
    let mask = (1 << N) - 1;
    if is_signed {
        value & mask | signed
    } else {
        value & mask
    }
}

pub(crate) fn reg_read_with_log<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    index: u8,
    channel: usize,
    state: &GenerationState<F, C, D>,
    row: &mut CpuColumnsView<F>,
) -> Result<(usize, MemoryOp), ProgramError> {
    let result = {
        if index < 32 {
            state.registers.gprs[index as usize]
        } else if index == 32 {
            state.registers.lo
        } else if index == 33 {
            state.registers.hi
        } else if index == 34 {
            state.registers.heap
        } else if index == 35 {
            state.registers.program_counter
        } else if index == 36 {
            state.registers.next_pc
        } else if index == 37 {
            state.registers.brk
        } else if index == 38 {
            state.registers.local_user
        } else {
            return Err(ProgramError::InvalidRegister);
        }
    };
    log::trace!("read reg {} : {:X}({})", index, result, result);
    let address = MemoryAddress::new(0, Segment::RegisterFile, index as usize);
    let op = MemoryOp::new(
        MemoryChannel::GeneralPurpose(channel),
        state.traces.clock(),
        address,
        MemoryOpKind::Read,
        result as u32,
    );

    let channel = &mut row.mem_channels[channel];
    assert_eq!(channel.used, F::ZERO);
    channel.used = F::ONE;
    channel.is_read = F::ONE;
    channel.addr_context = F::from_canonical_usize(address.context);
    channel.addr_segment = F::from_canonical_usize(address.segment);
    channel.addr_virtual = F::from_canonical_usize(address.virt);
    channel.value = F::from_canonical_u32(result as u32);

    Ok((result, op))
}

pub(crate) fn reg_write_with_log<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    index: u8,
    channel: usize,
    value: usize,
    state: &mut GenerationState<F, C, D>,
    row: &mut CpuColumnsView<F>,
) -> Result<MemoryOp, ProgramError> {
    if index == 0 {
        // Ignore write to r0
    } else if index < 32 {
        state.registers.gprs[index as usize] = value;
    } else if index == 32 {
        state.registers.lo = value;
    } else if index == 33 {
        state.registers.hi = value;
    } else if index == 34 {
        state.registers.heap = value;
    } else if index == 35 {
        state.registers.program_counter = value;
    } else if index == 36 {
        state.registers.next_pc = value;
    } else if index == 37 {
        state.registers.brk = value;
    } else if index == 38 {
        state.registers.local_user = value;
    } else {
        return Err(ProgramError::InvalidRegister);
    }

    log::trace!("write reg {} : {:X} ({})", index, value, value);

    let address = MemoryAddress::new(0, Segment::RegisterFile, index as usize);

    // trick: skip 0 register check since we can write anything in, but read 0 out only.
    let mut used = F::ONE;
    let mut filter = true;
    if index == 0 {
        used = F::ZERO;
        filter = false;
    }

    let mut op = MemoryOp::new(
        MemoryChannel::GeneralPurpose(channel),
        state.traces.clock(),
        address,
        MemoryOpKind::Write,
        value as u32,
    );
    op.filter = filter;

    let channel = &mut row.mem_channels[channel];
    assert_eq!(channel.used, F::ZERO);
    channel.used = used;
    channel.is_read = F::ZERO;
    channel.addr_context = F::from_canonical_usize(address.context);
    channel.addr_segment = F::from_canonical_usize(address.segment);
    channel.addr_virtual = F::from_canonical_usize(address.virt);
    channel.value = F::from_canonical_u32(value as u32);
    Ok(op)
}

pub(crate) fn reg_zero_write_with_log<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    channel: usize,
    value: usize,
    state: &mut GenerationState<F, C, D>,
    row: &mut CpuColumnsView<F>,
) -> MemoryOp {
    let address = MemoryAddress::new(0, Segment::RegisterFile, 0);

    let mut op = MemoryOp::new(
        MemoryChannel::GeneralPurpose(channel),
        state.traces.clock(),
        address,
        MemoryOpKind::Write,
        value as u32,
    );
    op.filter = false;

    let channel = &mut row.mem_channels[channel];
    assert_eq!(channel.used, F::ZERO);
    channel.used = F::ZERO;
    channel.is_read = F::ZERO;
    channel.addr_context = F::from_canonical_usize(address.context);
    channel.addr_segment = F::from_canonical_usize(address.segment);
    channel.addr_virtual = F::from_canonical_usize(address.virt);
    channel.value = F::from_canonical_u32(value as u32);
    op
}

pub(crate) fn mem_read_with_log<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    channel: MemoryChannel,
    address: MemoryAddress,
    state: &GenerationState<F, C, D>,
) -> (u32, MemoryOp) {
    let val = state.memory.get(address).to_be();
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
pub(crate) fn push_no_write<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    _state: &mut GenerationState<F, C, D>,
    row: &mut CpuColumnsView<F>,
    val: u32,
    channel_opt: Option<usize>,
) {
    if let Some(channel) = channel_opt {
        // let val_limbs: [u64; 4] = val.0;

        let channel = &mut row.mem_channels[channel];
        assert_eq!(channel.used, F::ZERO);
        channel.used = F::ZERO;
        channel.is_read = F::ZERO;
        channel.addr_context = F::from_canonical_usize(0);
        channel.addr_segment = F::from_canonical_usize(0);
        channel.addr_virtual = F::from_canonical_usize(0);
        channel.value = F::from_canonical_u32(val);
    }
}

pub(crate) fn mem_read_gp_with_log_and_fill<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    n: usize,
    address: MemoryAddress,
    state: &GenerationState<F, C, D>,
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
    channel.value = F::from_canonical_u32(val);
    (val, op)
}

pub(crate) fn mem_write_gp_log_and_fill<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    n: usize,
    address: MemoryAddress,
    state: &GenerationState<F, C, D>,
    row: &mut CpuColumnsView<F>,
    val: u32, // LE
) -> MemoryOp {
    let op = mem_write_log(MemoryChannel::GeneralPurpose(n), address, state, val);

    let channel = &mut row.mem_channels[n];
    assert_eq!(channel.used, F::ZERO);
    channel.used = F::ONE;
    channel.is_read = F::ZERO;
    channel.addr_context = F::from_canonical_usize(address.context);
    channel.addr_segment = F::from_canonical_usize(address.segment);
    channel.addr_virtual = F::from_canonical_usize(address.virt);
    channel.value = F::from_canonical_u32(val);
    op
}

pub(crate) fn mem_write_log<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    channel: MemoryChannel,
    address: MemoryAddress,
    state: &GenerationState<F, C, D>,
    val: u32, // LE
) -> MemoryOp {
    MemoryOp::new(
        channel,
        state.traces.clock(),
        address,
        MemoryOpKind::Write,
        val,
    )
}

pub(crate) fn poseidon_sponge_log<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    state: &mut GenerationState<F, C, D>,
    base_address: Vec<MemoryAddress>,
    input: Vec<u8>, // BE
) {
    let clock = state.traces.clock();

    let mut absorbed_bytes = 0;
    let mut input_blocks = input.chunks_exact(POSEIDON_RATE_BYTES);
    let mut poseidon_state = [F::ZEROS; SPONGE_WIDTH];
    // Since the poseidon read byte by byte, and the memory unit is of 4-byte, we just need to read
    // the same memory for 4 keccak-op
    let mut n_gp = 0;
    for block in input_blocks.by_ref() {
        for i in 0..block.len() {
            //for &byte in block {
            let align = (i / 4) * 4;
            // todo: LittleEndian::read_u32
            let val = u32::from_le_bytes(block[align..(align + 4)].try_into().unwrap());

            let addr_idx = absorbed_bytes / 4;
            state.traces.push_memory(MemoryOp::new(
                MemoryChannel::GeneralPurpose(n_gp),
                clock,
                base_address[addr_idx],
                MemoryOpKind::Read,
                val.to_be(),
            ));
            n_gp += 1;
            n_gp %= NUM_GP_CHANNELS - 1;
            absorbed_bytes += 1;
        }

        let rate_f = (0..POSEIDON_RATE_BYTES)
            .step_by(4)
            .map(|i| F::from_canonical_u32(LittleEndian::read_u32(&block[i..i + 4])))
            .collect_vec();
        poseidon_state[..SPONGE_RATE].copy_from_slice(&rate_f);

        state
            .traces
            .push_poseidon(poseidon_state, clock * NUM_CHANNELS);
        (poseidon_state, _) = poseidon_with_witness(&poseidon_state);
    }

    let rem = input_blocks.remainder();

    // patch data to match sponge logic
    let mut rem_data = [0u8; POSEIDON_RATE_BYTES];
    rem_data[0..rem.len()].copy_from_slice(&rem[0..rem.len()]);
    rem_data[rem.len()] = 1;
    rem_data[POSEIDON_RATE_BYTES - 1] |= 0b10000000;
    for i in 0..rem.len() {
        let align = (i / 4) * 4;
        let val = u32::from_le_bytes(rem_data[align..align + 4].try_into().unwrap());
        let addr_idx = absorbed_bytes / 4;

        state.traces.push_memory(MemoryOp::new(
            MemoryChannel::GeneralPurpose(n_gp),
            clock,
            base_address[addr_idx],
            MemoryOpKind::Read,
            val.to_be(),
        ));
        n_gp += 1;
        n_gp %= NUM_GP_CHANNELS - 1;
        absorbed_bytes += 1;
    }
    let mut final_block = [0u8; POSEIDON_RATE_BYTES];
    final_block[..input_blocks.remainder().len()].copy_from_slice(input_blocks.remainder());
    // pad10*1 rule
    if input_blocks.remainder().len() == POSEIDON_RATE_BYTES - 1 {
        // Both 1s are placed in the same byte.
        final_block[input_blocks.remainder().len()] = 0b10000001;
    } else {
        final_block[input_blocks.remainder().len()] = 1;
        final_block[POSEIDON_RATE_BYTES - 1] = 0b10000000;
    }

    let rate_f = (0..POSEIDON_RATE_BYTES)
        .step_by(4)
        .map(|i| F::from_canonical_u32(LittleEndian::read_u32(&final_block[i..i + 4])))
        .collect_vec();
    poseidon_state[..SPONGE_RATE].copy_from_slice(&rate_f);

    state
        .traces
        .push_poseidon(poseidon_state, clock * NUM_CHANNELS);

    //FIXME: how to setup the base address
    state.traces.push_poseidon_sponge(PoseidonSpongeOp {
        base_address,
        timestamp: clock * NUM_CHANNELS,
        input,
    });
}

pub(crate) fn keccak_sponge_log<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    state: &mut GenerationState<F, C, D>,
    base_address: Vec<MemoryAddress>,
    input: Vec<u8>, // BE
) {
    let clock = state.traces.clock();

    let mut absorbed_bytes = 0;
    let mut input_blocks = input.chunks_exact(KECCAK_RATE_BYTES);
    let mut sponge_state = [0u8; KECCAK_WIDTH_BYTES];
    // Since the keccak read byte by byte, and the memory unit is of 4-byte, we just need to read
    // the same memory for 4 keccak-op
    let mut n_gp = 0;
    for block in input_blocks.by_ref() {
        for i in 0..block.len() {
            //for &byte in block {
            let align = (i / 4) * 4;
            let val = u32::from_le_bytes(block[align..(align + 4)].try_into().unwrap());

            let addr_idx = absorbed_bytes / 4;
            state.traces.push_memory(MemoryOp::new(
                MemoryChannel::GeneralPurpose(n_gp),
                clock,
                base_address[addr_idx],
                MemoryOpKind::Read,
                val.to_be(),
            ));
            n_gp += 1;
            n_gp %= NUM_GP_CHANNELS - 1;
            absorbed_bytes += 1;
        }
        xor_into_sponge(state, &mut sponge_state, block.try_into().unwrap());
        state
            .traces
            .push_keccak_bytes(sponge_state, clock * NUM_CHANNELS);
        keccakf_u8s(&mut sponge_state);
    }

    let rem = input_blocks.remainder();

    // patch data to match sponge logic
    let mut rem_data = [0u8; KECCAK_RATE_BYTES];
    rem_data[0..rem.len()].copy_from_slice(&rem[0..rem.len()]);
    rem_data[rem.len()] = 1;
    rem_data[KECCAK_RATE_BYTES - 1] |= 0b10000000;
    for i in 0..rem.len() {
        let align = (i / 4) * 4;
        let val = u32::from_le_bytes(rem_data[align..align + 4].try_into().unwrap());
        let addr_idx = absorbed_bytes / 4;

        state.traces.push_memory(MemoryOp::new(
            MemoryChannel::GeneralPurpose(n_gp),
            clock,
            base_address[addr_idx],
            MemoryOpKind::Read,
            val.to_be(),
        ));
        n_gp += 1;
        n_gp %= NUM_GP_CHANNELS - 1;
        absorbed_bytes += 1;
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

    //FIXME: how to setup the base address
    state.traces.push_keccak_sponge(KeccakSpongeOp {
        base_address,
        timestamp: clock * NUM_CHANNELS,
        input,
    });
}

pub(crate) fn sha_extend_sponge_log<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    state: &mut GenerationState<F, C, D>,
    base_address: Vec<MemoryAddress>,
    inputs: Vec<[u8; 4]>, // le bytes
    output_address: MemoryAddress,
    round: usize,
) {
    // Since the Sha extend reads byte by byte, and the memory unit is of 4-byte, we just need to read
    // the same memory for 4 sha-extend ops

    let clock = state.traces.clock();
    let mut n_gp = 0;
    let extend_input: Vec<u8> = inputs.iter().flatten().cloned().collect();

    for (addr_idx, input) in inputs.into_iter().enumerate() {
        let val = u32::from_le_bytes(input);
        for _ in 0..4 {
            state.traces.push_memory(MemoryOp::new(
                MemoryChannel::GeneralPurpose(n_gp),
                clock,
                base_address[addr_idx],
                MemoryOpKind::Read,
                val,
            ));
            n_gp += 1;
            n_gp %= NUM_GP_CHANNELS - 1;
        }
    }
    state.traces.push_sha_extend(
        extend_input.clone().try_into().unwrap(),
        clock * NUM_CHANNELS,
    );

    state.traces.push_sha_extend_sponge(ShaExtendSpongeOp {
        base_address,
        timestamp: clock * NUM_CHANNELS,
        input: extend_input,
        i: round,
        output_address,
    });
}

pub(crate) fn sha_compress_sponge_log<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    state: &mut GenerationState<F, C, D>,
    hx_values: Vec<[u8; 4]>, // LE bytes
    hx_addresses: Vec<MemoryAddress>,
    w_i_values: Vec<[u8; 4]>, // LE bytes
    w_i_addresses: Vec<MemoryAddress>,
    input_state_list: Vec<Vec<[u8; 4]>>, // LE bytes
) {
    // Since the Sha compress reads byte by byte, and the memory unit is of 4-byte, we just need to read
    // the same memory for 4 sha-compress ops

    let clock = state.traces.clock();
    let mut n_gp = 0;

    // read hx as input
    for (j, hx) in hx_values.iter().enumerate() {
        let val = u32::from_le_bytes(*hx);
        // let val = 0;
        for _ in 0..4 {
            state.traces.push_memory(MemoryOp::new(
                MemoryChannel::GeneralPurpose(n_gp),
                clock,
                hx_addresses[j],
                MemoryOpKind::Read,
                val,
            ));
            n_gp += 1;
            n_gp %= NUM_GP_CHANNELS - 1;
        }
    }

    for i in 0..64 {
        // read w_i as input
        let w_i_u32 = u32::from_le_bytes(w_i_values[i]);
        for _ in 0..4 {
            state.traces.push_memory(MemoryOp::new(
                MemoryChannel::GeneralPurpose(n_gp),
                clock,
                w_i_addresses[i],
                MemoryOpKind::Read,
                w_i_u32,
            ));
            n_gp += 1;
            n_gp %= NUM_GP_CHANNELS - 1;
        }

        let w_i = w_i_values[i];
        let k_i = SHA_COMPRESS_K_LE_BYTES[i];

        let mut compress_input: Vec<u8> = input_state_list[i]
            .iter()
            .chain(&[w_i, k_i])
            .flatten()
            .cloned()
            .collect();
        compress_input.push(i as u8);
        debug_assert_eq!(compress_input.len(), 44);

        state.traces.push_sha_compress(
            compress_input.try_into().unwrap(),
            w_i_addresses[i],
            clock * NUM_CHANNELS,
        );
    }
    // the 65'th round
    let mut dummy_address = w_i_addresses[63].clone();
    dummy_address.virt += 4;
    let mut compress_input: Vec<u8> = input_state_list[64].iter().flatten().cloned().collect();
    compress_input.extend([0; 8]); // k_i and w_i
    compress_input.push(64);
    state.traces.push_sha_compress(
        compress_input.try_into().unwrap(),
        dummy_address,
        clock * NUM_CHANNELS,
    );

    let compress_sponge_input: Vec<u8> = hx_values.iter().flatten().cloned().collect();
    let mut base_address = hx_addresses.clone();
    base_address.push(w_i_addresses[0]);
    state.traces.push_sha_compress_sponge(ShaCompressSpongeOp {
        base_address,
        timestamp: clock * NUM_CHANNELS,
        input: compress_sponge_input,
        w_i_s: w_i_values,
    });
}

pub(crate) fn xor_logic_log<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    state: &mut GenerationState<F, C, D>,
    lhs: u32,
    rhs: u32,
) {
    state
        .traces
        .push_logic(logic::Operation::new(logic::Op::Xor, lhs, rhs));
}

pub(crate) fn and_logic_log<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    state: &mut GenerationState<F, C, D>,
    lhs: u32,
    rhs: u32,
) {
    state
        .traces
        .push_logic(logic::Operation::new(logic::Op::And, lhs, rhs));
}

fn xor_into_sponge<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    state: &mut GenerationState<F, C, D>,
    sponge_state: &mut [u8; KECCAK_WIDTH_BYTES],
    block: &[u8; KECCAK_RATE_BYTES],
) {
    // FIXME: why the step does not matter here?
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
