use plonky2::field::extension::Extendable;

use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;

use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::membus::NUM_GP_CHANNELS;
use crate::memory::segments::Segment;
use crate::util::{limb_from_bits_le, limb_from_bits_le_recursive};

#[inline]
fn load_offset<P: PackedField>(lv: &CpuColumnsView<P>) -> P {
    let mut mem_offset = [P::ZEROS; 32];
    mem_offset[0..6].copy_from_slice(&lv.func_bits); // 6 bits
    mem_offset[6..11].copy_from_slice(&lv.shamt_bits); // 5 bits
    mem_offset[11..16].copy_from_slice(&lv.rd_bits); // 5 bits
                                                     //mem_offset[16..].copy_from_slice(&[lv.rd_bits[4]; 16]);
    let mem_offset = sign_extend::<_, 16>(&mem_offset);
    limb_from_bits_le(mem_offset)
}

#[inline]
fn load_offset_ext<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
) -> ExtensionTarget<D> {
    let mut mem_offset = [builder.zero_extension(); 32];
    mem_offset[0..6].copy_from_slice(&lv.func_bits); // 6 bits
    mem_offset[6..11].copy_from_slice(&lv.shamt_bits); // 5 bits
    mem_offset[11..16].copy_from_slice(&lv.rd_bits); // 5 bits
                                                     //mem_offset[16..].copy_from_slice(&[lv.rd_bits[4]; 16]);
    let mem_offset = sign_extend_ext::<_, D, 16>(builder, &mem_offset);
    limb_from_bits_le_recursive(builder, mem_offset)
}

#[inline]
fn sign_extend<P: PackedField, const N: usize>(limbs: &[P; 32]) -> [P; 32] {
    let mut out = [P::ZEROS; 32];
    out[..N].copy_from_slice(&limbs[..N]);
    for i in N..32 {
        out[i] = limbs[N - 1];
    }
    out
}

#[inline]
fn sign_extend_ext<F: RichField + Extendable<D>, const D: usize, const N: usize>(
    builder: &mut CircuitBuilder<F, D>,
    limbs: &[ExtensionTarget<D>; 32],
) -> [ExtensionTarget<D>; 32] {
    let mut out = [builder.zero_extension(); 32];
    out[..N].copy_from_slice(&limbs[..N]);
    for i in N..32 {
        out[i] = limbs[N - 1];
    }
    out
}

//yield_constr.constraint(filter * lv.general.io().micro_op[2] * (mem - mem_value));
#[inline]
fn enforce_word<P: PackedField>(
    yield_constr: &mut ConstraintConsumer<P>,
    lv: &CpuColumnsView<P>,
    filter: P,
    op: usize,
    mem: P,
    mem_value: P,
) {
    let filter_op = filter * lv.general.io().micro_op[op];
    let filter_op_aux = lv.mem_channels[0].value[5];
    yield_constr.constraint(filter_op - filter_op_aux);
    yield_constr.constraint(filter_op_aux * (mem - mem_value));
}

//let sum = rs_limbs[1] * (mem - mem_val_1) + (rs_limbs[1] - P::ONES) * (mem - mem_val_0);
//yield_constr.constraint(filter * lv.general.io().micro_op[0] * sum);
#[inline]
fn enforce_half_word<P: PackedField>(
    yield_constr: &mut ConstraintConsumer<P>,
    lv: &CpuColumnsView<P>,
    filter: P,
    op: usize,
    rs_limbs: &[P],
    mem: P,
    mem_val_1: P,
    mem_val_0: P,
) {
    let lh_sum_a_aux = lv.mem_channels[0].value[3];
    let lh_sum_a = rs_limbs[1] * (mem - mem_val_1);
    yield_constr.constraint(lh_sum_a - lh_sum_a_aux);

    let lh_sum_b_aux = lv.mem_channels[0].value[4];
    let lh_sum_b = (rs_limbs[1] - P::ONES) * (mem - mem_val_0);
    yield_constr.constraint(lh_sum_b - lh_sum_b_aux);

    let filter_op = filter * lv.general.io().micro_op[op];
    let filter_op_aux = lv.mem_channels[0].value[5];
    yield_constr.constraint(filter_op - filter_op_aux);

    yield_constr.constraint(filter_op_aux * (lh_sum_a_aux + lh_sum_b_aux));
}

//let sum = (mem - mem_val_0_0) * (rs_limbs[1] - P::ONES) * (rs_limbs[0] - P::ONES)
//    + (mem - mem_val_1_0) * (rs_limbs[1] - P::ONES) * rs_limbs[0]
//    + (mem - mem_val_0_1) * rs_limbs[1] * (rs_limbs[0] - P::ONES)
//    + (mem - mem_val_1_1) * rs_limbs[1] * rs_limbs[0];
//yield_constr.constraint(filter * lv.general.io().micro_op[1] * sum);
#[inline]
fn enforce_byte<P: PackedField>(
    yield_constr: &mut ConstraintConsumer<P>,
    lv: &CpuColumnsView<P>,
    filter: P,
    op: usize,
    rs_limbs: &[P],
    mem: P,
    mem_val_0_0: P,
    mem_val_1_0: P,
    mem_val_0_1: P,
    mem_val_1_1: P,
) {
    let rs_limbs_1_rs_limbs_0 = rs_limbs[0] * rs_limbs[1];
    let rs_limbs_1_rs_limbs_0_aux = lv.mem_channels[0].value[3];
    yield_constr.constraint(rs_limbs_1_rs_limbs_0 - rs_limbs_1_rs_limbs_0_aux);

    let sum = (mem - mem_val_0_0)
        * (rs_limbs_1_rs_limbs_0_aux - rs_limbs[1] - rs_limbs[0] + P::ONES)
        + (mem - mem_val_1_0) * (rs_limbs_1_rs_limbs_0_aux - rs_limbs[0])
        + (mem - mem_val_0_1) * (rs_limbs_1_rs_limbs_0_aux - rs_limbs[1])
        + (mem - mem_val_1_1) * (rs_limbs_1_rs_limbs_0_aux);
    let sum_aux = lv.mem_channels[0].value[4];
    yield_constr.constraint(sum - sum_aux);

    let filter_op = filter * lv.general.io().micro_op[op];
    let filter_op_aux = lv.mem_channels[0].value[5];
    yield_constr.constraint(filter_op - filter_op_aux);

    yield_constr.constraint(sum_aux * filter_op_aux);
}

/// Constant -4
const GOLDILOCKS_INVERSE_NEG4: u64 = 18446744069414584317;

fn eval_packed_load<P: PackedField>(
    lv: &CpuColumnsView<P>,
    _nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    // If the operation is MLOAD_GENERAL, lv.opcode_bits[5] = 1
    let filter = lv.op.m_op_load * lv.opcode_bits[5];

    // Check mem channel segment is register
    let diff = lv.mem_channels[0].addr_segment
        - P::Scalar::from_canonical_u64(Segment::RegisterFile as u64);
    yield_constr.constraint(filter * diff);
    let diff = lv.mem_channels[1].addr_segment
        - P::Scalar::from_canonical_u64(Segment::RegisterFile as u64);
    yield_constr.constraint(filter * diff);

    // Check memory is used
    // Check is_read is 0/1

    let rs = lv.mem_channels[0].value[0];
    let rt = lv.mem_channels[1].value[0];
    let mem = lv.mem_channels[3].value[0];
    let rs_limbs = lv.general.io().rs_le;
    let rt_limbs = lv.general.io().rt_le;
    let mem_limbs = lv.general.io().mem_le;

    // Calculate rs:
    //    let virt_raw = (rs as u32).wrapping_add(sign_extend::<16>(offset));
    let offset = load_offset(lv);
    let virt_raw = rs + offset;

    // May raise overflow here since wrapping_add used in simulator
    let rs_from_bits = limb_from_bits_le(rs_limbs);
    let u32max = P::Scalar::from_canonical_u64(1u64 << 32);

    // All the AUXs are stored in values[1..7]
    let virt_raw_check = filter * (rs_from_bits - virt_raw);
    let virt_raw_check_aux = lv.mem_channels[0].value[1];
    yield_constr.constraint(virt_raw_check - virt_raw_check_aux);
    yield_constr.constraint(virt_raw_check_aux * (rs_from_bits + u32max - virt_raw));

    let rt_from_bits = limb_from_bits_le(rt_limbs);
    yield_constr.constraint(filter * (rt_from_bits - rt));

    // Constrain mem address
    //    let virt = virt_raw & 0xFFFF_FFFC;
    let mut tmp = rs_limbs;
    tmp[0] = P::ZEROS;
    tmp[1] = P::ZEROS;
    let virt = limb_from_bits_le(tmp);

    let mem_virt = lv.mem_channels[2].addr_virtual;
    yield_constr.constraint(filter * (virt - mem_virt));

    // Verify op
    let op_inv = lv.general.io().diff_inv;
    let op = lv.mem_channels[4].value[0];
    let filter_op = filter * op;
    let filter_op_aux = lv.mem_channels[0].value[2];
    yield_constr.constraint(filter_op - filter_op_aux);
    yield_constr.constraint(filter - filter_op_aux * op_inv);

    // Constrain mem value
    // LH: micro_op[0] * sign_extend::<16>((mem >> (16 - (rs & 2) * 8)) & 0xffff)
    {
        // Range value(rs[1]): rs[1] == 1
        let mut mem_val_1 = [P::ZEROS; 32];
        mem_val_1[0..16].copy_from_slice(&mem_limbs[0..16]);
        let mem_val_1 = sign_extend::<_, 16>(&mem_val_1);

        // Range value(rs[1]): rs[1] == 0
        let mut mem_val_0 = [P::ZEROS; 32];
        mem_val_0[0..16].copy_from_slice(&mem_limbs[16..32]);
        let mem_val_0 = sign_extend::<_, 16>(&mem_val_0);

        let mem_val_1 = limb_from_bits_le(mem_val_1);
        let mem_val_0 = limb_from_bits_le(mem_val_0);

        // Range check
        enforce_half_word(
            yield_constr,
            lv,
            filter,
            0,
            &rs_limbs,
            mem,
            mem_val_1,
            mem_val_0,
        );
    }

    // LWL:
    //    let val = mem << ((rs & 3) * 8);
    //    let mask = 0xffFFffFFu32 << ((rs & 3) * 8);
    //    (rt & (!mask)) | val
    //  Use mem_val_{rs[0]}_{rs[1]} to indicate the mem value for different value on rs' first and
    //  second bit
    {
        let mut mem_val_0_0 = [P::ZEROS; 32];
        let mut mem_val_0_1 = [P::ZEROS; 32];
        let mut mem_val_1_0 = [P::ZEROS; 32];
        let mut mem_val_1_1 = [P::ZEROS; 32];

        mem_val_0_0[0..32].copy_from_slice(&mem_limbs[0..32]);

        mem_val_1_0[0..8].copy_from_slice(&rt_limbs[0..8]);
        mem_val_1_0[8..].copy_from_slice(&mem_limbs[0..24]);

        mem_val_0_1[0..16].copy_from_slice(&rt_limbs[0..16]);
        mem_val_0_1[16..].copy_from_slice(&mem_limbs[0..16]);

        mem_val_1_1[0..24].copy_from_slice(&rt_limbs[0..24]);
        mem_val_1_1[24..].copy_from_slice(&mem_limbs[0..8]);

        let mem_val_0_0 = limb_from_bits_le(mem_val_0_0);
        let mem_val_1_0 = limb_from_bits_le(mem_val_1_0);
        let mem_val_0_1 = limb_from_bits_le(mem_val_0_1);
        let mem_val_1_1 = limb_from_bits_le(mem_val_1_1);

        enforce_byte(
            yield_constr,
            lv,
            filter,
            1,
            &rs_limbs,
            mem,
            mem_val_0_0,
            mem_val_1_0,
            mem_val_0_1,
            mem_val_1_1,
        );
    }

    // LW:
    {
        let mem_value = limb_from_bits_le(mem_limbs);
        enforce_word(yield_constr, lv, filter, 2, mem, mem_value);
    }

    // LBU: (mem >> (24 - (rs & 3) * 8)) & 0xff
    {
        let mut mem_val_0_0 = [P::ZEROS; 32];
        let mut mem_val_0_1 = [P::ZEROS; 32];
        let mut mem_val_1_0 = [P::ZEROS; 32];
        let mut mem_val_1_1 = [P::ZEROS; 32];

        mem_val_0_0[0..8].copy_from_slice(&mem_limbs[24..32]);
        mem_val_1_0[0..8].copy_from_slice(&mem_limbs[16..24]);
        mem_val_0_1[0..8].copy_from_slice(&mem_limbs[8..16]);
        mem_val_1_1[0..8].copy_from_slice(&mem_limbs[0..8]);

        let mem_val_0_0 = limb_from_bits_le(mem_val_0_0);
        let mem_val_1_0 = limb_from_bits_le(mem_val_1_0);
        let mem_val_0_1 = limb_from_bits_le(mem_val_0_1);
        let mem_val_1_1 = limb_from_bits_le(mem_val_1_1);

        enforce_byte(
            yield_constr,
            lv,
            filter,
            3,
            &rs_limbs,
            mem,
            mem_val_0_0,
            mem_val_1_0,
            mem_val_0_1,
            mem_val_1_1,
        );
    }

    // LHU: (mem >> (16 - (rs & 2) * 8)) & 0xffff
    {
        let mut mem_val_0 = [P::ZEROS; 32];
        let mut mem_val_1 = [P::ZEROS; 32];

        mem_val_0[0..16].copy_from_slice(&mem_limbs[16..32]);
        mem_val_1[0..16].copy_from_slice(&mem_limbs[0..16]);

        let mem_val_1 = limb_from_bits_le(mem_val_1);
        let mem_val_0 = limb_from_bits_le(mem_val_0);

        enforce_half_word(
            yield_constr,
            lv,
            filter,
            4,
            &rs_limbs,
            mem,
            mem_val_1,
            mem_val_0,
        );
    }

    // LWR:
    //     let val = mem >> (24 - (rs & 3) * 8);
    //     let mask = 0xffFFffFFu32 >> (24 - (rs & 3) * 8);
    //     (rt & (!mask)) | val
    {
        let mut mem_val_0_0 = [P::ZEROS; 32];
        let mut mem_val_0_1 = [P::ZEROS; 32];
        let mut mem_val_1_0 = [P::ZEROS; 32];
        let mut mem_val_1_1 = [P::ZEROS; 32];

        mem_val_0_0[8..].copy_from_slice(&rt_limbs[8..32]);
        mem_val_0_0[0..8].copy_from_slice(&mem_limbs[24..32]);

        mem_val_1_0[16..].copy_from_slice(&rt_limbs[16..32]);
        mem_val_1_0[0..16].copy_from_slice(&mem_limbs[16..32]);

        mem_val_0_1[24..].copy_from_slice(&rt_limbs[24..32]);
        mem_val_0_1[0..24].copy_from_slice(&mem_limbs[8..32]);

        mem_val_1_1[0..32].copy_from_slice(&mem_limbs[..]);

        let mem_val_0_0 = limb_from_bits_le(mem_val_0_0);
        let mem_val_1_0 = limb_from_bits_le(mem_val_1_0);
        let mem_val_0_1 = limb_from_bits_le(mem_val_0_1);
        let mem_val_1_1 = limb_from_bits_le(mem_val_1_1);

        enforce_byte(
            yield_constr,
            lv,
            filter,
            6,
            &rs_limbs,
            mem,
            mem_val_0_0,
            mem_val_1_0,
            mem_val_0_1,
            mem_val_1_1,
        );
    }

    // LL:
    {
        let mem_value = limb_from_bits_le(mem_limbs);
        enforce_word(yield_constr, lv, filter, 6, mem, mem_value);
    }

    // LB: sign_extend::<8>((mem >> (24 - (rs & 3) * 8)) & 0xff)
    {
        let mut mem_val_0_0 = [P::ZEROS; 32];
        let mut mem_val_0_1 = [P::ZEROS; 32];
        let mut mem_val_1_0 = [P::ZEROS; 32];
        let mut mem_val_1_1 = [P::ZEROS; 32];

        mem_val_0_0[0..8].copy_from_slice(&mem_limbs[24..]);
        mem_val_1_0[0..8].copy_from_slice(&mem_limbs[16..24]);
        mem_val_0_1[0..8].copy_from_slice(&mem_limbs[8..16]);
        mem_val_1_1[0..8].copy_from_slice(&mem_limbs[0..8]);

        let mem_val_0_0 = sign_extend::<_, 8>(&mem_val_0_0);
        let mem_val_1_0 = sign_extend::<_, 8>(&mem_val_1_0);
        let mem_val_0_1 = sign_extend::<_, 8>(&mem_val_0_1);
        let mem_val_1_1 = sign_extend::<_, 8>(&mem_val_1_1);

        let mem_val_0_0 = limb_from_bits_le(mem_val_0_0);
        let mem_val_1_0 = limb_from_bits_le(mem_val_1_0);
        let mem_val_0_1 = limb_from_bits_le(mem_val_0_1);
        let mem_val_1_1 = limb_from_bits_le(mem_val_1_1);

        enforce_byte(
            yield_constr,
            lv,
            filter,
            7,
            &rs_limbs,
            mem,
            mem_val_0_0,
            mem_val_1_0,
            mem_val_0_1,
            mem_val_1_1,
        );
    }

    // Disable remaining memory channels, if any.
    // Note: SC needs 5 channel
    for &channel in &lv.mem_channels[6..(NUM_GP_CHANNELS - 1)] {
        yield_constr.constraint(filter * channel.used);
    }
}

fn eval_ext_circuit_load<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    _nv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let zeros = builder.zero_extension();
    let ones = builder.one_extension();
    let filter = builder.mul_extension(lv.op.m_op_load, lv.opcode_bits[5]);

    // Check mem channel segment is register
    let diff = builder.add_const_extension(
        lv.mem_channels[0].addr_segment,
        -F::from_canonical_u64(Segment::RegisterFile as u64),
    );
    let constr = builder.mul_extension(filter, diff);
    yield_constr.constraint(builder, constr);

    let diff = builder.add_const_extension(
        lv.mem_channels[1].addr_segment,
        -F::from_canonical_u64(Segment::RegisterFile as u64),
    );
    let constr = builder.mul_extension(filter, diff);
    yield_constr.constraint(builder, constr);

    let rs = lv.mem_channels[0].value[0];
    let rt = lv.mem_channels[1].value[0];
    let mem = lv.mem_channels[3].value[0];
    let rs_limbs = lv.general.io().rs_le;
    let rt_limbs = lv.general.io().rt_le;
    let mem_limbs = lv.general.io().mem_le;

    // Calculate rs:
    //    let virt_raw = (rs as u32).wrapping_add(sign_extend::<16>(offset));
    let offset = load_offset_ext(builder, lv);
    let virt_raw = builder.add_extension(rs, offset);

    let u32max = F::from_canonical_u64(1u64 << 32);
    //yield_constr.constraint(filter * (rs_from_bits - virt_raw) * (rs_from_bits + u32max - virt_raw));
    let rs_from_bits = limb_from_bits_le_recursive(builder, rs_limbs);
    let diff1 = builder.sub_extension(rs_from_bits, virt_raw);

    let diff2 = builder.add_const_extension(rs_from_bits, u32max);
    let diff2 = builder.sub_extension(diff2, virt_raw);

    let constr = builder.mul_many_extension([filter, diff1, diff2]);
    yield_constr.constraint(builder, constr);

    let rt_from_bits = limb_from_bits_le_recursive(builder, rt_limbs);
    let diff = builder.sub_extension(rt_from_bits, rt);
    let constr = builder.mul_extension(filter, diff);
    yield_constr.constraint(builder, constr);

    // Constrain mem address
    //    let virt = virt_raw & 0xFFFF_FFFC;
    let mut tmp = rs_limbs;
    tmp[0] = zeros;
    tmp[1] = zeros;
    let virt = limb_from_bits_le_recursive(builder, tmp);

    let mem_virt = lv.mem_channels[2].addr_virtual;
    let diff = builder.sub_extension(virt, mem_virt);
    let constr = builder.mul_extension(filter, diff);
    yield_constr.constraint(builder, constr);

    // Verify op
    let op_inv = lv.general.io().diff_inv;
    let op = lv.mem_channels[4].value[0];
    let mul = builder.mul_extension(op, op_inv);
    let diff = builder.sub_extension(ones, mul);
    let constr = builder.mul_extension(filter, diff);
    yield_constr.constraint(builder, constr);

    // Constrain mem value
    // LH: micro_op[0] * sign_extend::<16>((mem >> (16 - (rs & 2) * 8)) & 0xffff)
    {
        // Range value(rs[1]): rs[1] == 1
        let mut mem_val_1 = [zeros; 32];
        mem_val_1[0..16].copy_from_slice(&mem_limbs[0..16]);
        let mem_val_1 = sign_extend_ext::<_, D, 16>(builder, &mem_val_1);

        // Range value(rs[1]): rs[1] == 0
        let mut mem_val_0 = [zeros; 32];
        mem_val_0[0..16].copy_from_slice(&mem_limbs[16..32]);
        let mem_val_0 = sign_extend_ext::<_, D, 16>(builder, &mem_val_0);

        let mem_val_1 = limb_from_bits_le_recursive(builder, mem_val_1);
        let mem_val_0 = limb_from_bits_le_recursive(builder, mem_val_0);

        // Range check
        // let sum = rs_limbs[1] * (mem - mem_val_1) + (rs_limbs[1] - P::ONES) * (mem - mem_val_0);
        // yield_constr.constraint(filter * lv.general.io().micro_op[0] * sum);
        let diff1 = builder.sub_extension(mem, mem_val_1);
        let diff2 = builder.sub_extension(mem, mem_val_0);
        let coff2 = builder.add_const_extension(rs_limbs[1], -F::ONES);
        let mult2 = builder.mul_extension(diff2, coff2);
        let sum = builder.arithmetic_extension(F::ONES, F::ONES, rs_limbs[1], diff1, mult2);
        let mult = builder.mul_many_extension([filter, lv.general.io().micro_op[0], sum]);
        yield_constr.constraint(builder, mult);
    }

    // LWL:
    //    let val = mem << ((rs & 3) * 8);
    //    let mask = 0xffFFffFFu32 << ((rs & 3) * 8);
    //    (rt & (!mask)) | val
    //  Use mem_val_{rs[0]}_{rs[1]} to indicate the mem value for different value on rs' first and
    //  second bit
    {
        let mut mem_val_0_0 = [zeros; 32];
        let mut mem_val_0_1 = [zeros; 32];
        let mut mem_val_1_0 = [zeros; 32];
        let mut mem_val_1_1 = [zeros; 32];

        mem_val_0_0[0..32].copy_from_slice(&mem_limbs[0..32]);

        mem_val_1_0[0..8].copy_from_slice(&rt_limbs[0..8]);
        mem_val_1_0[8..].copy_from_slice(&mem_limbs[0..24]);

        mem_val_0_1[0..16].copy_from_slice(&rt_limbs[0..16]);
        mem_val_0_1[16..].copy_from_slice(&mem_limbs[0..16]);

        mem_val_1_1[0..24].copy_from_slice(&rt_limbs[0..24]);
        mem_val_1_1[24..].copy_from_slice(&mem_limbs[0..8]);

        let mem_val_0_0 = limb_from_bits_le_recursive(builder, mem_val_0_0);
        let mem_val_1_0 = limb_from_bits_le_recursive(builder, mem_val_1_0);
        let mem_val_0_1 = limb_from_bits_le_recursive(builder, mem_val_0_1);
        let mem_val_1_1 = limb_from_bits_le_recursive(builder, mem_val_1_1);

        // let sum =
        //     (mem - mem_val_0_0) * (rs_limbs[1] - P::ONES) * (rs_limbs[0] - P::ONES) +
        //     (mem - mem_val_1_0) * (rs_limbs[1] - P::ONES) * rs_limbs[0] +
        //     (mem - mem_val_0_1) * rs_limbs[1] * (rs_limbs[0] - P::ONES) +
        //     (mem - mem_val_1_1) * rs_limbs[1] * rs_limbs[0];
        // yield_constr.constraint(filter * lv.general.io().micro_op[1] * sum);
        let diff1 = builder.sub_extension(mem, mem_val_0_0);
        let diff2 = builder.sub_extension(mem, mem_val_1_0);
        let diff3 = builder.sub_extension(mem, mem_val_0_1);
        let diff4 = builder.sub_extension(mem, mem_val_1_1);

        let coff10 = builder.add_const_extension(rs_limbs[0], -F::ONES);
        let coff11 = builder.add_const_extension(rs_limbs[1], -F::ONES);
        let sum1 = builder.mul_many_extension([diff1, coff10, coff11]);

        let coff21 = builder.add_const_extension(rs_limbs[1], -F::ONES);
        let sum2 = builder.mul_many_extension([diff2, coff21, rs_limbs[0]]);

        let coff30 = builder.add_const_extension(rs_limbs[0], -F::ONES);
        let sum3 = builder.mul_many_extension([diff3, rs_limbs[1], coff30]);

        let sum4 = builder.mul_many_extension([diff4, rs_limbs[1], rs_limbs[0]]);

        let sum = builder.add_many_extension([sum1, sum2, sum3, sum4]);

        let mult = builder.mul_many_extension([filter, lv.general.io().micro_op[1], sum]);
        yield_constr.constraint(builder, mult);
    }

    // LW:
    {
        let mem_value = limb_from_bits_le_recursive(builder, mem_limbs);
        // yield_constr.constraint(filter * lv.general.io().micro_op[2] * (mem - mem_value));
        let diff1 = builder.sub_extension(mem, mem_value);
        let mult = builder.mul_many_extension([filter, lv.general.io().micro_op[2], diff1]);
        yield_constr.constraint(builder, mult);
    }

    // LBU: (mem >> (24 - (rs & 3) * 8)) & 0xff
    {
        let mut mem_val_0_0 = [zeros; 32];
        let mut mem_val_0_1 = [zeros; 32];
        let mut mem_val_1_0 = [zeros; 32];
        let mut mem_val_1_1 = [zeros; 32];

        mem_val_0_0[0..8].copy_from_slice(&mem_limbs[24..32]);
        mem_val_1_0[0..8].copy_from_slice(&mem_limbs[16..24]);
        mem_val_0_1[0..8].copy_from_slice(&mem_limbs[8..16]);
        mem_val_1_1[0..8].copy_from_slice(&mem_limbs[0..8]);

        let mem_val_0_0 = limb_from_bits_le_recursive(builder, mem_val_0_0);
        let mem_val_1_0 = limb_from_bits_le_recursive(builder, mem_val_1_0);
        let mem_val_0_1 = limb_from_bits_le_recursive(builder, mem_val_0_1);
        let mem_val_1_1 = limb_from_bits_le_recursive(builder, mem_val_1_1);

        /*
        //yield_constr.constraint(filter * lv.general.io().micro_op[3]
        //    * (mem - mem_val_0_0) * (mem - mem_val_0_1)
        //    * (mem - mem_val_1_0) * (mem - mem_val_1_1));
        let diff1 = builder.sub_extension(mem, mem_val_0_0);
        let diff2 = builder.sub_extension(mem, mem_val_0_1);
        let diff3 = builder.sub_extension(mem, mem_val_1_0);
        let diff4 = builder.sub_extension(mem, mem_val_1_1);
        let mult = builder.mul_many_extension([filter, lv.general.io().micro_op[3], diff1, diff2, diff3, diff4]);
        yield_constr.constraint(builder, mult);
        */

        let diff1 = builder.sub_extension(mem, mem_val_0_0);
        let diff2 = builder.sub_extension(mem, mem_val_1_0);
        let diff3 = builder.sub_extension(mem, mem_val_0_1);
        let diff4 = builder.sub_extension(mem, mem_val_1_1);

        let coff10 = builder.add_const_extension(rs_limbs[0], -F::ONES);
        let coff11 = builder.add_const_extension(rs_limbs[1], -F::ONES);
        let sum1 = builder.mul_many_extension([diff1, coff10, coff11]);

        let coff21 = builder.add_const_extension(rs_limbs[1], -F::ONES);
        let sum2 = builder.mul_many_extension([diff2, coff21, rs_limbs[0]]);

        let coff30 = builder.add_const_extension(rs_limbs[0], -F::ONES);
        let sum3 = builder.mul_many_extension([diff3, rs_limbs[1], coff30]);

        let sum4 = builder.mul_many_extension([diff4, rs_limbs[1], rs_limbs[0]]);

        let sum = builder.add_many_extension([sum1, sum2, sum3, sum4]);

        let mult = builder.mul_many_extension([filter, lv.general.io().micro_op[3], sum]);
        yield_constr.constraint(builder, mult);
    }

    // LHU: (mem >> (16 - (rs & 2) * 8)) & 0xffff
    {
        let mut mem_val_0 = [zeros; 32];
        let mut mem_val_1 = [zeros; 32];

        mem_val_0[0..16].copy_from_slice(&mem_limbs[16..32]);
        mem_val_1[0..16].copy_from_slice(&mem_limbs[0..16]);

        let mem_val_1 = limb_from_bits_le_recursive(builder, mem_val_1);
        let mem_val_0 = limb_from_bits_le_recursive(builder, mem_val_0);

        let diff1 = builder.sub_extension(mem, mem_val_1);
        let diff2 = builder.sub_extension(mem, mem_val_0);
        let coff2 = builder.add_const_extension(rs_limbs[1], -F::ONES);
        let mult2 = builder.mul_extension(diff2, coff2);
        let sum = builder.arithmetic_extension(F::ONES, F::ONES, rs_limbs[1], diff1, mult2);
        let mult = builder.mul_many_extension([filter, lv.general.io().micro_op[4], sum]);
        yield_constr.constraint(builder, mult);
    }

    // LWR:
    //     let val = mem >> (24 - (rs & 3) * 8);
    //     let mask = 0xffFFffFFu32 >> (24 - (rs & 3) * 8);
    //     (rt & (!mask)) | val
    {
        let mut mem_val_0_0 = [zeros; 32];
        let mut mem_val_0_1 = [zeros; 32];
        let mut mem_val_1_0 = [zeros; 32];
        let mut mem_val_1_1 = [zeros; 32];

        mem_val_0_0[8..].copy_from_slice(&rt_limbs[8..32]);
        mem_val_0_0[0..8].copy_from_slice(&mem_limbs[24..32]);

        mem_val_1_0[16..].copy_from_slice(&rt_limbs[16..32]);
        mem_val_1_0[0..16].copy_from_slice(&mem_limbs[16..32]);

        mem_val_0_1[24..].copy_from_slice(&rt_limbs[24..32]);
        mem_val_0_1[0..24].copy_from_slice(&mem_limbs[8..32]);

        mem_val_1_1[0..32].copy_from_slice(&mem_limbs[..]);

        let mem_val_0_0 = limb_from_bits_le_recursive(builder, mem_val_0_0);
        let mem_val_1_0 = limb_from_bits_le_recursive(builder, mem_val_1_0);
        let mem_val_0_1 = limb_from_bits_le_recursive(builder, mem_val_0_1);
        let mem_val_1_1 = limb_from_bits_le_recursive(builder, mem_val_1_1);

        //let sum = (mem - mem_val_0_0) * (rs_limbs[1] - P::ONES) * (rs_limbs[0] - P::ONES)
        //    + (mem - mem_val_1_0) * (rs_limbs[1] - P::ONES) * rs_limbs[0]
        //    + (mem - mem_val_0_1) * rs_limbs[1] * (rs_limbs[0] - P::ONES)
        //    + (mem - mem_val_1_1) * rs_limbs[1] * rs_limbs[0];
        //yield_constr.constraint(filter * lv.general.io().micro_op[5] * sum);
        let diff1 = builder.sub_extension(mem, mem_val_0_0);
        let diff2 = builder.sub_extension(mem, mem_val_1_0);
        let diff3 = builder.sub_extension(mem, mem_val_0_1);
        let diff4 = builder.sub_extension(mem, mem_val_1_1);

        let coff10 = builder.add_const_extension(rs_limbs[0], -F::ONES);
        let coff11 = builder.add_const_extension(rs_limbs[1], -F::ONES);
        let sum1 = builder.mul_many_extension([diff1, coff10, coff11]);

        let coff21 = builder.add_const_extension(rs_limbs[1], -F::ONES);
        let sum2 = builder.mul_many_extension([diff2, coff21, rs_limbs[0]]);

        let coff30 = builder.add_const_extension(rs_limbs[0], -F::ONES);
        let sum3 = builder.mul_many_extension([diff3, rs_limbs[1], coff30]);

        let sum4 = builder.mul_many_extension([diff4, rs_limbs[1], rs_limbs[0]]);

        let sum = builder.add_many_extension([sum1, sum2, sum3, sum4]);

        let mult = builder.mul_many_extension([filter, lv.general.io().micro_op[5], sum]);
        yield_constr.constraint(builder, mult);
    }

    // LL:
    {
        let mem_value = limb_from_bits_le_recursive(builder, mem_limbs);
        // yield_constr.constraint(filter * lv.general.io().micro_op[6] * (mem - mem_value));
        let diff1 = builder.sub_extension(mem, mem_value);
        let mult = builder.mul_many_extension([filter, lv.general.io().micro_op[6], diff1]);
        yield_constr.constraint(builder, mult);
    }

    // LB: sign_extend::<8>((mem >> (24 - (rs & 3) * 8)) & 0xff)
    {
        let mut mem_val_0_0 = [zeros; 32];
        let mut mem_val_0_1 = [zeros; 32];
        let mut mem_val_1_0 = [zeros; 32];
        let mut mem_val_1_1 = [zeros; 32];

        mem_val_0_0[0..8].copy_from_slice(&mem_limbs[24..]);
        mem_val_1_0[0..8].copy_from_slice(&mem_limbs[16..24]);
        mem_val_0_1[0..8].copy_from_slice(&mem_limbs[8..16]);
        mem_val_1_1[0..8].copy_from_slice(&mem_limbs[0..8]);

        let mem_val_0_0 = sign_extend_ext::<_, D, 8>(builder, &mem_val_0_0);
        let mem_val_1_0 = sign_extend_ext::<_, D, 8>(builder, &mem_val_1_0);
        let mem_val_0_1 = sign_extend_ext::<_, D, 8>(builder, &mem_val_0_1);
        let mem_val_1_1 = sign_extend_ext::<_, D, 8>(builder, &mem_val_1_1);

        let mem_val_0_0 = limb_from_bits_le_recursive(builder, mem_val_0_0);
        let mem_val_1_0 = limb_from_bits_le_recursive(builder, mem_val_1_0);
        let mem_val_0_1 = limb_from_bits_le_recursive(builder, mem_val_0_1);
        let mem_val_1_1 = limb_from_bits_le_recursive(builder, mem_val_1_1);

        let diff1 = builder.sub_extension(mem, mem_val_0_0);
        let diff2 = builder.sub_extension(mem, mem_val_1_0);
        let diff3 = builder.sub_extension(mem, mem_val_0_1);
        let diff4 = builder.sub_extension(mem, mem_val_1_1);

        let coff10 = builder.add_const_extension(rs_limbs[0], -F::ONES);
        let coff11 = builder.add_const_extension(rs_limbs[1], -F::ONES);
        let sum1 = builder.mul_many_extension([diff1, coff10, coff11]);

        let coff21 = builder.add_const_extension(rs_limbs[1], -F::ONES);
        let sum2 = builder.mul_many_extension([diff2, coff21, rs_limbs[0]]);

        let coff30 = builder.add_const_extension(rs_limbs[0], -F::ONES);
        let sum3 = builder.mul_many_extension([diff3, rs_limbs[1], coff30]);

        let sum4 = builder.mul_many_extension([diff4, rs_limbs[1], rs_limbs[0]]);

        let sum = builder.add_many_extension([sum1, sum2, sum3, sum4]);

        let mult = builder.mul_many_extension([filter, lv.general.io().micro_op[7], sum]);
        yield_constr.constraint(builder, mult);
    }

    // Disable remaining memory channels, if any.
    for &channel in &lv.mem_channels[6..(NUM_GP_CHANNELS - 1)] {
        let constr = builder.mul_extension(filter, channel.used);
        yield_constr.constraint(builder, constr);
    }
}

fn eval_packed_store<P: PackedField>(
    lv: &CpuColumnsView<P>,
    _nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let filter = lv.op.m_op_store * lv.opcode_bits[5];

    // Check mem channel segment is register
    let diff = lv.mem_channels[0].addr_segment
        - P::Scalar::from_canonical_u64(Segment::RegisterFile as u64);
    yield_constr.constraint(filter * diff);
    let diff = lv.mem_channels[1].addr_segment
        - P::Scalar::from_canonical_u64(Segment::RegisterFile as u64);
    yield_constr.constraint(filter * diff);

    // Check memory is used
    // Check is_read is 0/1

    let rs = lv.mem_channels[0].value[0];
    let rt = lv.mem_channels[1].value[0];
    let mem = lv.mem_channels[3].value[0];
    let rs_limbs = lv.general.io().rs_le;
    let rt_limbs = lv.general.io().rt_le;
    let mem_limbs = lv.general.io().mem_le;

    // Calculate rs:
    //    let virt_raw = (rs as u32).wrapping_add(sign_extend::<16>(offset));
    let offset = load_offset(lv);
    let virt_raw = rs + offset;

    let rs_from_bits = limb_from_bits_le(rs_limbs);
    let u32max = P::Scalar::from_canonical_u64(1u64 << 32);

    let virt_raw_check = filter * (rs_from_bits - virt_raw);
    let virt_raw_check_aux = lv.mem_channels[0].value[1];
    yield_constr.constraint(virt_raw_check - virt_raw_check_aux);
    yield_constr.constraint(virt_raw_check_aux * (rs_from_bits + u32max - virt_raw));

    let rt_from_bits = limb_from_bits_le(rt_limbs);
    yield_constr.constraint(filter * (rt_from_bits - rt));

    // Constrain mem address
    //    let virt = virt_raw & 0xFFFF_FFFC;
    let mut tmp = rs_limbs;
    tmp[0] = P::ZEROS;
    tmp[1] = P::ZEROS;
    let virt = limb_from_bits_le(tmp);

    let mem_virt = lv.mem_channels[2].addr_virtual;
    yield_constr.constraint(filter * (virt - mem_virt));

    // Verify op
    let op_inv = lv.general.io().diff_inv;
    let op = lv.mem_channels[5].value[0];
    let filter_op = filter * op;
    let filter_op_aux = lv.mem_channels[0].value[2];
    yield_constr.constraint(filter_op - filter_op_aux);
    yield_constr.constraint(filter - filter_op_aux * op_inv);

    // Constrain mem value
    // SB:
    //    let val = (rt & 0xff) << (24 - (rs & 3) * 8);
    //    let mask = 0xffFFffFFu32 ^ (0xff << (24 - (rs & 3) * 8));
    //    (mem & mask) | val
    {
        let mut mem_val_0_0 = [P::ZEROS; 32];
        let mut mem_val_1_0 = [P::ZEROS; 32];
        let mut mem_val_0_1 = [P::ZEROS; 32];
        let mut mem_val_1_1 = [P::ZEROS; 32];

        // rs[0] = 0, rs[1] = 0
        mem_val_0_0[24..].copy_from_slice(&rt_limbs[0..8]);
        mem_val_0_0[0..24].copy_from_slice(&mem_limbs[0..24]);
        // rs[0] = 1, rs[1] = 0
        mem_val_1_0[24..].copy_from_slice(&mem_limbs[24..]);
        mem_val_1_0[16..24].copy_from_slice(&rt_limbs[0..8]);
        mem_val_1_0[0..16].copy_from_slice(&mem_limbs[0..16]);
        // rs[0] = 0, rs[1] = 1
        mem_val_0_1[16..].copy_from_slice(&mem_limbs[16..]);
        mem_val_0_1[8..16].copy_from_slice(&rt_limbs[0..8]);
        mem_val_0_1[0..8].copy_from_slice(&mem_limbs[0..8]);
        // rs[0] = 1, rs[1] = 1
        mem_val_1_1[0..8].copy_from_slice(&rt_limbs[0..8]);
        mem_val_1_1[8..].copy_from_slice(&mem_limbs[8..]);

        let mem_val_0_0 = limb_from_bits_le(mem_val_0_0);
        let mem_val_1_0 = limb_from_bits_le(mem_val_1_0);
        let mem_val_0_1 = limb_from_bits_le(mem_val_0_1);
        let mem_val_1_1 = limb_from_bits_le(mem_val_1_1);

        enforce_byte(
            yield_constr,
            lv,
            filter,
            0,
            &rs_limbs,
            mem,
            mem_val_0_0,
            mem_val_1_0,
            mem_val_0_1,
            mem_val_1_1,
        );
    }

    // SH
    //    let val = (rt & 0xffff) << (16 - (rs & 2) * 8);
    //    let mask = 0xffFFffFFu32 ^ (0xffff << (16 - (rs & 2) * 8));
    //    (mem & mask) | val
    {
        let mut mem_val_0 = [P::ZEROS; 32];
        let mut mem_val_1 = [P::ZEROS; 32];

        mem_val_0[16..].copy_from_slice(&rt_limbs[0..16]);
        mem_val_0[0..16].copy_from_slice(&mem_limbs[0..16]);

        mem_val_1[0..16].copy_from_slice(&rt_limbs[0..16]);
        mem_val_1[16..].copy_from_slice(&mem_limbs[16..]);

        let mem_val_1 = limb_from_bits_le(mem_val_1);
        let mem_val_0 = limb_from_bits_le(mem_val_0);

        enforce_half_word(
            yield_constr,
            lv,
            filter,
            1,
            &rs_limbs,
            mem,
            mem_val_1,
            mem_val_0,
        );
    }

    // SWL
    //    let val = rt >> ((rs & 3) * 8);
    //    let mask = 0xffFFffFFu32 >> ((rs & 3) * 8);
    //    (mem & (!mask)) | val
    {
        let mut mem_val_0_0 = [P::ZEROS; 32];
        let mut mem_val_1_0 = [P::ZEROS; 32];
        let mut mem_val_0_1 = [P::ZEROS; 32];
        let mut mem_val_1_1 = [P::ZEROS; 32];

        // rs[0] = 0, rs[1] = 0
        mem_val_0_0[..].copy_from_slice(&rt_limbs[..]);
        // rs[0] = 1, rs[1] = 0
        mem_val_1_0[0..24].copy_from_slice(&rt_limbs[8..]);
        mem_val_1_0[24..].copy_from_slice(&mem_limbs[24..]);
        // rs[0] = 0, rs[1] = 1
        mem_val_0_1[0..16].copy_from_slice(&rt_limbs[16..]);
        mem_val_0_1[16..].copy_from_slice(&mem_limbs[16..]);
        // rs[0] = 1, rs[1] = 1
        mem_val_1_1[0..8].copy_from_slice(&rt_limbs[24..]);
        mem_val_1_1[8..].copy_from_slice(&mem_limbs[8..]);

        let mem_val_0_0 = limb_from_bits_le(mem_val_0_0);
        let mem_val_1_0 = limb_from_bits_le(mem_val_1_0);
        let mem_val_0_1 = limb_from_bits_le(mem_val_0_1);
        let mem_val_1_1 = limb_from_bits_le(mem_val_1_1);

        enforce_byte(
            yield_constr,
            lv,
            filter,
            2,
            &rs_limbs,
            mem,
            mem_val_0_0,
            mem_val_1_0,
            mem_val_0_1,
            mem_val_1_1,
        );
    }

    // SW
    {
        let rt_value = limb_from_bits_le(rt_limbs);
        enforce_word(yield_constr, lv, filter, 3, mem, rt_value);
    }

    // SWR
    //    let val = rt << (24 - (rs & 3) * 8);
    //    let mask = 0xffFFffFFu32 << (24 - (rs & 3) * 8);
    //    (mem & (!mask)) | val
    {
        let mut mem_val_0_0 = [P::ZEROS; 32];
        let mut mem_val_1_0 = [P::ZEROS; 32];
        let mut mem_val_0_1 = [P::ZEROS; 32];
        let mut mem_val_1_1 = [P::ZEROS; 32];

        // rs[0] = 0, rs[1] = 0
        mem_val_0_0[24..].copy_from_slice(&rt_limbs[0..8]);
        mem_val_0_0[0..24].copy_from_slice(&mem_limbs[0..24]);
        // rs[0] = 1, rs[1] = 0
        mem_val_1_0[16..].copy_from_slice(&rt_limbs[0..16]);
        mem_val_1_0[0..16].copy_from_slice(&mem_limbs[0..16]);
        // rs[0] = 0, rs[1] = 1
        mem_val_0_1[8..].copy_from_slice(&rt_limbs[0..24]);
        mem_val_0_1[0..8].copy_from_slice(&mem_limbs[0..8]);
        // rs[0] = 1, rs[1] = 1
        mem_val_1_1[..].copy_from_slice(&rt_limbs[..]);

        let mem_val_0_0 = limb_from_bits_le(mem_val_0_0);
        let mem_val_1_0 = limb_from_bits_le(mem_val_1_0);
        let mem_val_0_1 = limb_from_bits_le(mem_val_0_1);
        let mem_val_1_1 = limb_from_bits_le(mem_val_1_1);

        enforce_byte(
            yield_constr,
            lv,
            filter,
            4,
            &rs_limbs,
            mem,
            mem_val_0_0,
            mem_val_1_0,
            mem_val_0_1,
            mem_val_1_1,
        );
    }

    // SC:
    //  TODO: write back rt register
    {
        let rt_value = limb_from_bits_le(rt_limbs);
        enforce_word(yield_constr, lv, filter, 5, mem, rt_value);
    }

    // Disable remaining memory channels, if any.
    for &channel in &lv.mem_channels[6..(NUM_GP_CHANNELS - 1)] {
        yield_constr.constraint(filter * channel.used);
    }
}

fn eval_ext_circuit_store<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    _nv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let zeros = builder.zero_extension();
    let ones = builder.one_extension();
    let filter = builder.mul_extension(lv.op.m_op_store, lv.opcode_bits[5]);

    // Check mem channel segment is register
    let diff = builder.add_const_extension(
        lv.mem_channels[0].addr_segment,
        -F::from_canonical_u64(Segment::RegisterFile as u64),
    );
    let constr = builder.mul_extension(filter, diff);
    yield_constr.constraint(builder, constr);

    let diff = builder.add_const_extension(
        lv.mem_channels[1].addr_segment,
        -F::from_canonical_u64(Segment::RegisterFile as u64),
    );
    let constr = builder.mul_extension(filter, diff);
    yield_constr.constraint(builder, constr);

    let rs = lv.mem_channels[0].value[0];
    let rt = lv.mem_channels[1].value[0];
    let mem = lv.mem_channels[3].value[0];
    let rs_limbs = lv.general.io().rs_le;
    let rt_limbs = lv.general.io().rt_le;
    let mem_limbs = lv.general.io().mem_le;

    // Calculate rs:
    //    let virt_raw = (rs as u32).wrapping_add(sign_extend::<16>(offset));
    let offset = load_offset_ext(builder, lv);
    let virt_raw = builder.add_extension(rs, offset);

    let u32max = F::from_canonical_u64(1u64 << 32);
    //yield_constr.constraint(filter * (rs_from_bits - virt_raw) * (rs_from_bits + u32max - virt_raw));
    let rs_from_bits = limb_from_bits_le_recursive(builder, rs_limbs);
    let diff1 = builder.sub_extension(rs_from_bits, virt_raw);

    let diff2 = builder.add_const_extension(rs_from_bits, u32max);
    let diff2 = builder.sub_extension(diff2, virt_raw);

    let constr = builder.mul_many_extension([filter, diff1, diff2]);
    yield_constr.constraint(builder, constr);

    let rt_from_bits = limb_from_bits_le_recursive(builder, rt_limbs);
    let diff = builder.sub_extension(rt_from_bits, rt);
    let constr = builder.mul_extension(filter, diff);
    yield_constr.constraint(builder, constr);

    // Constrain mem address
    //    let virt = virt_raw & 0xFFFF_FFFC;
    let mut tmp = rs_limbs;
    tmp[0] = zeros;
    tmp[1] = zeros;
    let virt = limb_from_bits_le_recursive(builder, tmp);

    let mem_virt = lv.mem_channels[2].addr_virtual;
    let diff = builder.sub_extension(virt, mem_virt);
    let constr = builder.mul_extension(filter, diff);
    yield_constr.constraint(builder, constr);

    // Verify op
    let op_inv = lv.general.io().diff_inv;
    let op = lv.mem_channels[5].value[0];
    let mul = builder.mul_extension(op, op_inv);
    let diff = builder.sub_extension(ones, mul);
    let constr = builder.mul_extension(filter, diff);
    yield_constr.constraint(builder, constr);

    // Constrain mem value
    // SB:
    //    let val = (rt & 0xff) << (24 - (rs & 3) * 8);
    //    let mask = 0xffFFffFFu32 ^ (0xff << (24 - (rs & 3) * 8));
    //    (mem & mask) | val
    {
        let mut mem_val_0_0 = [zeros; 32];
        let mut mem_val_1_0 = [zeros; 32];
        let mut mem_val_0_1 = [zeros; 32];
        let mut mem_val_1_1 = [zeros; 32];

        // rs[0] = 0, rs[1] = 0
        mem_val_0_0[24..].copy_from_slice(&rt_limbs[0..8]);
        mem_val_0_0[0..24].copy_from_slice(&mem_limbs[0..24]);
        // rs[0] = 1, rs[1] = 0
        mem_val_1_0[24..].copy_from_slice(&mem_limbs[24..]);
        mem_val_1_0[16..24].copy_from_slice(&rt_limbs[0..8]);
        mem_val_1_0[0..16].copy_from_slice(&mem_limbs[0..16]);
        // rs[0] = 0, rs[1] = 1
        mem_val_0_1[16..].copy_from_slice(&mem_limbs[16..]);
        mem_val_0_1[8..16].copy_from_slice(&rt_limbs[0..8]);
        mem_val_0_1[0..8].copy_from_slice(&mem_limbs[0..8]);
        // rs[0] = 1, rs[1] = 1
        mem_val_1_1[0..8].copy_from_slice(&rt_limbs[0..8]);
        mem_val_1_1[8..].copy_from_slice(&mem_limbs[8..]);

        let mem_val_0_0 = limb_from_bits_le_recursive(builder, mem_val_0_0);
        let mem_val_1_0 = limb_from_bits_le_recursive(builder, mem_val_1_0);
        let mem_val_0_1 = limb_from_bits_le_recursive(builder, mem_val_0_1);
        let mem_val_1_1 = limb_from_bits_le_recursive(builder, mem_val_1_1);

        let diff1 = builder.sub_extension(mem, mem_val_0_0);
        let diff2 = builder.sub_extension(mem, mem_val_1_0);
        let diff3 = builder.sub_extension(mem, mem_val_0_1);
        let diff4 = builder.sub_extension(mem, mem_val_1_1);

        let coff10 = builder.add_const_extension(rs_limbs[0], -F::ONES);
        let coff11 = builder.add_const_extension(rs_limbs[1], -F::ONES);
        let sum1 = builder.mul_many_extension([diff1, coff10, coff11]);

        let coff21 = builder.add_const_extension(rs_limbs[1], -F::ONES);
        let sum2 = builder.mul_many_extension([diff2, coff21, rs_limbs[0]]);

        let coff30 = builder.add_const_extension(rs_limbs[0], -F::ONES);
        let sum3 = builder.mul_many_extension([diff3, rs_limbs[1], coff30]);

        let sum4 = builder.mul_many_extension([diff4, rs_limbs[1], rs_limbs[0]]);

        let sum = builder.add_many_extension([sum1, sum2, sum3, sum4]);

        let mult = builder.mul_many_extension([filter, lv.general.io().micro_op[0], sum]);
        yield_constr.constraint(builder, mult);
    }

    // SH
    //    let val = (rt & 0xffff) << (16 - (rs & 2) * 8);
    //    let mask = 0xffFFffFFu32 ^ (0xffff << (16 - (rs & 2) * 8));
    //    (mem & mask) | val
    {
        let mut mem_val_0 = [zeros; 32];
        let mut mem_val_1 = [zeros; 32];

        mem_val_0[16..].copy_from_slice(&rt_limbs[0..16]);
        mem_val_0[0..16].copy_from_slice(&mem_limbs[0..16]);

        mem_val_1[0..16].copy_from_slice(&rt_limbs[0..16]);
        mem_val_1[16..].copy_from_slice(&mem_limbs[16..]);

        let mem_val_1 = limb_from_bits_le_recursive(builder, mem_val_1);
        let mem_val_0 = limb_from_bits_le_recursive(builder, mem_val_0);

        let diff1 = builder.sub_extension(mem, mem_val_1);
        let diff2 = builder.sub_extension(mem, mem_val_0);
        let coff2 = builder.add_const_extension(rs_limbs[1], -F::ONES);
        let mult2 = builder.mul_extension(diff2, coff2);
        let sum = builder.arithmetic_extension(F::ONES, F::ONES, rs_limbs[1], diff1, mult2);
        let mult = builder.mul_many_extension([filter, lv.general.io().micro_op[1], sum]);
        yield_constr.constraint(builder, mult);
    }

    // SWL
    //    let val = rt >> ((rs & 3) * 8);
    //    let mask = 0xffFFffFFu32 >> ((rs & 3) * 8);
    //    (mem & (!mask)) | val
    {
        let mut mem_val_0_0 = [zeros; 32];
        let mut mem_val_1_0 = [zeros; 32];
        let mut mem_val_0_1 = [zeros; 32];
        let mut mem_val_1_1 = [zeros; 32];

        // rs[0] = 0, rs[1] = 0
        mem_val_0_0[..].copy_from_slice(&rt_limbs[..]);
        // rs[0] = 1, rs[1] = 0
        mem_val_1_0[0..24].copy_from_slice(&rt_limbs[8..]);
        mem_val_1_0[24..].copy_from_slice(&mem_limbs[24..]);
        // rs[0] = 0, rs[1] = 1
        mem_val_0_1[0..16].copy_from_slice(&rt_limbs[16..]);
        mem_val_0_1[16..].copy_from_slice(&mem_limbs[16..]);
        // rs[0] = 1, rs[1] = 1
        mem_val_1_1[0..8].copy_from_slice(&rt_limbs[24..]);
        mem_val_1_1[8..].copy_from_slice(&mem_limbs[8..]);

        let mem_val_0_0 = limb_from_bits_le_recursive(builder, mem_val_0_0);
        let mem_val_1_0 = limb_from_bits_le_recursive(builder, mem_val_1_0);
        let mem_val_0_1 = limb_from_bits_le_recursive(builder, mem_val_0_1);
        let mem_val_1_1 = limb_from_bits_le_recursive(builder, mem_val_1_1);

        let diff1 = builder.sub_extension(mem, mem_val_0_0);
        let diff2 = builder.sub_extension(mem, mem_val_1_0);
        let diff3 = builder.sub_extension(mem, mem_val_0_1);
        let diff4 = builder.sub_extension(mem, mem_val_1_1);

        let coff10 = builder.add_const_extension(rs_limbs[0], -F::ONES);
        let coff11 = builder.add_const_extension(rs_limbs[1], -F::ONES);
        let sum1 = builder.mul_many_extension([diff1, coff10, coff11]);

        let coff21 = builder.add_const_extension(rs_limbs[1], -F::ONES);
        let sum2 = builder.mul_many_extension([diff2, coff21, rs_limbs[0]]);

        let coff30 = builder.add_const_extension(rs_limbs[0], -F::ONES);
        let sum3 = builder.mul_many_extension([diff3, rs_limbs[1], coff30]);

        let sum4 = builder.mul_many_extension([diff4, rs_limbs[1], rs_limbs[0]]);

        let sum = builder.add_many_extension([sum1, sum2, sum3, sum4]);

        let mult = builder.mul_many_extension([filter, lv.general.io().micro_op[2], sum]);
        yield_constr.constraint(builder, mult);
    }

    // SW
    {
        let rt_value = limb_from_bits_le_recursive(builder, rt_limbs);
        //yield_constr.constraint(filter * lv.general.io().micro_op[3] * (mem - rt_value));
        let diff1 = builder.sub_extension(mem, rt_value);
        let mult = builder.mul_many_extension([filter, lv.general.io().micro_op[3], diff1]);
        yield_constr.constraint(builder, mult);
    }

    // SWR
    //    let val = rt << (24 - (rs & 3) * 8);
    //    let mask = 0xffFFffFFu32 << (24 - (rs & 3) * 8);
    //    (mem & (!mask)) | val
    {
        let mut mem_val_0_0 = [zeros; 32];
        let mut mem_val_1_0 = [zeros; 32];
        let mut mem_val_0_1 = [zeros; 32];
        let mut mem_val_1_1 = [zeros; 32];

        // rs[0] = 0, rs[1] = 0
        mem_val_0_0[24..].copy_from_slice(&rt_limbs[0..8]);
        mem_val_0_0[0..24].copy_from_slice(&mem_limbs[0..24]);
        // rs[0] = 1, rs[1] = 0
        mem_val_1_0[16..].copy_from_slice(&rt_limbs[0..16]);
        mem_val_1_0[0..16].copy_from_slice(&mem_limbs[0..16]);
        // rs[0] = 0, rs[1] = 1
        mem_val_0_1[8..].copy_from_slice(&rt_limbs[0..24]);
        mem_val_0_1[0..8].copy_from_slice(&mem_limbs[0..8]);
        // rs[0] = 1, rs[1] = 1
        mem_val_1_1[..].copy_from_slice(&rt_limbs[..]);

        let mem_val_0_0 = limb_from_bits_le_recursive(builder, mem_val_0_0);
        let mem_val_1_0 = limb_from_bits_le_recursive(builder, mem_val_1_0);
        let mem_val_0_1 = limb_from_bits_le_recursive(builder, mem_val_0_1);
        let mem_val_1_1 = limb_from_bits_le_recursive(builder, mem_val_1_1);

        let diff1 = builder.sub_extension(mem, mem_val_0_0);
        let diff2 = builder.sub_extension(mem, mem_val_1_0);
        let diff3 = builder.sub_extension(mem, mem_val_0_1);
        let diff4 = builder.sub_extension(mem, mem_val_1_1);

        let coff10 = builder.add_const_extension(rs_limbs[0], -F::ONES);
        let coff11 = builder.add_const_extension(rs_limbs[1], -F::ONES);
        let sum1 = builder.mul_many_extension([diff1, coff10, coff11]);

        let coff21 = builder.add_const_extension(rs_limbs[1], -F::ONES);
        let sum2 = builder.mul_many_extension([diff2, coff21, rs_limbs[0]]);

        let coff30 = builder.add_const_extension(rs_limbs[0], -F::ONES);
        let sum3 = builder.mul_many_extension([diff3, rs_limbs[1], coff30]);

        let sum4 = builder.mul_many_extension([diff4, rs_limbs[1], rs_limbs[0]]);

        let sum = builder.add_many_extension([sum1, sum2, sum3, sum4]);

        let mult = builder.mul_many_extension([filter, lv.general.io().micro_op[4], sum]);
        yield_constr.constraint(builder, mult);
    }

    // SC
    {
        let rt_value = limb_from_bits_le_recursive(builder, rt_limbs);
        //yield_constr.constraint(filter * lv.general.io().micro_op[5] * (mem - rt_value));
        let diff1 = builder.sub_extension(mem, rt_value);
        let mult = builder.mul_many_extension([filter, lv.general.io().micro_op[5], diff1]);
        yield_constr.constraint(builder, mult);
    }

    // Disable remaining memory channels, if any.
    // Skip last since it's used by reading code
    for &channel in &lv.mem_channels[6..(NUM_GP_CHANNELS - 1)] {
        let constr = builder.mul_extension(filter, channel.used);
        yield_constr.constraint(builder, constr);
    }
}

pub fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    eval_packed_load(lv, nv, yield_constr);
    eval_packed_store(lv, nv, yield_constr);
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    nv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    eval_ext_circuit_load(builder, lv, nv, yield_constr);
    eval_ext_circuit_store(builder, lv, nv, yield_constr);
}
