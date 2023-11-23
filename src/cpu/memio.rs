use itertools::izip;
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::gates::base_sum::BaseSumGate;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::plonk_common::reduce_with_powers;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::membus::NUM_GP_CHANNELS;
use crate::memory::segments::Segment;
use crate::util::{limb_from_bits_le, limb_from_bits_le_recursive};

/*
use once_cell::sync::Lazy;

pub static KERNEL: Lazy<Vec<>> = Lazy::new(combined_kernel);
*/

#[inline]
fn get_offset<P: PackedField>(lv: &CpuColumnsView<P>) -> P {
    let mut mem_offset = [P::ZEROS; 16];
    mem_offset[0..6].copy_from_slice(&lv.func_bits); // 6 bits
    mem_offset[6..11].copy_from_slice(&lv.shamt_bits); // 5 bits
    mem_offset[11..16].copy_from_slice(&lv.rd_bits); // 5 bits
    limb_from_bits_le(mem_offset.into_iter())
}

pub const BASESUM_GATE_START_LIMBS: usize = 1;
/// Use base-sum algorithm on base B and limb size LS
fn u32_to_bits<P: PackedField, const LS: usize, const B: usize>(sum: P) -> Vec<P> {
    assert!(LS <= 32);
    let limb_indices: Vec<usize> = (0..LS).into_iter().map(|i| BASESUM_GATE_START_LIMBS + i).collect();

    let mut limbs = vec![P::ZEROS; LS];

    let base = P::Scalar::from_canonical_usize(B);
    let mut tmp = sum;
    for i in 0..LS {
        let next =  tmp / base;
        limbs[i] = tmp - next;
        tmp = next;
    }
    println!("{:?}", limbs);

    /*
    // Constrain by connect
    let computed_sum = reduce_with_powers(&limbs, P::Scalar::from_canonical_usize(B));
    let mut constraints = vec![computed_sum - sum];

    // Do range check for the remainder
    for limb in &limbs {
        constraints.push(
            (0..B)
            .map(|i| *limb - P::Scalar::from_canonical_usize(i))
            .product(),
        );
    }
    */

    limbs
}

/// Convert u32 to bits array with base B.
pub fn u32_to_bits_target<
    F: RichField + Extendable<D>,
    const D: usize,
    const LS: usize,
    const B: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    a: &Target, // u32
) -> Vec<BoolTarget> {
    assert!(LS <= 32);
    let mut res = Vec::new();
    let bit_targets = builder.split_le_base::<B>(*a, LS);
    for j in (0..LS).rev() {
        res.push(BoolTarget::new_unsafe(bit_targets[j]));
    }
    res
}

/// Consttant -4
const GOLDILOCKS_INVERSE_NEG4: u64 = 18446744069414584317;

fn get_addr<T: Copy>(lv: &CpuColumnsView<T>) -> (T, T, T) {
    let addr_context = lv.mem_channels[0].value;
    let addr_segment = lv.mem_channels[1].value;
    let addr_virtual = lv.mem_channels[2].value;
    (addr_context, addr_segment, addr_virtual)
}

fn eval_packed_load<P: PackedField>(
    lv: &CpuColumnsView<P>,
    _nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    // If the operation is MLOAD_GENERAL, lv.opcode_bits[5] = 1
    let filter = lv.op.m_op_general * lv.opcode_bits[5];

    // check mem channel segment is register
    let diff = lv.mem_channels[0].addr_segment
        - P::Scalar::from_canonical_u64(Segment::RegisterFile as u64);
    yield_constr.constraint(filter * diff);
    let diff = lv.mem_channels[1].addr_segment
        - P::Scalar::from_canonical_u64(Segment::RegisterFile as u64);
    yield_constr.constraint(filter * diff);

    // check memory is used
    // check is_read is 0/1

    let rs = lv.mem_channels[0].value;
    let rt = lv.mem_channels[1].value;
    let mem = lv.mem_channels[2].value;

    // calculate rs:
    //    let virt_raw = (rs as u32).wrapping_add(sign_extend::<16>(offset));
    //    let virt = virt_raw & 0xFFFF_FFFC;
    let offset = get_offset(lv);
    let virt_raw = rs + offset;
    let expected_virt = lv.mem_channels[5].value;
    let expected_virt_div_4 = lv.mem_channels[6].value;

    let one = P::Scalar::ONES;
    let two = P::Scalar::from_canonical_u64(2);
    let three = P::Scalar::from_canonical_u64(3);
    let four = P::Scalar::from_canonical_u64(4);

    // check expected_virt = 4 * expected_virt_div_4
    yield_constr.constraint(filter * (expected_virt - expected_virt_div_4 * four));

    // check (virt_raw - expected_virt) in [0, 1, 2, 3]
    let virt_diff = virt_raw - expected_virt;
    let virt_constr = virt_diff * (virt_diff - one) * (virt_diff - two) * (virt_diff - three);
    yield_constr.constraint(filter * virt_constr);

    //

    // Disable remaining memory channels, if any.
    // Note: SC needs 5 channel
    /*
    for &channel in &lv.mem_channels[5..NUM_GP_CHANNELS] {
    yield_constr.constraint(filter * channel.used);
    }
    */
}

fn eval_ext_circuit_load<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    _nv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let mut filter = lv.op.m_op_general;
    filter = builder.mul_extension(filter, lv.opcode_bits[5]);

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

    // Disable remaining memory channels, if any.
    /*
       for &channel in &lv.mem_channels[5..NUM_GP_CHANNELS] {
       let constr = builder.mul_extension(filter, channel.used);
       yield_constr.constraint(builder, constr);
    }
    */
}

fn eval_packed_store<P: PackedField>(
    lv: &CpuColumnsView<P>,
    _nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let filter = lv.op.m_op_general * (lv.opcode_bits[0] - P::ONES);

    let (addr_context, addr_segment, addr_virtual) = get_addr(lv);

    let value_channel = lv.mem_channels[3];
    let store_channel = lv.mem_channels[4];
    yield_constr.constraint(filter * (store_channel.used - P::ONES));
    yield_constr.constraint(filter * store_channel.is_read);
    yield_constr.constraint(filter * (store_channel.addr_context - addr_context));
    yield_constr.constraint(filter * (store_channel.addr_segment - addr_segment));
    yield_constr.constraint(filter * (store_channel.addr_virtual - addr_virtual));
    yield_constr.constraint(filter * (value_channel.value - store_channel.value));

    // Disable remaining memory channels, if any.
    for &channel in &lv.mem_channels[5..] {
        yield_constr.constraint(filter * channel.used);
    }

    // Stack constraints.
    // Pops.
    /*
       for i in 1..4 {
       let channel = lv.mem_channels[i];

       yield_constr.constraint(filter * (channel.used - P::ONES));
       yield_constr.constraint(filter * (channel.is_read - P::ONES));

       yield_constr.constraint(filter * (channel.addr_context - lv.context));
       yield_constr.constraint(
       filter * (channel.addr_segment - P::Scalar::from_canonical_u64(Segment::Stack as u64)),
       );
    // Remember that the first read (`i == 1`) is for the second stack element at `stack[stack_len - 1]`.
    let addr_virtual = lv.stack_len - P::Scalar::from_canonical_usize(i + 1);
    yield_constr.constraint(filter * (channel.addr_virtual - addr_virtual));
    }
    // Constrain `stack_inv_aux`.
    let len_diff = lv.stack_len - P::Scalar::from_canonical_usize(4);
    yield_constr.constraint(
    lv.op.m_op_general
     * (len_diff * lv.general.stack().stack_inv - lv.general.stack().stack_inv_aux),
     );
    // If stack_len != 4 and MSTORE, read new top of the stack in nv.mem_channels[0].
    let top_read_channel = nv.mem_channels[0];
    let is_top_read = lv.general.stack().stack_inv_aux * (P::ONES - lv.opcode_bits[0]);
    // Constrain `stack_inv_aux_2`. It contains `stack_inv_aux * opcode_bits[0]`.
    yield_constr
    .constraint(lv.op.m_op_general * (lv.general.stack().stack_inv_aux_2 - is_top_read));
    let new_filter = lv.op.m_op_general * lv.general.stack().stack_inv_aux_2;
    yield_constr.constraint_transition(new_filter * (top_read_channel.used - P::ONES));
    yield_constr.constraint_transition(new_filter * (top_read_channel.is_read - P::ONES));
    yield_constr.constraint_transition(new_filter * (top_read_channel.addr_context - nv.context));
    yield_constr.constraint_transition(
    new_filter
     * (top_read_channel.addr_segment
     - P::Scalar::from_canonical_u64(Segment::Stack as u64)),
     );
     let addr_virtual = nv.stack_len - P::ONES;
     yield_constr.constraint_transition(new_filter * (top_read_channel.addr_virtual - addr_virtual));
    // If stack_len == 4 or MLOAD, disable the channel.
    yield_constr.constraint(
    lv.op.m_op_general * (lv.general.stack().stack_inv_aux - P::ONES) * top_read_channel.used,
    );
    yield_constr.constraint(lv.op.m_op_general * lv.opcode_bits[0] * top_read_channel.used);
    */
}

fn eval_ext_circuit_store<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    _nv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let filter =
        builder.mul_sub_extension(lv.op.m_op_general, lv.opcode_bits[0], lv.op.m_op_general);

    let (addr_context, addr_segment, addr_virtual) = get_addr(lv);

    let value_channel = lv.mem_channels[3];
    let store_channel = lv.mem_channels[4];
    {
        let constr = builder.mul_sub_extension(filter, store_channel.used, filter);
        yield_constr.constraint(builder, constr);
    }
    {
        let constr = builder.mul_extension(filter, store_channel.is_read);
        yield_constr.constraint(builder, constr);
    }
    for (channel_field, target) in izip!(
        [
            store_channel.addr_context,
            store_channel.addr_segment,
            store_channel.addr_virtual,
        ],
        [addr_context, addr_segment, addr_virtual]
    ) {
        let diff = builder.sub_extension(channel_field, target);
        let constr = builder.mul_extension(filter, diff);
        yield_constr.constraint(builder, constr);
    }
    let diff = builder.sub_extension(value_channel.value, store_channel.value);
    let constr = builder.mul_extension(filter, diff);
    yield_constr.constraint(builder, constr);

    // Disable remaining memory channels, if any.
    for &channel in &lv.mem_channels[5..] {
        let constr = builder.mul_extension(filter, channel.used);
        yield_constr.constraint(builder, constr);
    }

    // Stack constraints
    // Pops.
    /*
           for i in 1..4 {
           let channel = lv.mem_channels[i];

           {
           let constr = builder.mul_sub_extension(filter, channel.used, filter);
           yield_constr.constraint(builder, constr);
           }
           {
           let constr = builder.mul_sub_extension(filter, channel.is_read, filter);
           yield_constr.constraint(builder, constr);
           }
           {
           let diff = builder.sub_extension(channel.addr_context, lv.context);
           let constr = builder.mul_extension(filter, diff);
           yield_constr.constraint(builder, constr);
           }
           {
           let diff = builder.add_const_extension(
           channel.addr_segment,
           -F::from_canonical_u64(Segment::Stack as u64),
           );
           let constr = builder.mul_extension(filter, diff);
           yield_constr.constraint(builder, constr);
           }
        // Remember that the first read (`i == 1`) is for the second stack element at `stack[stack_len - 1]`.
        let addr_virtual =
        builder.add_const_extension(lv.stack_len, -F::from_canonical_usize(i + 1));
        let diff = builder.sub_extension(channel.addr_virtual, addr_virtual);
        let constr = builder.mul_extension(filter, diff);
        yield_constr.constraint(builder, constr);
        }
        // Constrain `stack_inv_aux`.
        {
        let len_diff = builder.add_const_extension(lv.stack_len, -F::from_canonical_usize(4));
        let diff = builder.mul_sub_extension(
        len_diff,
        lv.general.stack().stack_inv,
        lv.general.stack().stack_inv_aux,
        );
        let constr = builder.mul_extension(lv.op.m_op_general, diff);
        yield_constr.constraint(builder, constr);
        }
        // If stack_len != 4 and MSTORE, read new top of the stack in nv.mem_channels[0].
        let top_read_channel = nv.mem_channels[0];
        let is_top_read = builder.mul_extension(lv.general.stack().stack_inv_aux, lv.opcode_bits[0]);
        let is_top_read = builder.sub_extension(lv.general.stack().stack_inv_aux, is_top_read);
        // Constrain `stack_inv_aux_2`. It contains `stack_inv_aux * opcode_bits[0]`.
        {
        let diff = builder.sub_extension(lv.general.stack().stack_inv_aux_2, is_top_read);
        let constr = builder.mul_extension(lv.op.m_op_general, diff);
        yield_constr.constraint(builder, constr);
        }
        let new_filter = builder.mul_extension(lv.op.m_op_general, lv.general.stack().stack_inv_aux_2);
        {
        let constr = builder.mul_sub_extension(new_filter, top_read_channel.used, new_filter);
        yield_constr.constraint_transition(builder, constr);
        }
        {
        let constr = builder.mul_sub_extension(new_filter, top_read_channel.is_read, new_filter);
        yield_constr.constraint_transition(builder, constr);
        }
        {
        let diff = builder.sub_extension(top_read_channel.addr_context, nv.context);
        let constr = builder.mul_extension(new_filter, diff);
        yield_constr.constraint_transition(builder, constr);
        }
        {
        let diff = builder.add_const_extension(
        top_read_channel.addr_segment,
        -F::from_canonical_u64(Segment::Stack as u64),
        );
        let constr = builder.mul_extension(new_filter, diff);
        yield_constr.constraint_transition(builder, constr);
    }
    {
        let addr_virtual = builder.add_const_extension(nv.stack_len, -F::ONE);
        let diff = builder.sub_extension(top_read_channel.addr_virtual, addr_virtual);
        let constr = builder.mul_extension(new_filter, diff);
        yield_constr.constraint_transition(builder, constr);
    }
    // If stack_len == 4 or MLOAD, disable the channel.
    {
        let diff = builder.mul_sub_extension(
            lv.op.m_op_general,
            lv.general.stack().stack_inv_aux,
            lv.op.m_op_general,
        );
        let constr = builder.mul_extension(diff, top_read_channel.used);
        yield_constr.constraint(builder, constr);
    }
    {
        let mul = builder.mul_extension(lv.op.m_op_general, lv.opcode_bits[0]);
        let constr = builder.mul_extension(mul, top_read_channel.used);
        yield_constr.constraint(builder, constr);
    }
    */
}

pub fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    nv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    eval_packed_load(lv, nv, yield_constr);
    //eval_packed_store(lv, nv, yield_constr);
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    nv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    eval_ext_circuit_load(builder, lv, nv, yield_constr);
    //eval_ext_circuit_store(builder, lv, nv, yield_constr);
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::extension::Extendable;
    use plonky2::field::packed::PackedField;
    use plonky2::field::types::Field;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    #[test]
    fn test_u32_to_bits() {
        env_logger::try_init().unwrap_or_default();
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let num = 1234;
        let bits = u32_to_bits::<_,32, 2>(F::from_canonical_u64(1234));
        let num_out = limb_from_bits_le(bits.into_iter());
        println!("{:?}, {:?}", num, num_out);
    }
}
