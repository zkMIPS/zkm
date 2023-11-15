/**
static inline __attribute((always_inline))
unsigned clz(uint32_t x)
{
    // *INDENT-OFF*
    if (x == 0) return 32;
    int n = 1;
    if ((x >> 16) == 0) { n += 16; x <<= 16; }
    if ((x >> 24) == 0) { n += 8; x <<= 8; }
    if ((x >> 28) == 0) { n += 4; x <<= 4; }
    if ((x >> 30) == 0) { n += 2; x <<= 2; }
    n = n - (x >> 31);
    return n;
    // *INDENT-ON*
}
*/
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::columns::{CpuColumnsView};
use crate::memory;
use crate::util::{limb_from_bits_le, limb_from_bits_le_recursive};
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;

const GOLDILOCKS_INVERSE_2EXP16: u64 = 18446462594437939201;
const GOLDILOCKS_INVERSE_2EXP24: u64 = 18446742969902956801;
const GOLDILOCKS_INVERSE_2EXP28: u64 = 18446744000695107601;
const GOLDILOCKS_INVERSE_2EXP30: u64 = 18446744052234715141;
const GOLDILOCKS_INVERSE_2EXP31: u64 = 18446744060824649731;

pub fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let filter = lv.op.count_op; // `CLZ` or `CLO`

    let rs_val = lv.mem_channels[0].value;
    let rd_val = lv.mem_channels[1].value;
    let rs = limb_from_bits_le(vec![rs_val].into_iter());
    let rd = limb_from_bits_le(vec![rd_val].into_iter());

    // CLZ and CLO are differentiated by their first func_bits.
    let clz_filter = filter * (P::ONES - lv.func_bits[0]);
    let clo_filter = filter * lv.func_bits[0];

    // Check rs Reg
    // constraint: filter * (rs_reg - rs) == 0
    {
        let rs_reg = lv.mem_channels[0].addr_virtual;
        let rs_src = limb_from_bits_le(lv.rs_bits.into_iter());
        yield_constr.constraint(filter * (rs_reg - rs_src));
    }

    // Check rd Reg
    // constraint: filter * (rd_reg - rd) == 0
    {
        let rd_reg = lv.mem_channels[1].addr_virtual;
        let rd_dst = limb_from_bits_le(lv.rd_bits.into_iter());
        yield_constr.constraint(filter * (rd_reg - rd_dst));
    }

    // Check CLZ
    {
        eval_packed_clz(clz_filter, rs, rd, yield_constr);
    }

    // Check CLO
    {
        // check by clz using !rs
        let rs = P::ZEROS - rs - P::ONES;
        eval_packed_clz(clo_filter, rs, rd, yield_constr);
    }
}

/**
1.if rs is all zero, rd=32
2.if rs is not zero,check by segment.
 */
pub fn eval_packed_clz<P: PackedField>(
    filter: P,
    rs: P,
    rd: P,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let limb32 = P::Scalar::from_canonical_u64(32);
    let limb16 = P::Scalar::from_canonical_u64(16);
    let limb8 = P::Scalar::from_canonical_u64(8);
    let limb4 = P::Scalar::from_canonical_u64(4);
    let limb2 = P::Scalar::from_canonical_u64(2);
    yield_constr.constraint(filter * (P::ONES - rs) * (rd - limb32)); // (1 - rs) * (rd - 32), if rs=0 then rd=32

    // check low16 bit
    let n = P::ONES;
    let pow16 = P::Scalar::from_canonical_u64(1 << 16);
    let pow16_inv = P::Scalar::from_canonical_u64(GOLDILOCKS_INVERSE_2EXP16);
    let n = n + limb16;
    let rs = rs * pow16;
    let low16_filter = (P::ONES - rs * pow16_inv) * (n - limb16 - P::ONES);
    yield_constr.constraint(filter * low16_filter); // if x >> 16 = 0, then n += 16 && x <<= 16

    // check low24
    let pow24_inv = P::Scalar::from_canonical_u64(GOLDILOCKS_INVERSE_2EXP24);
    let pow8 = P::Scalar::from_canonical_u64(1 << 8);
    let n = n + limb8;
    let rs = rs * pow8;
    let low24_filter = (P::ONES - rs * pow24_inv) * (n - limb8 - P::ONES);
    yield_constr.constraint(filter * low16_filter * low24_filter); // if x >> 24 = 0, then n += 8 && x <<= 8

    // check low28
    let pow28_inv = P::Scalar::from_canonical_u64(GOLDILOCKS_INVERSE_2EXP28);
    let pow4 = P::Scalar::from_canonical_u64(1 << 4);
    let n = n + limb4;
    let rs = rs * pow4;
    let low28_filter = (P::ONES - rs * pow28_inv) * (n - limb4 - P::ONES);
    yield_constr.constraint(filter * low16_filter * low24_filter * low28_filter); // if x >> 28 = 0, then n += 4 && x <<= 4

    // check low30
    let pow30_inv = P::Scalar::from_canonical_u64(GOLDILOCKS_INVERSE_2EXP30);
    let pow2 = P::Scalar::from_canonical_u64(1 << 2);
    let n = n + limb2;
    let rs = rs * pow2;
    let low30_filter = (P::ONES - rs * pow30_inv) * (n - limb2 - P::ONES);
    yield_constr.constraint(filter * low16_filter * low24_filter * low28_filter * low30_filter); // if x >> 30 = 0, then n += 2 && x <<= 2

    // check all
    let pow31_inv = P::Scalar::from_canonical_u64(GOLDILOCKS_INVERSE_2EXP31);
    let n = n - (rs * pow31_inv);
    // check: n = n - (x >> 31) && n = rd
    yield_constr
        .constraint(filter * low16_filter * low24_filter * low28_filter * low30_filter * (n - rd));
}

pub fn eval_ext_circuit_clz<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    filter: ExtensionTarget<D>,
    rs: ExtensionTarget<D>,
    rd: ExtensionTarget<D>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let one = builder.one_extension();
    let zero = builder.zero_extension();
    let limb32 = builder.constant_extension(F::Extension::from_canonical_u64(32));
    let limb16 = builder.constant_extension(F::Extension::from_canonical_u64(16));
    let limb8 = builder.constant_extension(F::Extension::from_canonical_u64(8));
    let limb4 = builder.constant_extension(F::Extension::from_canonical_u64(4));
    let limb2 = builder.constant_extension(F::Extension::from_canonical_u64(2));
    let left_constr = builder.sub_extension(one, rs);
    let right_constr = builder.sub_extension(rd, limb32);
    let constr = builder.mul_extension(filter, left_constr);
    let constr = builder.mul_extension(constr, right_constr);
    yield_constr.constraint(builder, constr); // (1 - rs) * (rd - 32), if rs=0 then rd=32

    let n = one;
    let pow16 = builder.constant_extension(F::Extension::from_canonical_u64(1 << 16));
    let pow16_inv =
        builder.constant_extension(F::Extension::from_canonical_u64(GOLDILOCKS_INVERSE_2EXP16));
    let n = builder.add_extension(n, limb16);
    let rs = builder.mul_extension(rs, pow16);
    let low16_left_filter = builder.mul_extension(rs, pow16_inv);
    let low16_left_filter = builder.sub_extension(one, low16_left_filter);
    let low16_right_filter = builder.sub_extension(n, limb16);
    let low16_right_filter = builder.sub_extension(low16_right_filter, one);
    let low16_filter = builder.mul_extension(low16_left_filter, low16_right_filter);
    let constr = builder.mul_extension(filter, low16_filter);
    yield_constr.constraint(builder, constr);

    let pow24_inv =
        builder.constant_extension(F::Extension::from_canonical_u64(GOLDILOCKS_INVERSE_2EXP24));
    let pow8 = builder.constant_extension(F::Extension::from_canonical_u64(1 << 8));
    let n = builder.add_extension(n, limb8);
    let rs = builder.mul_extension(rs, pow8);
    let low24_left_filter = builder.mul_extension(rs, pow24_inv);
    let low24_left_filter = builder.sub_extension(one, low24_left_filter);
    let low24_right_filter = builder.sub_extension(n, limb8);
    let low24_right_filter = builder.sub_extension(low24_right_filter, one);
    let low24_filter = builder.mul_extension(low24_left_filter, low24_right_filter);
    let constr = builder.mul_extension(filter, low16_filter);
    let constr = builder.mul_extension(constr, low24_filter);
    yield_constr.constraint(builder, constr);

    let pow28_inv =
        builder.constant_extension(F::Extension::from_canonical_u64(GOLDILOCKS_INVERSE_2EXP28));
    let pow4 = builder.constant_extension(F::Extension::from_canonical_u64(1 << 4));
    let n = builder.add_extension(n, limb4);
    let rs = builder.mul_extension(rs, pow4);
    let low28_left_filter = builder.mul_extension(rs, pow28_inv);
    let low28_left_filter = builder.sub_extension(one, low28_left_filter);
    let low28_right_filter = builder.sub_extension(n, limb4);
    let low28_right_filter = builder.sub_extension(low28_right_filter, one);
    let low28_filter = builder.mul_extension(low28_left_filter, low28_right_filter);
    let constr = builder.mul_extension(filter, low16_filter);
    let constr = builder.mul_extension(constr, low24_filter);
    let constr = builder.mul_extension(constr, low28_filter);
    yield_constr.constraint(builder, constr);

    let pow30_inv =
        builder.constant_extension(F::Extension::from_canonical_u64(GOLDILOCKS_INVERSE_2EXP30));
    let pow2 = builder.constant_extension(F::Extension::from_canonical_u64(1 << 2));
    let n = builder.add_extension(n, limb2);
    let rs = builder.mul_extension(rs, pow2);
    let low30_left_filter = builder.mul_extension(rs, pow30_inv);
    let low30_left_filter = builder.sub_extension(one, low30_left_filter);
    let low30_right_filter = builder.sub_extension(n, limb2);
    let low30_right_filter = builder.sub_extension(low30_right_filter, one);
    let low30_filter = builder.mul_extension(low30_left_filter, low30_right_filter);
    let constr = builder.mul_extension(filter, low16_filter);
    let constr = builder.mul_extension(constr, low24_filter);
    let constr = builder.mul_extension(constr, low28_filter);
    let constr = builder.mul_extension(constr, low30_filter);
    yield_constr.constraint(builder, constr);

    let pow31_inv =
        builder.constant_extension(F::Extension::from_canonical_u64(GOLDILOCKS_INVERSE_2EXP31));
    let last_n = builder.mul_extension(rs, pow31_inv);
    let last_n = builder.sub_extension(n, last_n);
    let last_constr = builder.sub_extension(last_n, rd);
    let constr = builder.mul_extension(filter, low16_filter);
    let constr = builder.mul_extension(constr, low24_filter);
    let constr = builder.mul_extension(constr, low28_filter);
    let constr = builder.mul_extension(constr, low30_filter);
    let constr = builder.mul_extension(constr, last_constr);
    yield_constr.constraint(builder, constr);
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let one = builder.one_extension();
    // CLZ and CLO are differentiated by their first func_bits.
    let filter = lv.op.count_op; // `CLZ` or `CLO`
    let clz_filter = builder.sub_extension(one, lv.func_bits[0]);
    let clz_filter = builder.mul_extension(filter, clz_filter);
    let clo_filter = builder.mul_extension(filter, lv.func_bits[0]);

    let rs_val = lv.mem_channels[0].value;
    let rd_val = lv.mem_channels[1].value;
    let rs = limb_from_bits_le_recursive(builder, vec![rs_val].into_iter());
    let rd = limb_from_bits_le_recursive(builder, vec![rd_val].into_iter());

    // Check rs Reg
    {
        let rs_reg = lv.mem_channels[0].addr_virtual;
        let mut rs_reg_index = [one; 5];
        rs_reg_index.copy_from_slice(&lv.rs_bits);
        let rs_src = limb_from_bits_le_recursive(builder, rs_reg_index.into_iter());
        let constr = builder.sub_extension(rs_reg, rs_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check rd Reg
    // constraint: filter * (rd_reg - rd) == 0
    {
        let rd_reg = lv.mem_channels[1].addr_virtual;
        let mut rd_reg_index = [one; 5];
        rd_reg_index.copy_from_slice(&lv.rd_bits);
        let rd_src = limb_from_bits_le_recursive(builder, rd_reg_index.into_iter());
        let constr = builder.sub_extension(rd_reg, rd_src);
        let constr = builder.mul_extension(constr, filter);
        yield_constr.constraint(builder, constr);
    }

    // Check CLZ
    {
        eval_ext_circuit_clz(builder, clz_filter, rs, rd, yield_constr);
    }

    // Check CLO
    {
        let one = builder.one_extension();
        let zero = builder.zero_extension();
        // check by clz using !rs
        let rs = builder.sub_extension(zero, rs);
        let rs = builder.sub_extension(rs, one);
        eval_ext_circuit_clz(builder, clo_filter, rs, rd, yield_constr);
    }
}
