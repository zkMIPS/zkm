use itertools::cloned;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::columns::CpuColumnsView;
use crate::util::{limb_from_bits_le, limb_from_bits_le_recursive};
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use crate::witness::operation::*;

pub fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let filter = lv.op.syscall; // syscall
    let sys_num = lv.mem_channels[0].value[0];
    let a0 = lv.mem_channels[1].value[0];
    let a1 = lv.mem_channels[2].value[0];
    let a2 = lv.mem_channels[3].value[0];
    let v0 = P::ZEROS;
    let v1 = P::ZEROS;

    //SYSMMAP

    let is_sz_mid_not_zero = lv.mem_channels[0].value[1];//sz & 0xFFF != 0
    let is_sz_mid_zero = P::ONES - is_sz_mid_not_zero;
    let mut sz = a1;
    let remain = sz / P::Scalar::from_canonical_u64(1 << 12);
    let remain = remain * P::Scalar::from_canonical_u64(1 << 12);
    let sz_mid = sz - remain; //sz & 0xfff
    let sz_in_sz_mid_not_zero = sz + P::Scalar::from_canonical_u64(256u64) - sz_mid;
    let is_a0_zero = lv.mem_channels[0].value[2];
    let heap_in_a0_zero = lv.mem_channels[6].value[0];
    let v0_in_a0_zero = heap_in_a0_zero;
    let heap_in_a0_zero_and_in_sz_mid_not_zero = heap_in_a0_zero + sz_in_sz_mid_not_zero; // branch1:sz&fff!=0 & a0==0
    let result_heap = lv.mem_channels[7].value[0];
    let result_v0 = lv.mem_channels[4].value[0];
    let result_v1 = lv.mem_channels[5].value[0];


    let heap_in_a0_zero_and_not_in_sz_mid_not_zero = heap_in_a0_zero + sz; // branch2: sz&fff==0 &a0 ==0
    yield_constr.constraint(
        filter * is_sz_mid_not_zero * is_a0_zero
            * (heap_in_a0_zero_and_in_sz_mid_not_zero - result_heap)
    );
    yield_constr.constraint(
        filter * is_sz_mid_zero * is_a0_zero
            * (heap_in_a0_zero_and_not_in_sz_mid_not_zero - result_heap)
    );
    yield_constr.constraint(
        filter * is_a0_zero
            * (v0_in_a0_zero - result_v0)
    );
    yield_constr.constraint(
        filter * (P::ONES - is_a0_zero)
            * (a0 - result_v0)
    );

//SYSBRK
    let is_SYSBRK = lv.mem_channels[0].value[3];
    let v0_in_SYSBRK = P::Scalar::from_canonical_u64(0x40000000u64);
    yield_constr.constraint(
        filter * is_SYSBRK
            * (v0_in_SYSBRK - result_v0)
    );
    yield_constr.constraint(
        filter *
            (v1 - result_v1)
    );

    //SYSCLONE
    let is_SYSCLONE = lv.mem_channels[0].value[4];
    let v0_in_SYSCLONE = P::ONES;

    yield_constr.constraint(
        filter * is_SYSCLONE
            * (v0_in_SYSCLONE - result_v0)
    );
    yield_constr.constraint(
        filter * is_SYSCLONE
            * (v1 - result_v1)
    );

    // let is_SYSEXITGROUP =sys_num.is_equal_private(P::Scalar::from_canonical_usize(SYSEXITGROUP),Equal);
    // //todo
    //SYSREAD
    let a0_is_FD_STDIN = lv.mem_channels[0].value[5];
    let a0_is_not_FD_STDIN = lv.mem_channels[0].value[6];
    let v0_in_a0_is_not_FD_STDIN = P::Scalar::from_canonical_usize(0xFFFFFFFF);
    let v1_in_a0_is_not_FD_STDIN = P::Scalar::from_canonical_usize(MIPSEBADF);
    yield_constr.constraint(
        filter * a0_is_not_FD_STDIN
            * (v0_in_a0_is_not_FD_STDIN - result_v0)
    );
    yield_constr.constraint(
        filter * a0_is_not_FD_STDIN
            * (v1_in_a0_is_not_FD_STDIN - result_v1)
    );
    yield_constr.constraint(
        filter * a0_is_FD_STDIN
            * (v0 - result_v0)
    );
    yield_constr.constraint(
        filter * a0_is_FD_STDIN
            * (v1 - result_v1)
    );

    //SYSWRITE
    let a0_is_FD_STDOUT_or_FD_STDERR = lv.mem_channels[0].value[7];
    let a0_is_not_FD_STDERR_and_FD_STDERR = lv.mem_channels[1].value[1];

    let v0_in_a0_is_not_FD_STDOUT_and_FD_STDERR = P::Scalar::from_canonical_usize(0xFFFFFFFF);
    let v1_in_a0_is_not_FD_STDIN_and_FD_STDERR = P::Scalar::from_canonical_usize(MIPSEBADF);
    yield_constr.constraint(
        filter * a0_is_not_FD_STDERR_and_FD_STDERR
            * (v0_in_a0_is_not_FD_STDOUT_and_FD_STDERR - result_v0)
    );
    yield_constr.constraint(
        filter * a0_is_not_FD_STDERR_and_FD_STDERR
            * (v1_in_a0_is_not_FD_STDIN_and_FD_STDERR - result_v1)
    );
    yield_constr.constraint(
        filter * a0_is_FD_STDOUT_or_FD_STDERR
            * (a2 - result_v0)
    );
    yield_constr.constraint(
        filter * a0_is_FD_STDOUT_or_FD_STDERR
            * (v1 - result_v1)
    );


    //SYSFCNTL
    let a0_is_FD_STDIN = lv.mem_channels[1].value[2];
    let v0_in_a0_is_FD_STDIN = P::ZEROS;
    let a0_is_FD_STDOUT_or_FD_STDERR = lv.mem_channels[1].value[3];
    let v0_in_a0_is_FD_STDOUT_or_FD_STDERR = P::ONES;
    let a0_is_else = lv.mem_channels[1].value[4];
    let v0_in_a0_is_not_FD_STDOUT_and_FD_STDERR_and_FD_STDIN = P::Scalar::from_canonical_usize(0xFFFFFFFF);
    let v1_in_a0_is_not_FD_STDIN_and_FD_STDERR_and_FD_STDIN = P::Scalar::from_canonical_usize(MIPSEBADF);
    yield_constr.constraint(
        filter * a0_is_FD_STDIN
            * (v0_in_a0_is_FD_STDIN - result_v0)
    );

    yield_constr.constraint(
        filter * a0_is_FD_STDIN
            * (v1 - result_v1)
    );

    yield_constr.constraint(
        filter * a0_is_FD_STDOUT_or_FD_STDERR
            * (P::ONES - result_v0)
    );

    yield_constr.constraint(
        filter * a0_is_FD_STDOUT_or_FD_STDERR
            * (v1 - result_v1)
    );

    yield_constr.constraint(
        filter * a0_is_else
            * (v0_in_a0_is_not_FD_STDOUT_and_FD_STDERR_and_FD_STDIN - result_v0)
    );

    yield_constr.constraint(
        filter * a0_is_else
            * (v1_in_a0_is_not_FD_STDIN_and_FD_STDERR_and_FD_STDIN - result_v1)
    );
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let filter = lv.op.syscall;
    let sys_num = lv.mem_channels[0].value[0];
    let a0 = lv.mem_channels[1].value[0];
    let a1 = lv.mem_channels[2].value[0];
    let a2 = lv.mem_channels[3].value[0];
    let v0 = builder.zero_extension();
    let v1 = builder.zero_extension();

    //SYSMMAP
    let is_sz_mid_not_zero = lv.mem_channels[0].value[1];//sz & 0xFFF != 0
    let one_extension = builder.one_extension();
    let is_sz_mid_zero = builder.sub_extension(one_extension, is_sz_mid_not_zero);
    let mut sz = a1;
    let divsor = builder.constant_extension(F::Extension::from_canonical_u64(1 << 12));
    let remain = builder.div_extension(sz, divsor);
    let remain = builder.mul_extension(remain, divsor);
    let sz_mid = builder.sub_extension(sz, remain); //sz & 0xfff
    let u256 = builder.constant_extension(F::Extension::from_canonical_u64(256u64));
    let temp = builder.sub_extension(u256, sz_mid);
    let sz_in_sz_mid_not_zero = builder.add_extension(sz, temp);
    let is_a0_zero = lv.mem_channels[0].value[2];
    let heap_in_a0_zero = lv.mem_channels[6].value[0];
    let v0_in_a0_zero = heap_in_a0_zero;
    let heap_in_a0_zero_and_in_sz_mid_not_zero = builder.add_extension(heap_in_a0_zero, sz_in_sz_mid_not_zero); // branch1:sz&fff!=0 & a0==0
    let heap_in_a0_zero_and_not_in_sz_mid_not_zero = builder.add_extension(heap_in_a0_zero, sz); // branch2: sz&fff==0 &a0 ==0
    let result_heap = lv.mem_channels[7].value[0];
    let result_v0 = lv.mem_channels[4].value[0];
    let result_v1 = lv.mem_channels[5].value[0];

    let constr_1 = builder.mul_extension(filter, is_a0_zero);
    let constr_2 = builder.mul_extension(constr_1, is_sz_mid_not_zero);
    let constr_3 = builder.sub_extension(heap_in_a0_zero_and_in_sz_mid_not_zero, result_heap);
    let constr = builder.mul_extension(constr_2, constr_3);
    yield_constr.constraint(builder, constr);
    let constr_4 = builder.mul_extension(constr_1, is_sz_mid_zero);
    let constr_5 = builder.sub_extension(heap_in_a0_zero_and_not_in_sz_mid_not_zero, result_heap);
    let constr = builder.mul_extension(constr_4, constr_5);
    yield_constr.constraint(builder, constr);

    let constr_6 = builder.sub_extension(v0_in_a0_zero, result_v0);
    let constr = builder.mul_extension(constr_1, constr_6);
    yield_constr.constraint(builder, constr);
    let constr_7 = builder.sub_extension(a0, result_v0);
    let constr_8 = builder.sub_extension(one_extension, is_a0_zero);
    let constr_9 = builder.mul_extension(constr_8, filter);

    let constr = builder.mul_extension(constr_7, constr_9);
    yield_constr.constraint(builder, constr);

//SYSBRK

    let is_SYSBRK = lv.mem_channels[0].value[3];
    let v0_in_SYSBRK = builder.constant_extension(F::Extension::from_canonical_u64(0x40000000u64));
    let constr_8 = builder.mul_extension(filter, is_SYSBRK);
    let constr_9 = builder.sub_extension(v0_in_SYSBRK, result_v0);
    let constr = builder.mul_extension(constr_8, constr_9);
    yield_constr.constraint(builder, constr);
    let constr_10 = builder.sub_extension(v1, result_v1);
    let constr = builder.mul_extension(filter, constr_10);
    yield_constr.constraint(builder, constr);

    //SYSCLONE
    let is_SYSCLONE = lv.mem_channels[0].value[4];
    let v0_in_SYSCLONE = builder.one_extension();
    let constr_12 = builder.mul_extension(filter, is_SYSCLONE);
    let constr_13 = builder.sub_extension(v0_in_SYSCLONE, result_v0);
    let constr = builder.mul_extension(constr_12, constr_13);
    yield_constr.constraint(builder, constr);
    let constr_14 = builder.sub_extension(v1, result_v1);
    let constr = builder.mul_extension(constr_12, constr_14);
    yield_constr.constraint(builder, constr);


    // let is_SYSEXITGROUP =sys_num.is_equal_private(P::Scalar::from_canonical_usize(SYSEXITGROUP),Equal);
    // //todo
    //SYSREAD
    let a0_is_FD_STDIN = lv.mem_channels[0].value[5];
    let a0_is_not_FD_STDIN = lv.mem_channels[0].value[6];
    let v0_in_a0_is_not_FD_STDIN = builder.constant_extension(F::Extension::from_canonical_usize(0xFFFFFFFF));
    let v1_in_a0_is_not_FD_STDIN = builder.constant_extension(F::Extension::from_canonical_usize(MIPSEBADF));
    let constr_15 = builder.mul_extension(filter, a0_is_not_FD_STDIN);
    let constr_16 = builder.sub_extension(v0_in_a0_is_not_FD_STDIN, result_v0);
    let constr = builder.mul_extension(constr_15, constr_16);
    yield_constr.constraint(builder, constr);
    let constr_17 = builder.sub_extension(v1_in_a0_is_not_FD_STDIN, result_v1);
    let constr = builder.mul_extension(constr_15, constr_17);
    yield_constr.constraint(builder, constr);
    let constr_19 = builder.mul_extension(filter, a0_is_FD_STDIN);
    let constr_20 = builder.sub_extension(v0, result_v0);
    let constr = builder.mul_extension(constr_19, constr_20);
    yield_constr.constraint(builder, constr);
    let constr_21 = builder.sub_extension(v1, result_v1);
    let constr = builder.mul_extension(constr_19, constr_21);
    yield_constr.constraint(builder, constr);

    //SYSWRITE

    let a0_is_FD_STDOUT_or_FD_STDERR = lv.mem_channels[0].value[7];
    let a0_is_not_FD_STDERR_and_FD_STDERR = lv.mem_channels[1].value[1];
    let v0_in_a0_is_not_FD_STDOUT_and_FD_STDERR = builder.constant_extension(F::Extension::from_canonical_usize(0xFFFFFFFF));
    let v1_in_a0_is_not_FD_STDIN_and_FD_STDERR = builder.constant_extension(F::Extension::from_canonical_usize(MIPSEBADF));
    let constr_22 = builder.mul_extension(filter, a0_is_not_FD_STDERR_and_FD_STDERR);
    let constr_25 = builder.sub_extension(v0_in_a0_is_not_FD_STDOUT_and_FD_STDERR, result_v0);
    let constr = builder.mul_extension(constr_22, constr_25);
    yield_constr.constraint(builder, constr);
    let constr_26 = builder.sub_extension(v1_in_a0_is_not_FD_STDIN_and_FD_STDERR, result_v1);
    let constr = builder.mul_extension(constr_22, constr_26);
    yield_constr.constraint(builder, constr);
    let constr_27 = builder.mul_extension(filter, a0_is_FD_STDOUT_or_FD_STDERR);
    let constr_28 = builder.sub_extension(a2, result_v0);
    let constr = builder.mul_extension(constr_27, constr_28);
    yield_constr.constraint(builder, constr);
    let constr_29 = builder.sub_extension(v1, result_v1);
    let constr = builder.mul_extension(constr_27, constr_29);
    yield_constr.constraint(builder, constr);


    //SYSFCNTL

    let a0_is_FD_STDIN = lv.mem_channels[1].value[2];
    let v0_in_a0_is_FD_STDIN = builder.zero_extension();
    let a0_is_FD_STDOUT_or_FD_STDERR = lv.mem_channels[1].value[3];
    let v0_in_a0_is_FD_STDOUT_or_FD_STDERR = builder.one_extension();
    let a0_is_else = lv.mem_channels[1].value[4];
    let v0_in_a0_is_not_FD_STDOUT_and_FD_STDERR_and_FD_STDIN = builder.constant_extension(F::Extension::from_canonical_usize(0xFFFFFFFF));
    let v1_in_a0_is_not_FD_STDIN_and_FD_STDERR_and_FD_STDIN = builder.constant_extension(F::Extension::from_canonical_usize(MIPSEBADF));

    let constr_30 = builder.mul_extension(filter, a0_is_FD_STDIN);
    let constr_32 = builder.sub_extension(v0_in_a0_is_FD_STDIN, result_v0);
    let constr = builder.mul_extension(constr_30, constr_32);
    yield_constr.constraint(builder, constr);

    let constr_33 = builder.sub_extension(v1, result_v1);
    let constr = builder.mul_extension(constr_30, constr_33);
    yield_constr.constraint(builder, constr);

    let constr_34 = builder.mul_extension(filter, a0_is_FD_STDOUT_or_FD_STDERR);
    let constr_36 = builder.sub_extension(v0_in_a0_is_FD_STDOUT_or_FD_STDERR, result_v0);
    let constr = builder.mul_extension(constr_34, constr_36);
    yield_constr.constraint(builder, constr);

    let constr_37 = builder.sub_extension(v1, result_v1);
    let constr = builder.mul_extension(constr_34, constr_37);
    yield_constr.constraint(builder, constr);

    let constr_38 = builder.mul_extension(filter, a0_is_else);
    let constr_40 = builder.sub_extension(v0_in_a0_is_not_FD_STDOUT_and_FD_STDERR_and_FD_STDIN, result_v0);
    let constr = builder.mul_extension(constr_38, constr_40);
    yield_constr.constraint(builder, constr);

    let constr_41 = builder.sub_extension(v1_in_a0_is_not_FD_STDIN_and_FD_STDERR_and_FD_STDIN, result_v1);
    let constr = builder.mul_extension(constr_38, constr_41);
    yield_constr.constraint(builder, constr);
}
