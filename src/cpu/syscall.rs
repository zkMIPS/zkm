use std::cmp::Ordering::Equal;
use env_logger::builder;
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


    let is_SYSMMAP = sys_num.is_equal_private(P::Scalar::from_canonical_usize(SYSMMAP),Equal);
    let mut sz = a1;
    let remain = sz / P::Scalar::from_canonical_u64(1 << 12);
    let remain = remain * P::Scalar::from_canonical_u64(1 << 12);
    let sz_mid =  sz- remain; //sz & 0xfff
    let is_sz_mid_zero = P::ZEROS.is_equal_private(sz_mid,Equal);
    let is_sz_mid_not_zero = P::ONES-is_sz_mid_zero;//sz & 0xFFF != 0
    let sz_in_sz_mid_not_zero = sz + P::Scalar::from_canonical_u64(256u64)-sz_mid;
    let is_a0_zero = P::ZEROS.is_equal_private(a0,Equal);
    let heap_in_a0_zero = lv.mem_channels[6].value[0];
    let v0_in_a0_zero = heap_in_a0_zero;
    let heap_in_a0_zero_and_in_sz_mid_not_zero = heap_in_a0_zero+sz_in_sz_mid_not_zero; // branch1:sz&fff!=0 & a0==0
    let result_heap = lv.mem_channels[7].value[0];
    let result_v0 = lv.mem_channels[4].value[0];
    let result_v1 = lv.mem_channels[5].value[0];


    let heap_in_a0_zero_and_not_in_sz_mid_not_zero = heap_in_a0_zero+sz; // branch2: sz&fff==0 &a0 ==0
    yield_constr.constraint(
        filter*is_SYSMMAP*is_sz_mid_not_zero*is_a0_zero
            * (heap_in_a0_zero_and_in_sz_mid_not_zero - result_heap),
    );
    yield_constr.constraint(
        filter*is_SYSMMAP*is_sz_mid_zero*is_a0_zero
            * (heap_in_a0_zero_and_not_in_sz_mid_not_zero - result_heap),
    );
    yield_constr.constraint(
        filter*is_SYSMMAP*is_a0_zero
            * (v0_in_a0_zero - result_v0),
    );
    yield_constr.constraint(
        filter*is_SYSMMAP*
            * (v1 - result_v1),
    );


    let is_SYSBRK = sys_num.is_equal_private(P::Scalar::from_canonical_usize(SYSBRK),Equal);
    let v0_in_SYSBRK = P::Scalar::from_canonical_u64(0x40000000u64);
    yield_constr.constraint(
        filter*is_SYSBRK*
            * (v0_in_SYSBRK - result_v0),
    );
    yield_constr.constraint(
        filter*is_SYSBRK*
            * (v1 - result_v1),
    );



    let is_SYSCLONE = sys_num.is_equal_private(P::Scalar::from_canonical_usize(SYSCLONE),Equal);
    let v0_in_SYSCLONE = P::ONES;

    yield_constr.constraint(
        filter*is_SYSCLONE*
            * (v0_in_SYSCLONE - result_v0),
    );
    yield_constr.constraint(
        filter*is_SYSCLONE*
            * (v1 - result_v1),
    );

    // let is_SYSEXITGROUP =sys_num.is_equal_private(P::Scalar::from_canonical_usize(SYSEXITGROUP),Equal);
    // //todo

    let is_SYSREAD = sys_num.is_equal_private(P::Scalar::from_canonical_usize(SYSREAD),Equal);
    let a0_is_FD_STDIN = a0.is_equal_private(P::Scalar::from_canonical_usize(FD_STDIN),Equal);
    let a0_is_not_FD_STDIN = P::ONES-a0_is_FD_STDIN;
    let v0_in_a0_is_not_FD_STDIN = P::Scalar::from_canonical_usize(0xFFFFFFFF);
    let v1_in_a0_is_not_FD_STDIN = P::Scalar::from_canonical_usize(MIPSEBADF);
    yield_constr.constraint(
        filter*is_SYSREAD*a0_is_not_FD_STDIN
            * (v0_in_a0_is_not_FD_STDIN - result_v0),
    );
    yield_constr.constraint(
        filter*is_SYSREAD*a0_is_not_FD_STDIN
            * (v1_in_a0_is_not_FD_STDIN - result_v1),
    );
    yield_constr.constraint(
        filter*is_SYSREAD*a0_is_FD_STDIN
            * (v0 - result_v0),
    );
    yield_constr.constraint(
        filter*is_SYSREAD*a0_is_FD_STDIN
            * (v1 - result_v1),
    );


    let is_SYSWRITE = sys_num.is_equal_private(P::Scalar::from_canonical_usize(SYSWRITE),Equal);
    let a0_is_FD_STDOUT=a0.is_equal_private(P::Scalar::from_canonical_usize(FD_STDOUT),Equal);
    let a0_is_FD_STDERR=a0.is_equal_private(P::Scalar::from_canonical_usize(FD_STDERR),Equal);

    let a0_is_not_FD_STDOUT=P::ONES-a0_is_FD_STDOUT;
    let a0_is_not_FD_STDERR=P::ONES-a0_is_FD_STDERR;
    let v0_in_a0_is_not_FD_STDOUT_and_FD_STDERR = P::Scalar::from_canonical_usize(0xFFFFFFFF);
    let v1_in_a0_is_not_FD_STDIN_and_FD_STDERR = P::Scalar::from_canonical_usize(MIPSEBADF);
    yield_constr.constraint(
        filter*is_SYSWRITE*a0_is_not_FD_STDOUT*a0_is_not_FD_STDERR
            * (v0_in_a0_is_not_FD_STDOUT_and_FD_STDERR - result_v0),
    );
    yield_constr.constraint(
        filter*is_SYSWRITE*a0_is_not_FD_STDOUT*a0_is_not_FD_STDERR
            * (v1_in_a0_is_not_FD_STDIN_and_FD_STDERR - result_v1),
    );
    yield_constr.constraint(
        filter*is_SYSWRITE*(a0_is_FD_STDIN+a0_is_FD_STDERR)
            * (v0 - result_v0),
    );
    yield_constr.constraint(
        filter*is_SYSWRITE*(a0_is_FD_STDIN+a0_is_FD_STDERR)
            * (v1 - result_v1),
    );

    let is_SYSFCNTL = sys_num.is_equal_private(P::Scalar::from_canonical_usize(SYSFCNTL),Equal);
    let a0_is_FD_STDIN =a0.is_equal_private(P::Scalar::from_canonical_usize(FD_STDIN),Equal);
    let a0_is_not_FD_STDIN =P::ONES-a0_is_FD_STDIN;

    let v0_in_a0_is_FD_STDIN  = P::ZEROS;
    let a0_is_FD_STDOUT = a0.is_equal_private(P::Scalar::from_canonical_usize(FD_STDOUT),Equal);
    let a0_is_not_FD_STDOUT = P::ONES-a0_is_not_FD_STDOUT;
    let a0_is_FD_STDERR = a0.is_equal_private(P::Scalar::from_canonical_usize(FD_STDERR),Equal);
    let a0_is_not_FD_STDERR = P::ONES-a0_is_FD_STDERR;
    let v0_in_a0_is_FD_STDOUT_or_FD_STDERR = P::ONES;

    let v0_in_a0_is_not_FD_STDOUT_and_FD_STDERR_and_FD_STDIN = P::Scalar::from_canonical_usize(0xFFFFFFFF);
    let v1_in_a0_is_not_FD_STDIN_and_FD_STDERR_and_FD_STDIN = P::Scalar::from_canonical_usize(MIPSEBADF);
    yield_constr.constraint(
        filter*is_SYSFCNTL*a0_is_FD_STDIN
            * (v0_in_a0_is_FD_STDIN - result_v0),
    );
    yield_constr.constraint(
        filter*is_SYSFCNTL*a0_is_FD_STDIN
            * (v1 - result_v1),
    );
    yield_constr.constraint(
        filter*is_SYSFCNTL*a0_is_FD_STDOUT*a0_is_FD_STDERR
            * (v0_in_a0_is_FD_STDOUT_or_FD_STDERR - result_v0),
    );
    yield_constr.constraint(
        filter*is_SYSFCNTL*a0_is_FD_STDOUT*a0_is_FD_STDERR
            * (v1 - result_v1),
    );
    yield_constr.constraint(
        filter*is_SYSFCNTL*(a0_is_not_FD_STDIN+a0_is_not_FD_STDOUT+a0_is_not_FD_STDERR)
            * (v0_in_a0_is_not_FD_STDOUT_and_FD_STDERR_and_FD_STDIN - result_v0),
    );
    yield_constr.constraint(
        filter*is_SYSFCNTL*(a0_is_not_FD_STDIN+a0_is_not_FD_STDOUT+a0_is_not_FD_STDERR)
            * (v1_in_a0_is_not_FD_STDIN_and_FD_STDERR_and_FD_STDIN - result_v1),
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

    let is_SYSMMAP = sys_num.is_equal_private(F::from_canonical_usize(SYSMMAP),Equal);
    let mut sz = a1;
    let remain = builder.div_extension(sz,F::from_canonical_u64(1 << 12)) ;
    let remain = builder.mul_extension(remain,F::from_canonical_u64(1 << 12)) ;
    let sz_mid = builder.sub_extension(sz, remain) ; //sz & 0xfff
    let is_sz_mid_zero = builder.zero_extension().is_equal_private(sz_mid,Equal);
    let is_sz_mid_not_zero = builder.sub_extension(builder.one_extension(),is_sz_mid_zero); //sz & 0xFFF != 0
    let temp = builder.sub_extension(F::from_canonical_u64(256u64),sz_mid);
    let sz_in_sz_mid_not_zero = builder.add_extension(sz,temp);
    let is_a0_zero =builder.zero_extension().is_equal_private(a0,Equal);
    let heap_in_a0_zero = lv.mem_channels[6].value[0];
    let v0_in_a0_zero = heap_in_a0_zero;
    let heap_in_a0_zero_and_in_sz_mid_not_zero = builder.add_extension(heap_in_a0_zero,sz_in_sz_mid_not_zero); // branch1:sz&fff!=0 & a0==0
    let heap_in_a0_zero_and_not_in_sz_mid_not_zero = builder.add_extension(heap_in_a0_zero,sz); // branch2: sz&fff==0 &a0 ==0
    let result_heap = lv.mem_channels[7].value[0];
    let result_v0 = lv.mem_channels[4].value[0];
    let result_v1 = lv.mem_channels[5].value[0];

    let constr_1 = builder.mul_extension(filter,is_SYSMMAP);
    let constr_2 = builder.mul_extension(constr_1,is_a0_zero);
    let constr_3 = builder.mul_extension(constr_2,is_sz_mid_not_zero);
    let constr_4 = builder.sub_extension(heap_in_a0_zero_and_in_sz_mid_not_zero,result_heap);
    let constr = builder.mul_extension(constr_3,constr_4);
    yield_constr.constraint(builder, constr);
    let constr_5 = builder.mul_extension(constr_2,is_sz_mid_zero);
    let constr_6 = builder.sub_extension(heap_in_a0_zero_and_not_in_sz_mid_not_zero,result_heap);
    let constr = builder.mul_extension(constr_5,constr_6);
    yield_constr.constraint(builder, constr);

    let constr_7 = builder.sub_extension(v0_in_a0_zero,result_v0);
    let constr = builder.mul_extension(constr_2,constr_7);
    yield_constr.constraint(builder, constr);

    let constr_8 = builder.sub_extension(v1,result_v1);
    let constr = builder.mul_extension(constr_1,constr_8);
    yield_constr.constraint(builder, constr);



    let is_SYSBRK = sys_num.is_equal_private(F::from_canonical_usize(SYSBRK),Equal);
    let v0_in_SYSBRK = F::from_canonical_u64(0x40000000u64);
    let constr_9 = builder.mul_extension(filter,is_SYSBRK);
    let constr_10 = builder.sub_extension(v0_in_SYSBRK,result_v0);
    let constr = builder.mul_extension(constr_9,constr_10);
    yield_constr.constraint(builder, constr);
    let constr_11 = builder.sub_extension(v1,result_v1);
    let constr = builder.mul_extension(constr_9,constr_11);
    yield_constr.constraint(builder, constr);


    let is_SYSCLONE = sys_num.is_equal_private(F::from_canonical_usize(SYSCLONE),Equal);
    let v0_in_SYSCLONE = builder.one_extension();
    let constr_12 = builder.mul_extension(filter,is_SYSCLONE);
    let constr_13 = builder.sub_extension(v0_in_SYSCLONE,result_v0);
    let constr = builder.mul_extension(constr_12,constr_13);
    yield_constr.constraint(builder, constr);
    let constr_14 = builder.sub_extension(v1,result_v1);
    let constr = builder.mul_extension(constr_12,constr_14);
    yield_constr.constraint(builder, constr);


    // let is_SYSEXITGROUP =sys_num.is_equal_private(P::Scalar::from_canonical_usize(SYSEXITGROUP),Equal);
    // //todo

    let is_SYSREAD = sys_num.is_equal_private(F::from_canonical_usize(SYSREAD),Equal);
    let a0_is_FD_STDIN = a0.is_equal_private(P::Scalar::from_canonical_usize(FD_STDIN),Equal);
    let a0_is_not_FD_STDIN = builder.sub_extension(builder.one_extension(),a0_is_FD_STDIN);
    let v0_in_a0_is_not_FD_STDIN = F::from_canonical_usize(0xFFFFFFFF);
    let v1_in_a0_is_not_FD_STDIN = F::from_canonical_usize(MIPSEBADF);
    let constr_15 = builder.mul_extension(filter,is_SYSREAD);
    let constr_16 = builder.mul_extension(constr_15,a0_is_not_FD_STDIN);
    let constr_17 = builder.sub_extension(v0_in_a0_is_not_FD_STDIN,result_v0);
    let constr = builder.mul_extension(constr_16,constr_17);
    yield_constr.constraint(builder, constr);
    let constr_18 = builder.sub_extension(v1_in_a0_is_not_FD_STDIN,result_v1);
    let constr = builder.mul_extension(constr_16,constr_18);
    yield_constr.constraint(builder, constr);
    let constr_19 = builder.mul_extension(constr_15,a0_is_FD_STDIN);
    let constr_20 = builder.sub_extension(v0,result_v0);
    let constr = builder.mul_extension(constr_19,constr_20);
    yield_constr.constraint(builder, constr);
    let constr_21 = builder.sub_extension(v1,result_v1);
    let constr = builder.mul_extension(constr_19,constr_21);
    yield_constr.constraint(builder, constr);

    let is_SYSWRITE = sys_num.is_equal_private(F::from_canonical_usize(SYSWRITE),Equal);
    let a0_is_FD_STDIN = a0.is_equal_private(F::from_canonical_usize(FD_STDOUT),Equal);
    let a0_is_FD_STDERR = a0.is_equal_private(F::from_canonical_usize(FD_STDERR),Equal);

    let a0_is_not_FD_STDOUT=builder.sub_extension(builder.one_extension(),a0_is_FD_STDIN);
    let a0_is_not_FD_STDERR=builder.sub_extension(builder.one_extension(),a0_is_FD_STDERR);
    let v0_in_a0_is_not_FD_STDOUT_and_FD_STDERR = F::from_canonical_usize(0xFFFFFFFF);
    let v1_in_a0_is_not_FD_STDIN_and_FD_STDERR = F::from_canonical_usize(MIPSEBADF);
    let constr_22 = builder.mul_extension(filter,is_SYSWRITE);
    let constr_23 = builder.mul_extension(constr_22,a0_is_not_FD_STDOUT);
    let constr_24 = builder.mul_extension(constr_23,a0_is_not_FD_STDERR);
    let constr_25 = builder.sub_extension(v0_in_a0_is_not_FD_STDOUT_and_FD_STDERR,result_v0);
    let constr = builder.mul_extension(constr_24,constr_25);
    yield_constr.constraint(builder, constr);
    let constr_26 = builder.sub_extension(v1_in_a0_is_not_FD_STDIN_and_FD_STDERR,result_v1);
    let constr = builder.mul_extension(constr_24,constr_26);
    yield_constr.constraint(builder, constr);
    let constr_27 = builder.add_extension(a0_is_FD_STDIN,a0_is_FD_STDERR);
    let constr_28 = builder.sub_extension(v0,result_v0);
    let constr = builder.mul_extension(constr_27,constr_28);
    yield_constr.constraint(builder, constr);
    let constr_29 = builder.sub_extension(v1,result_v1);
    let constr = builder.mul_extension(constr_28,constr_29);
    yield_constr.constraint(builder, constr);

    let is_SYSFCNTL = sys_num.is_equal_private(F::from_canonical_usize(SYSFCNTL),Equal);
    let a0_is_FD_STDIN =a0.is_equal_private(F::from_canonical_usize(FD_STDIN),Equal);
    let v0_in_a0_is_FD_STDIN  = builder.one_extension();
    let a0_is_FD_STDOUT = a0.is_equal_private(F::from_canonical_usize(FD_STDOUT),Equal);
    let a0_is_FD_STDERR = a0.is_equal_private(F::from_canonical_usize(FD_STDERR),Equal);
    let v0_in_a0_is_FD_STDOUT_or_FD_STDERR = builder.one_extension();
    let v0_in_a0_is_not_FD_STDOUT_and_FD_STDERR_and_FD_STDIN = F::from_canonical_usize(0xFFFFFFFF);
    let v1_in_a0_is_not_FD_STDIN_and_FD_STDERR_and_FD_STDIN = F::from_canonical_usize(MIPSEBADF);

    let constr_30 = builder.mul_extension(filter,is_SYSFCNTL);
    let constr_31 = builder.mul_extension(constr_30,a0_is_FD_STDIN);
    let constr_32 = builder.sub_extension(v0_in_a0_is_FD_STDIN,result_v0);
    let constr = builder.mul_extension(constr_31,constr_32);
    yield_constr.constraint(builder, constr);
    let constr_33 = builder.sub_extension(v1,result_v1);
    let constr = builder.mul_extension(constr_31,constr_33);
    yield_constr.constraint(builder, constr);
    let constr_34 = builder.mul_extension(a0_is_FD_STDOUT,a0_is_FD_STDERR);
    let constr_35 = builder.mul_extension(constr_34,constr_30);
    let constr_36 = builder.sub_extension(v0_in_a0_is_FD_STDOUT_or_FD_STDERR,result_v0);
    let constr = builder.mul_extension(constr_35,constr_36);
    yield_constr.constraint(builder, constr);
    let constr_37 = builder.sub_extension(v1,result_v1);
    let constr = builder.mul_extension(constr_35,constr_37);
    yield_constr.constraint(builder, constr);
    let constr_38 = builder.add_extension(a0_is_not_FD_STDIN,a0_is_not_FD_STDOUT);
    let constr_39 = builder.add_extension(constr_38,a0_is_not_FD_STDERR);
    let constr_40 = builder.sub_extension(v0_in_a0_is_not_FD_STDOUT_and_FD_STDERR_and_FD_STDIN,result_v0);
    let constr = builder.mul_extension(constr_39,constr_40);
    yield_constr.constraint(builder, constr);
    let constr_41 = builder.sub_extension(v1_in_a0_is_not_FD_STDIN_and_FD_STDERR_and_FD_STDIN,result_v1);
    let constr = builder.mul_extension(constr_39,constr_41);
    yield_constr.constraint(builder, constr);
}
