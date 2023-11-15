use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cpu::columns::CpuColumnsView;

use crate::witness::operation::*;

use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;

pub fn eval_packed<P: PackedField>(
    lv: &CpuColumnsView<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let filter = lv.op.syscall; // syscall
                                // let _sys_num = lv.mem_channels[0].value;
    let a0 = lv.mem_channels[1].value;
    let a1 = lv.mem_channels[2].value;
    let a2 = lv.mem_channels[3].value;
    let v0 = P::ZEROS;
    let v1 = P::ZEROS;

    //sysmap
    // is_sysmap|is_sz_mid_not_zero|is_a0_zero is calculated outside and written in the mem_channels.
    let is_sysmap = lv.mem_channels[2].value;
    let is_sz_mid_not_zero = lv.mem_channels[0].value; //sz & 0xFFF != 0
    let is_sz_mid_zero = P::ONES - is_sz_mid_not_zero;
    let sz = a1;
    let remain = sz / P::Scalar::from_canonical_u64(1 << 12);
    let remain = remain * P::Scalar::from_canonical_u64(1 << 12);
    let sz_mid = sz - remain; //sz & 0xfff
    let sz_in_sz_mid_not_zero = sz + P::Scalar::from_canonical_u64(256u64) - sz_mid;
    let is_a0_zero = lv.mem_channels[0].value;
    let heap_in_a0_zero = lv.mem_channels[6].value;
    let v0_in_a0_zero = heap_in_a0_zero;
    let heap_in_a0_zero_and_in_sz_mid_not_zero = heap_in_a0_zero + sz_in_sz_mid_not_zero; // branch1:sz&fff!=0 & a0==0
    let result_heap = lv.mem_channels[7].value;
    let result_v0 = lv.mem_channels[4].value;
    let result_v1 = lv.mem_channels[5].value;

    let heap_in_a0_zero_and_not_in_sz_mid_not_zero = heap_in_a0_zero + sz; // branch2: sz&fff==0 &a0 ==0
                                                                           //check:
                                                                           //1 is_syscall
                                                                           //2 sysnum==sysmap
                                                                           //3 a0 is zero
                                                                           //4 heap value is right
                                                                           //5 sz & 0xFFF != 0
    yield_constr.constraint(
        filter
            * is_sysmap
            * is_sz_mid_not_zero
            * is_a0_zero
            * (heap_in_a0_zero_and_in_sz_mid_not_zero - result_heap),
    );
    //check:
    //1 is_syscall
    //2 sysnum==sysmap
    //3 a0 is zero
    //4 heap value is right
    //5 sz & 0xFFF == 0
    yield_constr.constraint(
        filter
            * is_sysmap
            * is_sz_mid_zero
            * is_a0_zero
            * (heap_in_a0_zero_and_not_in_sz_mid_not_zero - result_heap),
    );
    //check:
    //1 is_syscall
    //2 sysnum==sysmap
    //3 a0 is zero
    //4 v0 value is right
    yield_constr.constraint(filter * is_sysmap * is_a0_zero * (v0_in_a0_zero - result_v0));
    //check:
    //1 is_syscall
    //2 sysnum==sysmap
    //3 a0 is not zero
    //4 v0 value is right
    yield_constr.constraint(filter * is_sysmap * (P::ONES - is_a0_zero) * (a0 - result_v0));

    //sysbrk
    let is_sysbrk = lv.mem_channels[0].value;
    let v0_in_sysbrk = P::Scalar::from_canonical_u64(0x40000000u64);
    //check:
    //1 is_syscall
    //2 sysnum==sysbrk
    //3 v0&v1 are right
    yield_constr.constraint(filter * is_sysbrk * (v0_in_sysbrk - result_v0));
    yield_constr.constraint(filter * (v1 - result_v1));

    //sysclone
    let is_sysclone = lv.mem_channels[0].value;
    let v0_in_sysclone = P::ONES;
    //check:
    //1 is_syscall
    //2 sysnum==sysclone
    //3 v0&v1 are right
    yield_constr.constraint(filter * is_sysclone * (v0_in_sysclone - result_v0));
    yield_constr.constraint(filter * is_sysclone * (v1 - result_v1));

    // let is_SYSEXITGROUP =sys_num.is_equal_private(P::Scalar::from_canonical_usize(SYSEXITGROUP),Equal);
    // //todo
    //sysread
    let is_sysread = lv.mem_channels[2].value;
    let a0_is_fd_stdin = lv.mem_channels[0].value;
    let a0_is_not_fd_stdin = lv.mem_channels[0].value;
    let v0_in_a0_is_not_fd_stdin = P::Scalar::from_canonical_usize(0xFFFFFFFF);
    let v1_in_a0_is_not_fd_stdin = P::Scalar::from_canonical_usize(MIPSEBADF);
    //check:
    //1 is_syscall
    //2 sysnum==sysread
    //3 v0&v1 are right
    //4 a0 != fd_stdin
    yield_constr.constraint(
        filter * is_sysread * a0_is_not_fd_stdin * (v0_in_a0_is_not_fd_stdin - result_v0),
    );
    yield_constr.constraint(
        filter * is_sysread * a0_is_not_fd_stdin * (v1_in_a0_is_not_fd_stdin - result_v1),
    );
    //check:
    //1 is_syscall
    //2 sysnum==sysread
    //3 v0&v1 are right
    //4 a0 == fd_stdin
    yield_constr.constraint(filter * is_sysread * a0_is_fd_stdin * (v0 - result_v0));
    yield_constr.constraint(filter * is_sysread * a0_is_fd_stdin * (v1 - result_v1));

    //syswrite
    let is_syswrite = lv.mem_channels[2].value;
    let a0_is_fd_stdout_or_fd_stderr = lv.mem_channels[0].value;
    let a0_is_not_fd_stderr_and_fd_stderr = lv.mem_channels[1].value;

    let v0_in_a0_is_not_fd_stdout_and_fd_stderr = P::Scalar::from_canonical_usize(0xFFFFFFFF);
    let v1_in_a0_is_not_fd_stdin_and_fd_stderr = P::Scalar::from_canonical_usize(MIPSEBADF);
    //check:
    //1 is_syscall
    //2 sysnum==syswrite
    //3 v0&v1 are right
    //4 a0 =! fd_stderr and a0 != fd_stderr
    yield_constr.constraint(
        filter
            * is_syswrite
            * a0_is_not_fd_stderr_and_fd_stderr
            * (v0_in_a0_is_not_fd_stdout_and_fd_stderr - result_v0),
    );
    yield_constr.constraint(
        filter
            * is_syswrite
            * a0_is_not_fd_stderr_and_fd_stderr
            * (v1_in_a0_is_not_fd_stdin_and_fd_stderr - result_v1),
    );
    //check:
    //1 is_syscall
    //2 sysnum==syswrite
    //3 v0&v1 are right
    //4 a0 ==fd_stderr or a0 == fd_stderr
    yield_constr.constraint(filter * is_syswrite * a0_is_fd_stdout_or_fd_stderr * (a2 - result_v0));
    yield_constr.constraint(filter * is_syswrite * a0_is_fd_stdout_or_fd_stderr * (v1 - result_v1));

    //sysfcntl
    let is_sysfcntl = lv.mem_channels[2].value;
    let a0_is_fd_stdin = lv.mem_channels[1].value;
    let v0_in_a0_is_fd_stdin = P::ZEROS;
    let a0_is_fd_stdout_or_fd_stderr = lv.mem_channels[1].value;
    let _v0_in_a0_is_fd_stdout_or_fd_stderr = P::ONES;
    let a0_is_else = lv.mem_channels[1].value;
    let v0_in_a0_is_not_fd_stdout_and_fd_stderr_and_fd_stdin =
        P::Scalar::from_canonical_usize(0xFFFFFFFF);
    let v1_in_a0_is_not_fd_stdin_and_fd_stderr_and_fd_stdin =
        P::Scalar::from_canonical_usize(MIPSEBADF);
    yield_constr
        .constraint(filter * is_sysfcntl * a0_is_fd_stdin * (v0_in_a0_is_fd_stdin - result_v0));

    yield_constr.constraint(filter * is_sysfcntl * a0_is_fd_stdin * (v1 - result_v1));

    yield_constr
        .constraint(filter * is_sysfcntl * a0_is_fd_stdout_or_fd_stderr * (P::ONES - result_v0));

    yield_constr.constraint(filter * is_sysfcntl * a0_is_fd_stdout_or_fd_stderr * (v1 - result_v1));

    yield_constr.constraint(
        filter
            * is_sysfcntl
            * a0_is_else
            * (v0_in_a0_is_not_fd_stdout_and_fd_stderr_and_fd_stdin - result_v0),
    );

    yield_constr.constraint(
        filter
            * is_sysfcntl
            * a0_is_else
            * (v1_in_a0_is_not_fd_stdin_and_fd_stderr_and_fd_stdin - result_v1),
    );
}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let filter = lv.op.syscall;
    // let _sys_num = lv.mem_channels[0].value;
    let a0 = lv.mem_channels[1].value;
    let a1 = lv.mem_channels[2].value;
    let a2 = lv.mem_channels[3].value;
    let v0 = builder.zero_extension();
    let v1 = builder.zero_extension();

    //sysmap
    let is_sysmap = lv.mem_channels[2].value;
    let is_sz_mid_not_zero = lv.mem_channels[0].value; //sz & 0xFFF != 0
    let one_extension = builder.one_extension();
    let is_sz_mid_zero = builder.sub_extension(one_extension, is_sz_mid_not_zero);
    let sz = a1;
    let divsor = builder.constant_extension(F::Extension::from_canonical_u64(1 << 12));
    let remain = builder.div_extension(sz, divsor);
    let remain = builder.mul_extension(remain, divsor);
    let sz_mid = builder.sub_extension(sz, remain); //sz & 0xfff
    let u256 = builder.constant_extension(F::Extension::from_canonical_u64(256u64));
    let temp = builder.sub_extension(u256, sz_mid);
    let sz_in_sz_mid_not_zero = builder.add_extension(sz, temp);
    let is_a0_zero = lv.mem_channels[0].value;
    let heap_in_a0_zero = lv.mem_channels[6].value;
    let v0_in_a0_zero = heap_in_a0_zero;
    let heap_in_a0_zero_and_in_sz_mid_not_zero =
        builder.add_extension(heap_in_a0_zero, sz_in_sz_mid_not_zero); // branch1:sz&fff!=0 & a0==0
    let heap_in_a0_zero_and_not_in_sz_mid_not_zero = builder.add_extension(heap_in_a0_zero, sz); // branch2: sz&fff==0 &a0 ==0
    let result_heap = lv.mem_channels[7].value;
    let result_v0 = lv.mem_channels[4].value;
    let result_v1 = lv.mem_channels[5].value;
    let filter_0 = builder.mul_extension(filter, is_sysmap);
    let constr_1 = builder.mul_extension(filter_0, is_a0_zero);
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
    let constr_9 = builder.mul_extension(constr_8, filter_0);

    let constr = builder.mul_extension(constr_7, constr_9);
    yield_constr.constraint(builder, constr);

    //sysbrk

    let is_sysbrk = lv.mem_channels[0].value;
    let v0_in_sysbrk = builder.constant_extension(F::Extension::from_canonical_u64(0x40000000u64));
    let constr_8 = builder.mul_extension(filter, is_sysbrk);
    let constr_9 = builder.sub_extension(v0_in_sysbrk, result_v0);
    let constr = builder.mul_extension(constr_8, constr_9);
    yield_constr.constraint(builder, constr);
    let constr_10 = builder.sub_extension(v1, result_v1);
    let constr = builder.mul_extension(filter, constr_10);
    yield_constr.constraint(builder, constr);

    //sysclone
    let is_sysclone = lv.mem_channels[0].value;
    let v0_in_sysclone = builder.one_extension();
    let constr_12 = builder.mul_extension(filter, is_sysclone);
    let constr_13 = builder.sub_extension(v0_in_sysclone, result_v0);
    let constr = builder.mul_extension(constr_12, constr_13);
    yield_constr.constraint(builder, constr);
    let constr_14 = builder.sub_extension(v1, result_v1);
    let constr = builder.mul_extension(constr_12, constr_14);
    yield_constr.constraint(builder, constr);

    // let is_SYSEXITGROUP =sys_num.is_equal_private(P::Scalar::from_canonical_usize(SYSEXITGROUP),Equal);
    // //todo
    //sysread
    let is_sysread = lv.mem_channels[2].value;
    let a0_is_fd_stdin = lv.mem_channels[0].value;
    let a0_is_not_fd_stdin = lv.mem_channels[0].value;
    let v0_in_a0_is_not_fd_stdin =
        builder.constant_extension(F::Extension::from_canonical_usize(0xFFFFFFFF));
    let v1_in_a0_is_not_fd_stdin =
        builder.constant_extension(F::Extension::from_canonical_usize(MIPSEBADF));
    let filter_0 = builder.mul_extension(filter, is_sysread);
    let constr_15 = builder.mul_extension(filter_0, a0_is_not_fd_stdin);
    let constr_16 = builder.sub_extension(v0_in_a0_is_not_fd_stdin, result_v0);
    let constr = builder.mul_extension(constr_15, constr_16);
    yield_constr.constraint(builder, constr);
    let constr_17 = builder.sub_extension(v1_in_a0_is_not_fd_stdin, result_v1);
    let constr = builder.mul_extension(constr_15, constr_17);
    yield_constr.constraint(builder, constr);
    let constr_19 = builder.mul_extension(filter_0, a0_is_fd_stdin);
    let constr_20 = builder.sub_extension(v0, result_v0);
    let constr = builder.mul_extension(constr_19, constr_20);
    yield_constr.constraint(builder, constr);
    let constr_21 = builder.sub_extension(v1, result_v1);
    let constr = builder.mul_extension(constr_19, constr_21);
    yield_constr.constraint(builder, constr);

    //syswrite

    let is_syswrite = lv.mem_channels[2].value;
    let a0_is_fd_stdout_or_fd_stderr = lv.mem_channels[0].value;
    let a0_is_not_fd_stderr_and_fd_stderr = lv.mem_channels[1].value;
    let v0_in_a0_is_not_fd_stdout_and_fd_stderr =
        builder.constant_extension(F::Extension::from_canonical_usize(0xFFFFFFFF));
    let v1_in_a0_is_not_fd_stdin_and_fd_stderr =
        builder.constant_extension(F::Extension::from_canonical_usize(MIPSEBADF));
    let filter_0 = builder.mul_extension(filter, is_syswrite);
    let constr_22 = builder.mul_extension(filter_0, a0_is_not_fd_stderr_and_fd_stderr);
    let constr_25 = builder.sub_extension(v0_in_a0_is_not_fd_stdout_and_fd_stderr, result_v0);
    let constr = builder.mul_extension(constr_22, constr_25);
    yield_constr.constraint(builder, constr);
    let constr_26 = builder.sub_extension(v1_in_a0_is_not_fd_stdin_and_fd_stderr, result_v1);
    let constr = builder.mul_extension(constr_22, constr_26);
    yield_constr.constraint(builder, constr);
    let constr_27 = builder.mul_extension(filter_0, a0_is_fd_stdout_or_fd_stderr);
    let constr_28 = builder.sub_extension(a2, result_v0);
    let constr = builder.mul_extension(constr_27, constr_28);
    yield_constr.constraint(builder, constr);
    let constr_29 = builder.sub_extension(v1, result_v1);
    let constr = builder.mul_extension(constr_27, constr_29);
    yield_constr.constraint(builder, constr);

    //sysfcntl

    let is_sysfcntl = lv.mem_channels[2].value;
    let a0_is_fd_stdin = lv.mem_channels[1].value;
    let v0_in_a0_is_fd_stdin = builder.zero_extension();
    let a0_is_fd_stdout_or_fd_stderr = lv.mem_channels[1].value;
    let v0_in_a0_is_fd_stdout_or_fd_stderr = builder.one_extension();
    let a0_is_else = lv.mem_channels[1].value;
    let v0_in_a0_is_not_fd_stdout_and_fd_stderr_and_fd_stdin =
        builder.constant_extension(F::Extension::from_canonical_usize(0xFFFFFFFF));
    let v1_in_a0_is_not_fd_stdin_and_fd_stderr_and_fd_stdin =
        builder.constant_extension(F::Extension::from_canonical_usize(MIPSEBADF));
    let filter_0 = builder.mul_extension(filter, is_sysfcntl);
    let constr_30 = builder.mul_extension(filter_0, a0_is_fd_stdin);
    let constr_32 = builder.sub_extension(v0_in_a0_is_fd_stdin, result_v0);
    let constr = builder.mul_extension(constr_30, constr_32);
    yield_constr.constraint(builder, constr);

    let constr_33 = builder.sub_extension(v1, result_v1);
    let constr = builder.mul_extension(constr_30, constr_33);
    yield_constr.constraint(builder, constr);

    let constr_34 = builder.mul_extension(filter_0, a0_is_fd_stdout_or_fd_stderr);
    let constr_36 = builder.sub_extension(v0_in_a0_is_fd_stdout_or_fd_stderr, result_v0);
    let constr = builder.mul_extension(constr_34, constr_36);
    yield_constr.constraint(builder, constr);

    let constr_37 = builder.sub_extension(v1, result_v1);
    let constr = builder.mul_extension(constr_34, constr_37);
    yield_constr.constraint(builder, constr);

    let constr_38 = builder.mul_extension(filter_0, a0_is_else);
    let constr_40 = builder.sub_extension(
        v0_in_a0_is_not_fd_stdout_and_fd_stderr_and_fd_stdin,
        result_v0,
    );
    let constr = builder.mul_extension(constr_38, constr_40);
    yield_constr.constraint(builder, constr);

    let constr_41 = builder.sub_extension(
        v1_in_a0_is_not_fd_stdin_and_fd_stderr_and_fd_stdin,
        result_v1,
    );
    let constr = builder.mul_extension(constr_38, constr_41);
    yield_constr.constraint(builder, constr);
}
