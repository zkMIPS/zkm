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
    let syscall = lv.general.syscall();
    let result_v0 = lv.mem_channels[4].value;
    let result_v1 = lv.mem_channels[5].value;

    //sysmap
    // is_sysmap|is_sz_mid_not_zero|is_a0_zero is calculated outside and written in the mem_channels.
    let is_sysmap = syscall.sysnum[1];
    let is_sz_mid_not_zero = syscall.a1; //sz & 0xFFF != 0
    let is_sz_mid_zero = syscall.sysnum[10]; //sz & 0xFFF == 0
    let sz = a1;
    let sz_in_sz_mid_not_zero = syscall.sysnum[9]; //the value of sz_mid
    let is_a0_zero = syscall.a0[0];
    let is_a0_not_zero = syscall.a0[2];
    let heap_in_a0_zero = lv.mem_channels[6].value;
    let result_heap = lv.mem_channels[7].value;
    let is_sysmap_a0_zero = syscall.cond[0];
    let is_sysmap_a0_zero_sz_nz = syscall.cond[1];
    let is_sysmap_a0_zero_sz_zero = syscall.cond[2];
    let is_sysmap_a0_nz = syscall.cond[3];
    let is_sysread_a0_not_stdin = syscall.cond[4];
    let is_sysread_a0_stdin = syscall.cond[5];
    let is_syswrite_a0_not_stdout_err = syscall.cond[6];
    let is_syswrite_a0_stdout_or_err = syscall.cond[7];
    let is_sysfcntl_a0_stdin = syscall.cond[8];
    let is_sysfcntl_a0_stdout_or_err = syscall.cond[9];

    let v0_in_a0_zero = heap_in_a0_zero;
    let heap_in_a0_zero_and_in_sz_mid_not_zero = heap_in_a0_zero + sz_in_sz_mid_not_zero; // branch1:sz&fff!=0 & a0==0

    let heap_in_a0_zero_and_not_in_sz_mid_not_zero = heap_in_a0_zero + sz; // branch2: sz&fff==0 &a0 ==0

    //check:
    //1 is_syscall
    //2 sysnum==sysmap
    //3 a0 is zero
    //4 heap value is right
    //5 sz & 0xFFF != 0
    yield_constr.constraint(filter * (is_sysmap_a0_zero - is_sysmap * is_a0_zero));

    yield_constr
        .constraint(filter * (is_sysmap_a0_zero_sz_nz - is_sysmap_a0_zero * is_sz_mid_not_zero));

    yield_constr.constraint(
        filter * is_sysmap_a0_zero_sz_nz * (heap_in_a0_zero_and_in_sz_mid_not_zero - result_heap),
    );

    //check:
    //1 is_syscall
    //2 sysnum==sysmap
    //3 a0 is zero
    //4 heap value is right
    //5 sz & 0xFFF == 0
    yield_constr
        .constraint(filter * (is_sysmap_a0_zero_sz_zero - is_sysmap_a0_zero * is_sz_mid_zero));
    yield_constr.constraint(
        filter
            * is_sysmap_a0_zero_sz_zero
            * (heap_in_a0_zero_and_not_in_sz_mid_not_zero - result_heap),
    );
    //check:
    //1 is_syscall
    //2 sysnum==sysmap
    //3 a0 is zero
    //4 v0 value is right
    yield_constr.constraint(filter * is_sysmap_a0_zero * (v0_in_a0_zero - result_v0));
    //check:
    //1 is_syscall
    //2 sysnum==sysmap
    //3 a0 is not zero
    //4 v0 value is right
    yield_constr.constraint(filter * (is_sysmap_a0_nz - is_sysmap * is_a0_not_zero));
    yield_constr.constraint(filter * is_sysmap_a0_nz * (a0 - result_v0));

    //sysbrk
    let is_sysbrk = syscall.sysnum[2];
    let is_sysbrk_gt = syscall.cond[10];
    let is_sysbrk_le = syscall.cond[11];
    let initial_brk = lv.mem_channels[6].value;
    //check:
    //1 is_syscall
    //2 sysnum==sysbrk
    //3 v0&v1 are right
    yield_constr.constraint(filter * is_sysbrk * (P::ONES - (is_sysbrk_gt + is_sysbrk_le)));
    yield_constr.constraint(filter * is_sysbrk_gt * (a0 - result_v0));
    yield_constr.constraint(filter * is_sysbrk_le * (initial_brk - result_v0));
    yield_constr.constraint(filter * is_sysbrk * (v1 - result_v1));

    //sysclone
    let is_sysclone = syscall.sysnum[3];
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
    let is_sysread = syscall.sysnum[5];
    let a0_is_fd_stdin = syscall.a0[0];
    let a0_is_not_fd_stdin = syscall.a0[2];
    let v0_in_a0_is_not_fd_stdin = P::Scalar::from_canonical_usize(0xFFFFFFFF);
    let v1_in_a0_is_not_fd_stdin = P::Scalar::from_canonical_usize(MIPSEBADF);
    //check:
    //1 is_syscall
    //2 sysnum==sysread
    //3 v0&v1 are right
    //4 a0 != fd_stdin
    yield_constr.constraint(filter * (is_sysread_a0_not_stdin - is_sysread * a0_is_not_fd_stdin));
    yield_constr
        .constraint(filter * is_sysread_a0_not_stdin * (v0_in_a0_is_not_fd_stdin - result_v0));
    yield_constr
        .constraint(filter * is_sysread_a0_not_stdin * (v1_in_a0_is_not_fd_stdin - result_v1));
    //check:
    //1 is_syscall
    //2 sysnum==sysread
    //3 v0&v1 are right
    //4 a0 == fd_stdin
    yield_constr.constraint(filter * (is_sysread_a0_stdin - is_sysread * a0_is_fd_stdin));
    yield_constr.constraint(filter * is_sysread_a0_stdin * (v0 - result_v0));
    yield_constr.constraint(filter * is_sysread_a0_stdin * (v1 - result_v1));

    //syswrite
    let is_syswrite = syscall.sysnum[6];
    let a0_is_fd_stdout_or_fd_stderr = syscall.a0[1];
    let a0_is_not_fd_stdout_and_fd_stderr = syscall.a0[2];

    let v0_in_a0_is_not_fd_stdout_and_fd_stderr = P::Scalar::from_canonical_usize(0xFFFFFFFF);
    let v1_in_a0_is_not_fd_stdin_and_fd_stderr = P::Scalar::from_canonical_usize(MIPSEBADF);
    //check:
    //1 is_syscall
    //2 sysnum==syswrite
    //3 v0&v1 are right
    //4 a0 =! fd_stderr and a0 != fd_stderr
    yield_constr.constraint(
        filter * (is_syswrite_a0_not_stdout_err - is_syswrite * a0_is_not_fd_stdout_and_fd_stderr),
    );
    yield_constr.constraint(
        filter
            * is_syswrite_a0_not_stdout_err
            * (v0_in_a0_is_not_fd_stdout_and_fd_stderr - result_v0),
    );
    yield_constr.constraint(
        filter
            * is_syswrite_a0_not_stdout_err
            * (v1_in_a0_is_not_fd_stdin_and_fd_stderr - result_v1),
    );
    //check:
    //1 is_syscall
    //2 sysnum==syswrite
    //3 v0&v1 are right
    //4 a0 ==fd_stderr or a0 == fd_stderr
    yield_constr.constraint(
        filter * (is_syswrite_a0_stdout_or_err - is_syswrite * a0_is_fd_stdout_or_fd_stderr),
    );
    yield_constr.constraint(filter * is_syswrite_a0_stdout_or_err * (a2 - result_v0));
    yield_constr.constraint(filter * is_syswrite_a0_stdout_or_err * (v1 - result_v1));

    //sysfcntl
    let is_sysfcntl = syscall.sysnum[7];
    let a0_is_fd_stdin = syscall.a0[0];
    let v0_in_a0_is_fd_stdin = P::ZEROS;
    let a0_is_fd_stdout_or_fd_stderr = syscall.a0[1];
    let _v0_in_a0_is_fd_stdout_or_fd_stderr = P::ONES;
    let a0_is_else = syscall.a0[2];
    let v0_in_a0_is_not_fd_stdout_and_fd_stderr_and_fd_stdin =
        P::Scalar::from_canonical_usize(0xFFFFFFFF);
    let v1_in_a0_is_not_fd_stdin_and_fd_stderr_and_fd_stdin =
        P::Scalar::from_canonical_usize(MIPSEBADF);

    yield_constr.constraint(filter * (is_sysfcntl_a0_stdin - is_sysfcntl * a0_is_fd_stdin));

    yield_constr.constraint(filter * is_sysfcntl_a0_stdin * (v0_in_a0_is_fd_stdin - result_v0));

    yield_constr.constraint(filter * is_sysfcntl_a0_stdin * (v1 - result_v1));

    yield_constr.constraint(
        filter * (is_sysfcntl_a0_stdout_or_err - is_sysfcntl * a0_is_fd_stdout_or_fd_stderr),
    );
    yield_constr.constraint(filter * is_sysfcntl_a0_stdout_or_err * (P::ONES - result_v0));

    yield_constr.constraint(filter * is_sysfcntl_a0_stdout_or_err * (v1 - result_v1));

    yield_constr.constraint(
        filter
            * (is_sysfcntl
                - is_sysfcntl_a0_stdin
                - is_sysfcntl_a0_stdout_or_err
                - is_sysfcntl * a0_is_else),
    );
    yield_constr.constraint(
        filter
            * (is_sysfcntl - is_sysfcntl_a0_stdin - is_sysfcntl_a0_stdout_or_err)
            * (v0_in_a0_is_not_fd_stdout_and_fd_stderr_and_fd_stdin - result_v0),
    );

    yield_constr.constraint(
        filter
            * (is_sysfcntl - is_sysfcntl_a0_stdin - is_sysfcntl_a0_stdout_or_err)
            * (v1_in_a0_is_not_fd_stdin_and_fd_stderr_and_fd_stdin - result_v1),
    );

    //syssetthreadarea
    let is_syssetthreadarea = syscall.sysnum[8];
    let threadarea = lv.mem_channels[6].value;
    yield_constr.constraint(filter * is_syssetthreadarea * (a0 - threadarea));
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
    let syscall = lv.general.syscall();
    let result_v0 = lv.mem_channels[4].value;
    let result_v1 = lv.mem_channels[5].value;

    //sysmap
    let is_sysmap = syscall.sysnum[1];
    let is_sz_mid_not_zero = syscall.a1; //sz & 0xFFF != 0
    let is_sz_mid_zero = syscall.sysnum[10]; //sz & 0xFFF == 0
    let sz = a1;
    let sz_in_sz_mid_not_zero = syscall.sysnum[9]; //the value of sz_mid
    let is_a0_zero = syscall.a0[0];
    let is_a0_not_zero = syscall.a0[2];
    let heap_in_a0_zero = lv.mem_channels[6].value;
    let result_heap = lv.mem_channels[7].value;
    let is_sysmap_a0_zero = syscall.cond[0];
    let is_sysmap_a0_zero_sz_nz = syscall.cond[1];
    let is_sysmap_a0_zero_sz_zero = syscall.cond[2];
    let is_sysmap_a0_nz = syscall.cond[3];
    let is_sysread_a0_not_stdin = syscall.cond[4];
    let is_sysread_a0_stdin = syscall.cond[5];
    let is_syswrite_a0_not_stdout_err = syscall.cond[6];
    let is_syswrite_a0_stdout_or_err = syscall.cond[7];
    let is_sysfcntl_a0_stdin = syscall.cond[8];
    let is_sysfcntl_a0_stdout_or_err = syscall.cond[9];
    let one_extension = builder.one_extension();

    let v0_in_a0_zero = heap_in_a0_zero;
    let heap_in_a0_zero_and_in_sz_mid_not_zero =
        builder.add_extension(heap_in_a0_zero, sz_in_sz_mid_not_zero); // branch1:sz&fff!=0 & a0==0
    let heap_in_a0_zero_and_not_in_sz_mid_not_zero = builder.add_extension(heap_in_a0_zero, sz); // branch2: sz&fff==0 &a0 ==0

    let filter_1 = builder.mul_extension(is_sysmap, is_a0_zero);
    let constr = builder.sub_extension(is_sysmap_a0_zero, filter_1);
    let constr = builder.mul_extension(filter, constr);
    yield_constr.constraint(builder, constr);

    let filter_1 = builder.mul_extension(is_sysmap_a0_zero, is_sz_mid_not_zero);
    let constr = builder.sub_extension(is_sysmap_a0_zero_sz_nz, filter_1);
    let constr = builder.mul_extension(filter, constr);
    yield_constr.constraint(builder, constr);

    let constr_1 = builder.mul_extension(filter, is_sysmap_a0_zero_sz_nz);
    let constr_2 = builder.sub_extension(heap_in_a0_zero_and_in_sz_mid_not_zero, result_heap);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let filter_1 = builder.mul_extension(is_sysmap_a0_zero, is_sz_mid_zero);
    let constr = builder.sub_extension(is_sysmap_a0_zero_sz_zero, filter_1);
    let constr = builder.mul_extension(filter, constr);
    yield_constr.constraint(builder, constr);

    let constr_1 = builder.mul_extension(filter, is_sysmap_a0_zero_sz_zero);
    let constr_2 = builder.sub_extension(heap_in_a0_zero_and_not_in_sz_mid_not_zero, result_heap);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let constr = builder.sub_extension(v0_in_a0_zero, result_v0);
    let constr = builder.mul_extension(is_sysmap_a0_zero, constr);
    let constr = builder.mul_extension(filter, constr);
    yield_constr.constraint(builder, constr);

    let filter_1 = builder.mul_extension(is_sysmap, is_a0_not_zero);
    let constr = builder.sub_extension(is_sysmap_a0_nz, filter_1);
    let constr = builder.mul_extension(filter, constr);
    yield_constr.constraint(builder, constr);

    let constr = builder.sub_extension(a0, result_v0);
    let constr = builder.mul_extension(constr, is_sysmap_a0_nz);
    let constr = builder.mul_extension(filter, constr);
    yield_constr.constraint(builder, constr);

    //sysbrk
    let is_sysbrk = syscall.sysnum[2];
    let is_sysbrk_gt = syscall.cond[10];
    let is_sysbrk_le = syscall.cond[11];
    let initial_brk = lv.mem_channels[6].value;

    let constr_1 = builder.mul_extension(filter, is_sysbrk);
    let constr_2 = builder.add_extension(is_sysbrk_gt, is_sysbrk_le);
    let constr_2 = builder.sub_extension(one_extension, constr_2);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let constr_1 = builder.mul_extension(filter, is_sysbrk_gt);
    let constr_2 = builder.sub_extension(a0, result_v0);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let constr_1 = builder.mul_extension(filter, is_sysbrk_le);
    let constr_2 = builder.sub_extension(initial_brk, result_v0);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let constr_1 = builder.mul_extension(filter, is_sysbrk);
    let constr_2 = builder.sub_extension(v1, result_v1);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    //sysclone
    let is_sysclone = syscall.sysnum[3];
    let v0_in_sysclone = builder.one_extension();
    let constr_1 = builder.mul_extension(filter, is_sysclone);
    let constr_2 = builder.sub_extension(v0_in_sysclone, result_v0);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let constr_2 = builder.sub_extension(v1, result_v1);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    // let is_SYSEXITGROUP =sys_num.is_equal_private(P::Scalar::from_canonical_usize(SYSEXITGROUP),Equal);
    // //todo
    //sysread
    let is_sysread = syscall.sysnum[5];
    let a0_is_fd_stdin = syscall.a0[0];
    let a0_is_not_fd_stdin = syscall.a0[2];
    let v0_in_a0_is_not_fd_stdin =
        builder.constant_extension(F::Extension::from_canonical_usize(0xFFFFFFFF));
    let v1_in_a0_is_not_fd_stdin =
        builder.constant_extension(F::Extension::from_canonical_usize(MIPSEBADF));

    let filter_1 = builder.mul_extension(is_sysread, a0_is_not_fd_stdin);
    let constr = builder.sub_extension(is_sysread_a0_not_stdin, filter_1);
    let constr = builder.mul_extension(filter, constr);
    yield_constr.constraint(builder, constr);

    let constr_1 = builder.mul_extension(filter, is_sysread_a0_not_stdin);
    let constr_2 = builder.sub_extension(v0_in_a0_is_not_fd_stdin, result_v0);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let constr_2 = builder.sub_extension(v1_in_a0_is_not_fd_stdin, result_v1);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let filter_1 = builder.mul_extension(is_sysread, a0_is_fd_stdin);
    let constr = builder.sub_extension(is_sysread_a0_stdin, filter_1);
    let constr = builder.mul_extension(filter, constr);
    yield_constr.constraint(builder, constr);

    let constr_1 = builder.mul_extension(filter, is_sysread_a0_stdin);
    let constr_2 = builder.sub_extension(v0, result_v0);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let constr_2 = builder.sub_extension(v1, result_v1);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    //syswrite
    let is_syswrite = syscall.sysnum[6];
    let a0_is_fd_stdout_or_fd_stderr = syscall.a0[1];
    let a0_is_not_fd_stdout_and_fd_stderr = syscall.a0[2];
    let v0_in_a0_is_not_fd_stdout_and_fd_stderr =
        builder.constant_extension(F::Extension::from_canonical_usize(0xFFFFFFFF));
    let v1_in_a0_is_not_fd_stdin_and_fd_stderr =
        builder.constant_extension(F::Extension::from_canonical_usize(MIPSEBADF));

    let filter_1 = builder.mul_extension(is_syswrite, a0_is_not_fd_stdout_and_fd_stderr);
    let constr = builder.sub_extension(is_syswrite_a0_not_stdout_err, filter_1);
    let constr = builder.mul_extension(filter, constr);
    yield_constr.constraint(builder, constr);

    let constr_1 = builder.mul_extension(filter, is_syswrite_a0_not_stdout_err);
    let constr_2 = builder.sub_extension(v0_in_a0_is_not_fd_stdout_and_fd_stderr, result_v0);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let constr_2 = builder.sub_extension(v1_in_a0_is_not_fd_stdin_and_fd_stderr, result_v1);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let filter_1 = builder.mul_extension(is_syswrite, a0_is_fd_stdout_or_fd_stderr);
    let constr = builder.sub_extension(is_syswrite_a0_stdout_or_err, filter_1);
    let constr = builder.mul_extension(filter, constr);
    yield_constr.constraint(builder, constr);

    let constr_1 = builder.mul_extension(filter, is_syswrite_a0_stdout_or_err);
    let constr_2 = builder.sub_extension(a2, result_v0);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let constr_2 = builder.sub_extension(v1, result_v1);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    //sysfcntl
    let is_sysfcntl = syscall.sysnum[7];
    let a0_is_fd_stdin = syscall.a0[0];
    let v0_in_a0_is_fd_stdin = builder.zero_extension();
    let a0_is_fd_stdout_or_fd_stderr = syscall.a0[1];
    let v0_in_a0_is_fd_stdout_or_fd_stderr = builder.one_extension();
    let a0_is_else = syscall.a0[2];
    let v0_in_a0_is_not_fd_stdout_and_fd_stderr_and_fd_stdin =
        builder.constant_extension(F::Extension::from_canonical_usize(0xFFFFFFFF));
    let v1_in_a0_is_not_fd_stdin_and_fd_stderr_and_fd_stdin =
        builder.constant_extension(F::Extension::from_canonical_usize(MIPSEBADF));

    let filter_1 = builder.mul_extension(is_sysfcntl, a0_is_fd_stdin);
    let constr = builder.sub_extension(is_sysfcntl_a0_stdin, filter_1);
    let constr = builder.mul_extension(filter, constr);
    yield_constr.constraint(builder, constr);

    let constr_1 = builder.mul_extension(filter, is_sysfcntl_a0_stdin);
    let constr_2 = builder.sub_extension(v0_in_a0_is_fd_stdin, result_v0);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let constr_2 = builder.sub_extension(v1, result_v1);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let filter_1 = builder.mul_extension(is_sysfcntl, a0_is_fd_stdout_or_fd_stderr);
    let constr = builder.sub_extension(is_sysfcntl_a0_stdout_or_err, filter_1);
    let constr = builder.mul_extension(filter, constr);
    yield_constr.constraint(builder, constr);

    let constr_1 = builder.mul_extension(filter, is_sysfcntl_a0_stdout_or_err);
    let constr_2 = builder.sub_extension(v0_in_a0_is_fd_stdout_or_fd_stderr, result_v0);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let constr_2 = builder.sub_extension(v1, result_v1);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let filter_1 = builder.mul_extension(is_sysfcntl, a0_is_else);
    let filter_2 = builder.sub_extension(is_sysfcntl, is_sysfcntl_a0_stdin);
    let filter_2 = builder.sub_extension(filter_2, is_sysfcntl_a0_stdout_or_err);
    let constr = builder.sub_extension(filter_2, filter_1);
    let constr = builder.mul_extension(filter, constr);
    yield_constr.constraint(builder, constr);

    let constr_1 = builder.mul_extension(filter, filter_2);
    let constr_2 = builder.sub_extension(
        v0_in_a0_is_not_fd_stdout_and_fd_stderr_and_fd_stdin,
        result_v0,
    );
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let constr_2 = builder.sub_extension(
        v1_in_a0_is_not_fd_stdin_and_fd_stderr_and_fd_stdin,
        result_v1,
    );
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    //syssetthreadarea
    let is_syssetthreadarea = syscall.sysnum[8];
    let threadarea = lv.mem_channels[6].value;
    let constr_1 = builder.mul_extension(filter, is_syssetthreadarea);
    let constr_2 = builder.sub_extension(a0, threadarea);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);
}
