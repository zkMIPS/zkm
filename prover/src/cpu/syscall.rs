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
    let a2 = lv.mem_channels[3].value;
    let v1 = P::ZEROS;
    let syscall = lv.general.syscall();
    let result_v0 = lv.mem_channels[4].value;
    let result_v1 = lv.mem_channels[5].value;

    //syswrite
    let a0_is_fd_stdout_or_fd_stderr = syscall.cond[0];
    let a0_is_not_fd_stdout_and_fd_stderr = syscall.cond[1];

    let v0_in_a0_is_not_fd_stdout_and_fd_stderr = P::Scalar::from_canonical_usize(0xFFFFFFFF);
    let v1_in_a0_is_not_fd_stdin_and_fd_stderr = P::Scalar::from_canonical_usize(MIPSEBADF);
    //check:
    //1 is_syscall
    //2 sysnum==syswrite
    //3 v0&v1 are right
    //4 a0 =! fd_stderr and a0 != fd_stderr

    yield_constr.constraint(
        filter
            * a0_is_not_fd_stdout_and_fd_stderr
            * (v0_in_a0_is_not_fd_stdout_and_fd_stderr - result_v0),
    );
    yield_constr.constraint(
        filter
            * a0_is_not_fd_stdout_and_fd_stderr
            * (v1_in_a0_is_not_fd_stdin_and_fd_stderr - result_v1),
    );
    //check:
    //1 is_syscall
    //2 sysnum==syswrite
    //3 v0&v1 are right
    //4 a0 ==fd_stderr or a0 == fd_stderr
    yield_constr.constraint(filter * a0_is_fd_stdout_or_fd_stderr * (a2 - result_v0));
    yield_constr.constraint(filter * a0_is_fd_stdout_or_fd_stderr * (v1 - result_v1));

}

pub fn eval_ext_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    lv: &CpuColumnsView<ExtensionTarget<D>>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let filter = lv.op.syscall;
    // let _sys_num = lv.mem_channels[0].value;
    let a2 = lv.mem_channels[3].value;
    let v1 = builder.zero_extension();
    let syscall = lv.general.syscall();
    let result_v0 = lv.mem_channels[4].value;
    let result_v1 = lv.mem_channels[5].value;

    //syswrite
    let a0_is_fd_stdout_or_fd_stderr = syscall.cond[0];
    let a0_is_not_fd_stdout_and_fd_stderr = syscall.cond[1];
    let v0_in_a0_is_not_fd_stdout_and_fd_stderr =
        builder.constant_extension(F::Extension::from_canonical_usize(0xFFFFFFFF));
    let v1_in_a0_is_not_fd_stdin_and_fd_stderr =
        builder.constant_extension(F::Extension::from_canonical_usize(MIPSEBADF));

    let constr_1 = builder.mul_extension(filter, a0_is_not_fd_stdout_and_fd_stderr);
    let constr_2 = builder.sub_extension(v0_in_a0_is_not_fd_stdout_and_fd_stderr, result_v0);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let constr_2 = builder.sub_extension(v1_in_a0_is_not_fd_stdin_and_fd_stderr, result_v1);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let constr_1 = builder.mul_extension(filter, a0_is_fd_stdout_or_fd_stderr);
    let constr_2 = builder.sub_extension(a2, result_v0);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);

    let constr_2 = builder.sub_extension(v1, result_v1);
    let constr = builder.mul_extension(constr_1, constr_2);
    yield_constr.constraint(builder, constr);
}
