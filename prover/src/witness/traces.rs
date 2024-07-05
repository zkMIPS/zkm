use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::RichField;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use std::cmp::max;

use crate::all_stark::{AllStark, MIN_TRACE_LEN, NUM_TABLES};
use crate::arithmetic::{BinaryOperator, Operation};
use crate::config::StarkConfig;
use crate::cpu::columns::CpuColumnsView;

use crate::poseidon::constants::SPONGE_WIDTH;
use crate::poseidon_sponge::columns::POSEIDON_RATE_BYTES;
use crate::poseidon_sponge::poseidon_sponge_stark::PoseidonSpongeOp;
use crate::util::trace_rows_to_poly_values;
use crate::witness::memory::MemoryOp;
use crate::{arithmetic, logic};

#[derive(Clone, Copy, Debug)]
pub struct TraceCheckpoint {
    pub(self) arithmetic_len: usize,
    pub(self) cpu_len: usize,
    pub(self) poseidon_len: usize,
    pub(self) poseidon_sponge_len: usize,
    pub(self) logic_len: usize,
    pub(self) memory_len: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct Traces<T: Copy> {
    pub(crate) arithmetic_ops: Vec<Operation>,
    pub(crate) cpu: Vec<CpuColumnsView<T>>,
    pub(crate) logic_ops: Vec<logic::Operation>,
    pub(crate) memory_ops: Vec<MemoryOp>,
    pub(crate) poseidon_inputs: Vec<([T; SPONGE_WIDTH], usize)>,
    pub(crate) poseidon_sponge_ops: Vec<PoseidonSpongeOp>,
}

impl<T: Copy> Traces<T> {
    pub fn new() -> Self {
        Traces {
            arithmetic_ops: vec![],
            cpu: vec![],
            logic_ops: vec![],
            memory_ops: vec![],
            poseidon_inputs: vec![],
            poseidon_sponge_ops: vec![],
        }
    }

    /// Returns the actual trace lengths for each STARK module.
    //  Uses a `TraceCheckPoint` as return object for convenience.
    pub fn get_lengths(&self) -> TraceCheckpoint {
        TraceCheckpoint {
            arithmetic_len: self
                .arithmetic_ops
                .iter()
                .map(|op| match op {
                    Operation::BinaryOperation { operator, .. } => match operator {
                        BinaryOperator::DIV => 2,
                        _ => 1,
                    },
                })
                .sum(),
            cpu_len: self.cpu.len(),
            poseidon_len: self.poseidon_inputs.len(),
            poseidon_sponge_len: self
                .poseidon_sponge_ops
                .iter()
                .map(|op| op.input.len() / POSEIDON_RATE_BYTES + 1)
                .sum(),
            logic_len: self.logic_ops.len(),
            // This is technically a lower-bound, as we may fill gaps,
            // but this gives a relatively good estimate.
            memory_len: self.memory_ops.len(),
        }
    }

    /// Returns the number of operations for each STARK module.
    pub fn checkpoint(&self) -> TraceCheckpoint {
        TraceCheckpoint {
            arithmetic_len: self.arithmetic_ops.len(),
            cpu_len: self.cpu.len(),
            poseidon_len: self.poseidon_inputs.len(),
            poseidon_sponge_len: self.poseidon_sponge_ops.len(),
            logic_len: self.logic_ops.len(),
            memory_len: self.memory_ops.len(),
        }
    }

    pub fn rollback(&mut self, checkpoint: TraceCheckpoint) {
        self.arithmetic_ops.truncate(checkpoint.arithmetic_len);
        self.cpu.truncate(checkpoint.cpu_len);
        self.poseidon_inputs.truncate(checkpoint.poseidon_len);
        self.poseidon_sponge_ops
            .truncate(checkpoint.poseidon_sponge_len);
        self.logic_ops.truncate(checkpoint.logic_len);
        self.memory_ops.truncate(checkpoint.memory_len);
    }

    pub fn mem_ops_since(&self, checkpoint: TraceCheckpoint) -> &[MemoryOp] {
        &self.memory_ops[checkpoint.memory_len..]
    }

    pub fn push_cpu(&mut self, val: CpuColumnsView<T>) {
        self.cpu.push(val);
    }

    pub fn push_logic(&mut self, op: logic::Operation) {
        self.logic_ops.push(op);
    }

    pub fn push_arithmetic(&mut self, op: arithmetic::Operation) {
        self.arithmetic_ops.push(op);
    }

    pub fn push_memory(&mut self, op: MemoryOp) {
        self.memory_ops.push(op);
    }

    pub fn push_poseidon(&mut self, input: [T; SPONGE_WIDTH], clock: usize) {
        self.poseidon_inputs.push((input, clock));
    }

    pub fn push_poseidon_sponge(&mut self, op: PoseidonSpongeOp) {
        self.poseidon_sponge_ops.push(op);
    }

    pub fn clock(&self) -> usize {
        self.cpu.len()
    }

    pub fn into_tables<const D: usize>(
        self,
        all_stark: &AllStark<T, D>,
        config: &StarkConfig,
        timing: &mut TimingTree,
    ) -> [Vec<PolynomialValues<T>>; NUM_TABLES]
    where
        T: RichField + Extendable<D>,
    {
        let cap_elements = config.fri_config.num_cap_elements();
        let min_rows = max(cap_elements, MIN_TRACE_LEN);
        let Traces {
            arithmetic_ops,
            cpu,
            logic_ops,
            memory_ops,
            poseidon_inputs,
            poseidon_sponge_ops,
        } = self;

        let arithmetic_trace = timed!(
            timing,
            "generate arithmetic trace",
            all_stark.arithmetic_stark.generate_trace(arithmetic_ops)
        );
        let cpu_rows: Vec<_> = cpu.into_iter().map(|x| x.into()).collect();
        let cpu_trace = trace_rows_to_poly_values(cpu_rows);
        let poseidon_trace = timed!(
            timing,
            "generate Poseidon trace",
            all_stark
                .poseidon_stark
                .generate_trace(poseidon_inputs, min_rows, timing)
        );
        let poseidon_sponge_trace = timed!(
            timing,
            "generate Poseidon sponge trace",
            all_stark
                .poseidon_sponge_stark
                .generate_trace(poseidon_sponge_ops, min_rows, timing)
        );
        let logic_trace = timed!(
            timing,
            "generate logic trace",
            all_stark
                .logic_stark
                .generate_trace(logic_ops, min_rows, timing)
        );
        let memory_trace = timed!(
            timing,
            "generate memory trace",
            all_stark.memory_stark.generate_trace(memory_ops, timing)
        );

        [
            arithmetic_trace,
            cpu_trace,
            poseidon_trace,
            poseidon_sponge_trace,
            logic_trace,
            memory_trace,
        ]
    }
}

impl<T: Copy> Default for Traces<T> {
    fn default() -> Self {
        Self::new()
    }
}
