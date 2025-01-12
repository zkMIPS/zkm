use itertools::Itertools;
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

use crate::keccak::keccak_stark;
use crate::keccak_sponge;
use crate::keccak_sponge::columns::KECCAK_WIDTH_BYTES;
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeOp;
use crate::poseidon::constants::SPONGE_WIDTH;
use crate::poseidon_sponge::columns::POSEIDON_RATE_BYTES;
use crate::poseidon_sponge::poseidon_sponge_stark::PoseidonSpongeOp;
use crate::util::join;
use crate::util::trace_rows_to_poly_values;
use crate::witness::memory::MemoryOp;
use crate::{arithmetic, logic};

#[derive(Clone, Copy, Debug)]
pub struct TraceCheckpoint {
    pub(self) arithmetic_len: usize,
    pub(self) cpu_len: usize,
    pub(self) poseidon_len: usize,
    pub(self) poseidon_sponge_len: usize,
    pub(self) keccak_len: usize,
    pub(self) keccak_sponge_len: usize,
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
    pub(crate) keccak_inputs: Vec<([u64; keccak_stark::NUM_INPUTS], usize)>,
    pub(crate) keccak_sponge_ops: Vec<KeccakSpongeOp>,
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
            keccak_inputs: vec![],
            keccak_sponge_ops: vec![],
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
            keccak_len: self.keccak_inputs.len() * keccak_stark::NUM_ROUNDS,
            keccak_sponge_len: self
                .keccak_sponge_ops
                .iter()
                .map(|op| op.input.len() / keccak_sponge::columns::KECCAK_RATE_BYTES + 1)
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
            keccak_len: self.keccak_inputs.len(),
            keccak_sponge_len: self.keccak_sponge_ops.len(),
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
        self.keccak_inputs.truncate(checkpoint.keccak_len);
        self.keccak_sponge_ops
            .truncate(checkpoint.keccak_sponge_len);
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

    pub fn push_keccak(&mut self, input: [u64; keccak_stark::NUM_INPUTS], clock: usize) {
        self.keccak_inputs.push((input, clock));
    }

    pub fn push_keccak_bytes(&mut self, input: [u8; KECCAK_WIDTH_BYTES], clock: usize) {
        let chunks = input
            .chunks(size_of::<u64>())
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
            .collect_vec()
            .try_into()
            .unwrap();
        self.push_keccak(chunks, clock);
    }

    pub fn push_keccak_sponge(&mut self, op: KeccakSpongeOp) {
        self.keccak_sponge_ops.push(op);
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
            mut memory_ops,
            poseidon_inputs,
            poseidon_sponge_ops,
            keccak_inputs,
            keccak_sponge_ops,
        } = self;

        let mut memory_trace = vec![];
        let mut arithmetic_trace = vec![];
        let mut cpu_trace = vec![];
        let mut poseidon_trace = vec![];
        let mut poseidon_sponge_trace = vec![];
        let mut keccak_trace = vec![];
        let mut keccak_sponge_trace = vec![];
        let mut logic_trace = vec![];

        timed!(
            timing,
            "convert trace to table parallelly",
            join!(
                || memory_trace = all_stark.memory_stark.generate_trace(&mut memory_ops),
                || arithmetic_trace = all_stark.arithmetic_stark.generate_trace(&arithmetic_ops),
                || cpu_trace =
                    trace_rows_to_poly_values(cpu.into_iter().map(|x| x.into()).collect()),
                || poseidon_trace = all_stark
                    .poseidon_stark
                    .generate_trace(&poseidon_inputs, min_rows),
                || poseidon_sponge_trace = all_stark
                    .poseidon_sponge_stark
                    .generate_trace(&poseidon_sponge_ops, min_rows),
                || keccak_trace = all_stark
                    .keccak_stark
                    .generate_trace(&keccak_inputs, min_rows),
                || keccak_sponge_trace = all_stark
                    .keccak_sponge_stark
                    .generate_trace(&keccak_sponge_ops, min_rows),
                || logic_trace = all_stark.logic_stark.generate_trace(&logic_ops, min_rows),
            )
        );

        [
            arithmetic_trace,
            cpu_trace,
            poseidon_trace,
            poseidon_sponge_trace,
            keccak_trace,
            keccak_sponge_trace,
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
