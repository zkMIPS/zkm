use crate::arithmetic::arithmetic_stark;
use crate::arithmetic::arithmetic_stark::ArithmeticStark;
use crate::config::StarkConfig;
use crate::cpu::cpu_stark;
use crate::cpu::cpu_stark::CpuStark;
use crate::cpu::membus::NUM_GP_CHANNELS;
use crate::cross_table_lookup::{CrossTableLookup, TableWithColumns};
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;

use crate::logic;
use crate::logic::LogicStark;
use crate::memory::memory_stark;
use crate::memory::memory_stark::MemoryStark;
use crate::poseidon::poseidon_stark;
use crate::poseidon::poseidon_stark::PoseidonStark;
use crate::poseidon_sponge::columns::POSEIDON_RATE_BYTES;
use crate::poseidon_sponge::poseidon_sponge_stark;
use crate::poseidon_sponge::poseidon_sponge_stark::PoseidonSpongeStark;
use crate::stark::Stark;

#[derive(Clone)]
pub struct AllStark<F: RichField + Extendable<D>, const D: usize> {
    pub arithmetic_stark: ArithmeticStark<F, D>,
    pub cpu_stark: CpuStark<F, D>,
    pub poseidon_stark: PoseidonStark<F, D>,
    pub poseidon_sponge_stark: PoseidonSpongeStark<F, D>,
    pub logic_stark: LogicStark<F, D>,
    pub memory_stark: MemoryStark<F, D>,
    pub cross_table_lookups: Vec<CrossTableLookup<F>>,
}

impl<F: RichField + Extendable<D>, const D: usize> Default for AllStark<F, D> {
    fn default() -> Self {
        Self {
            arithmetic_stark: ArithmeticStark::default(),
            cpu_stark: CpuStark::default(),
            poseidon_stark: PoseidonStark::default(),
            poseidon_sponge_stark: PoseidonSpongeStark::default(),
            logic_stark: LogicStark::default(),
            memory_stark: MemoryStark::default(),
            cross_table_lookups: all_cross_table_lookups(),
        }
    }
}

impl<F: RichField + Extendable<D>, const D: usize> AllStark<F, D> {
    pub(crate) fn num_lookups_helper_columns(&self, config: &StarkConfig) -> [usize; NUM_TABLES] {
        [
            self.arithmetic_stark.num_lookup_helper_columns(config),
            self.cpu_stark.num_lookup_helper_columns(config),
            self.poseidon_stark.num_lookup_helper_columns(config),
            self.poseidon_sponge_stark.num_lookup_helper_columns(config),
            self.logic_stark.num_lookup_helper_columns(config),
            self.memory_stark.num_lookup_helper_columns(config),
        ]
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Table {
    Arithmetic = 0,
    Cpu = 1,
    Poseidon = 2,
    PoseidonSponge = 3,
    Logic = 4,
    Memory = 5,
}

pub(crate) const NUM_TABLES: usize = Table::Memory as usize + 1;
pub(crate) const NUM_PUBLIC_INPUT_USERDATA: usize = 32;

pub(crate) const MIN_TRACE_LEN: usize = 1 << 6;

impl Table {
    pub(crate) fn all() -> [Self; NUM_TABLES] {
        [
            Self::Arithmetic,
            Self::Cpu,
            Self::Poseidon,
            Self::PoseidonSponge,
            Self::Logic,
            Self::Memory,
        ]
    }
}

pub(crate) fn all_cross_table_lookups<F: Field>() -> Vec<CrossTableLookup<F>> {
    vec![
        ctl_arithmetic(),
        ctl_poseidon_sponge(),
        ctl_poseidon_inputs(),
        ctl_poseidon_outputs(),
        ctl_logic(),
        ctl_memory(),
    ]
}

fn ctl_arithmetic<F: Field>() -> CrossTableLookup<F> {
    CrossTableLookup::new(
        vec![
            cpu_stark::ctl_arithmetic_base_rows(),
            cpu_stark::ctl_arithmetic_imm_base_rows(),
        ],
        arithmetic_stark::ctl_arithmetic_rows(),
    )
}

// We now need two different looked tables for `PoseidonStark`:
// one for the inputs and one for the outputs.
// They are linked with the timestamp.
fn ctl_poseidon_inputs<F: Field>() -> CrossTableLookup<F> {
    let poseidon_sponge_looking = TableWithColumns::new(
        Table::PoseidonSponge,
        poseidon_sponge_stark::ctl_looking_poseidon_inputs(),
        Some(poseidon_sponge_stark::ctl_looking_poseidon_filter()),
    );
    let poseidon_looked = TableWithColumns::new(
        Table::Poseidon,
        poseidon_stark::ctl_data_inputs(),
        Some(poseidon_stark::ctl_filter_inputs()),
    );
    CrossTableLookup::new(vec![poseidon_sponge_looking], poseidon_looked)
}

fn ctl_poseidon_outputs<F: Field>() -> CrossTableLookup<F> {
    let poseidon_sponge_looking = TableWithColumns::new(
        Table::PoseidonSponge,
        poseidon_sponge_stark::ctl_looking_poseidon_outputs(),
        Some(poseidon_sponge_stark::ctl_looking_poseidon_filter()),
    );
    let poseidon_looked = TableWithColumns::new(
        Table::Poseidon,
        poseidon_stark::ctl_data_outputs(),
        Some(poseidon_stark::ctl_filter_outputs()),
    );
    CrossTableLookup::new(vec![poseidon_sponge_looking], poseidon_looked)
}

fn ctl_poseidon_sponge<F: Field>() -> CrossTableLookup<F> {
    let cpu_looking = TableWithColumns::new(
        Table::Cpu,
        cpu_stark::ctl_data_poseidon_sponge(),
        Some(cpu_stark::ctl_filter_poseidon_sponge()),
    );
    let poseidon_sponge_looked = TableWithColumns::new(
        Table::PoseidonSponge,
        poseidon_sponge_stark::ctl_looked_data(),
        Some(poseidon_sponge_stark::ctl_looked_filter()),
    );
    CrossTableLookup::new(vec![cpu_looking], poseidon_sponge_looked)
}

pub(crate) fn ctl_logic<F: Field>() -> CrossTableLookup<F> {
    let cpu_looking = TableWithColumns::new(
        Table::Cpu,
        cpu_stark::ctl_data_logic(),
        Some(cpu_stark::ctl_filter_logic()),
    );
    let logic_looked =
        TableWithColumns::new(Table::Logic, logic::ctl_data(), Some(logic::ctl_filter()));

    CrossTableLookup::new(vec![cpu_looking], logic_looked)
}

fn ctl_memory<F: Field>() -> CrossTableLookup<F> {
    let cpu_memory_gp_ops = (0..NUM_GP_CHANNELS).map(|channel| {
        TableWithColumns::new(
            Table::Cpu,
            cpu_stark::ctl_data_gp_memory(channel),
            Some(cpu_stark::ctl_filter_gp_memory(channel)),
        )
    });
    let poseidon_sponge_reads = (0..POSEIDON_RATE_BYTES).map(|i| {
        TableWithColumns::new(
            Table::PoseidonSponge,
            poseidon_sponge_stark::ctl_looking_memory(i),
            Some(poseidon_sponge_stark::ctl_looking_memory_filter(i)),
        )
    });
    let all_lookers = []
        .into_iter()
        .chain(cpu_memory_gp_ops)
        .chain(poseidon_sponge_reads)
        .collect();
    let memory_looked = TableWithColumns::new(
        Table::Memory,
        memory_stark::ctl_data(),
        Some(memory_stark::ctl_filter()),
    );
    CrossTableLookup::new(all_lookers, memory_looked)
}
