use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;

use crate::arithmetic::arithmetic_stark;
use crate::arithmetic::arithmetic_stark::ArithmeticStark;
//use crate::byte_packing::byte_packing_stark::{self, BytePackingStark};
use crate::config::StarkConfig;
use crate::cpu::cpu_stark;
use crate::cpu::cpu_stark::CpuStark;
use crate::cpu::membus::NUM_GP_CHANNELS;
use crate::cross_table_lookup::{CrossTableLookup, TableWithColumns};
use crate::keccak::keccak_stark;
use crate::keccak::keccak_stark::KeccakStark;
use crate::keccak_sponge::columns::KECCAK_RATE_BYTES;
use crate::keccak_sponge::keccak_sponge_stark;
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeStark;
use crate::logic;
use crate::logic::LogicStark;
use crate::memory::memory_stark;
use crate::memory::memory_stark::MemoryStark;
use crate::stark::Stark;

#[derive(Clone)]
pub struct AllStark<F: RichField + Extendable<D>, const D: usize> {
    pub arithmetic_stark: ArithmeticStark<F, D>,
    //   pub byte_packing_stark: BytePackingStark<F, D>,
    pub cpu_stark: CpuStark<F, D>,
    pub keccak_stark: KeccakStark<F, D>,
    pub keccak_sponge_stark: KeccakSpongeStark<F, D>,
    pub logic_stark: LogicStark<F, D>,
    pub memory_stark: MemoryStark<F, D>,
    pub cross_table_lookups: Vec<CrossTableLookup<F>>,
}

impl<F: RichField + Extendable<D>, const D: usize> Default for AllStark<F, D> {
    fn default() -> Self {
        Self {
            arithmetic_stark: ArithmeticStark::default(),
            //           byte_packing_stark: BytePackingStark::default(),
            cpu_stark: CpuStark::default(),
            keccak_stark: KeccakStark::default(),
            keccak_sponge_stark: KeccakSpongeStark::default(),
            logic_stark: LogicStark::default(),
            memory_stark: MemoryStark::default(),
            cross_table_lookups: all_cross_table_lookups(),
        }
    }
}

impl<F: RichField + Extendable<D>, const D: usize> AllStark<F, D> {
    pub(crate) fn num_lookups_helper_columns(&self, config: &StarkConfig) -> [usize; 6] {
        [
            self.arithmetic_stark.num_lookup_helper_columns(config),
            //            self.byte_packing_stark.num_lookup_helper_columns(config),
            self.cpu_stark.num_lookup_helper_columns(config),
            self.keccak_stark.num_lookup_helper_columns(config),
            self.keccak_sponge_stark.num_lookup_helper_columns(config),
            self.logic_stark.num_lookup_helper_columns(config),
            self.memory_stark.num_lookup_helper_columns(config),
        ]
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Table {
    Arithmetic = 0,
    Cpu = 1,
    Keccak = 2,
    KeccakSponge = 3,
    Logic = 4,
    Memory = 5,
}

pub(crate) const NUM_TABLES: usize = Table::Memory as usize + 1;

impl Table {
    pub(crate) fn all() -> [Self; NUM_TABLES] {
        [
            Self::Arithmetic,
            Self::Cpu,
            Self::Keccak,
            Self::KeccakSponge,
            Self::Logic,
            Self::Memory,
        ]
    }
}

pub(crate) fn all_cross_table_lookups<F: Field>() -> Vec<CrossTableLookup<F>> {
    vec![
        ctl_arithmetic(),
        ctl_keccak_sponge(),
        ctl_keccak_inputs(),
        ctl_keccak_outputs(),
        ctl_logic(),
        ctl_memory(),
    ]
}

fn ctl_arithmetic<F: Field>() -> CrossTableLookup<F> {
    CrossTableLookup::new(
        vec![cpu_stark::ctl_arithmetic_base_rows()],
        arithmetic_stark::ctl_arithmetic_rows(),
    )
}

// We now need two different looked tables for `KeccakStark`:
// one for the inputs and one for the outputs.
// They are linked with the timestamp.
fn ctl_keccak_inputs<F: Field>() -> CrossTableLookup<F> {
    let keccak_sponge_looking = TableWithColumns::new(
        Table::KeccakSponge,
        keccak_sponge_stark::ctl_looking_keccak_inputs(),
        Some(keccak_sponge_stark::ctl_looking_keccak_filter()),
    );
    let keccak_looked = TableWithColumns::new(
        Table::Keccak,
        keccak_stark::ctl_data_inputs(),
        Some(keccak_stark::ctl_filter_inputs()),
    );
    CrossTableLookup::new(vec![keccak_sponge_looking], keccak_looked)
}

fn ctl_keccak_outputs<F: Field>() -> CrossTableLookup<F> {
    let keccak_sponge_looking = TableWithColumns::new(
        Table::KeccakSponge,
        keccak_sponge_stark::ctl_looking_keccak_outputs(),
        Some(keccak_sponge_stark::ctl_looking_keccak_filter()),
    );
    let keccak_looked = TableWithColumns::new(
        Table::Keccak,
        keccak_stark::ctl_data_outputs(),
        Some(keccak_stark::ctl_filter_outputs()),
    );
    CrossTableLookup::new(vec![keccak_sponge_looking], keccak_looked)
}

fn ctl_keccak_sponge<F: Field>() -> CrossTableLookup<F> {
    let cpu_looking = TableWithColumns::new(
        Table::Cpu,
        cpu_stark::ctl_data_keccak_sponge(),
        Some(cpu_stark::ctl_filter_keccak_sponge()),
    );
    let keccak_sponge_looked = TableWithColumns::new(
        Table::KeccakSponge,
        keccak_sponge_stark::ctl_looked_data(),
        Some(keccak_sponge_stark::ctl_looked_filter()),
    );
    CrossTableLookup::new(vec![cpu_looking], keccak_sponge_looked)
}

pub(crate) fn ctl_logic<F: Field>() -> CrossTableLookup<F> {
    let cpu_looking = TableWithColumns::new(
        Table::Cpu,
        cpu_stark::ctl_data_logic(),
        Some(cpu_stark::ctl_filter_logic()),
    );
    let mut all_lookers = vec![cpu_looking];
    /* FIXME: connect keccak, may use 8 u32s
    for i in 0..keccak_sponge_stark::num_logic_ctls() {
        let keccak_sponge_looking = TableWithColumns::new(
            Table::KeccakSponge,
            keccak_sponge_stark::ctl_looking_logic(i),
            Some(keccak_sponge_stark::ctl_looking_logic_filter()),
        );
        all_lookers.push(keccak_sponge_looking);
    }
    */
    let logic_looked =
        TableWithColumns::new(Table::Logic, logic::ctl_data(), Some(logic::ctl_filter()));
    CrossTableLookup::new(all_lookers, logic_looked)
}

fn ctl_memory<F: Field>() -> CrossTableLookup<F> {
    let cpu_memory_code_read = TableWithColumns::new(
        Table::Cpu,
        cpu_stark::ctl_data_code_memory::<F>(),
        Some(cpu_stark::ctl_filter_code_memory()),
    );
    let cpu_memory_gp_ops = (0..NUM_GP_CHANNELS).map(|channel| {
        TableWithColumns::new(
            Table::Cpu,
            cpu_stark::ctl_data_gp_memory(channel),
            Some(cpu_stark::ctl_filter_gp_memory(channel)),
        )
    });
    let keccak_sponge_reads = (0..KECCAK_RATE_BYTES).map(|i| {
        TableWithColumns::new(
            Table::KeccakSponge,
            keccak_sponge_stark::ctl_looking_memory(i),
            Some(keccak_sponge_stark::ctl_looking_memory_filter(i)),
        )
    });
    let all_lookers = cpu_memory_gp_ops
        .into_iter()
        .chain(keccak_sponge_reads)
        .collect();
    let memory_looked = TableWithColumns::new(
        Table::Memory,
        memory_stark::ctl_data(),
        Some(memory_stark::ctl_filter()),
    );
    CrossTableLookup::new(all_lookers, memory_looked)
}
