use crate::arithmetic::arithmetic_stark;
use crate::arithmetic::arithmetic_stark::ArithmeticStark;
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
use crate::poseidon::poseidon_stark;
use crate::poseidon::poseidon_stark::PoseidonStark;
use crate::poseidon_sponge::columns::POSEIDON_RATE_BYTES;
use crate::poseidon_sponge::poseidon_sponge_stark;
use crate::poseidon_sponge::poseidon_sponge_stark::PoseidonSpongeStark;
use crate::sha_compress::sha_compress_stark;
use crate::sha_compress::sha_compress_stark::ShaCompressStark;
use crate::sha_compress_sponge::sha_compress_sponge_stark;
use crate::sha_compress_sponge::sha_compress_sponge_stark::{
    ShaCompressSpongeStark, SHA_COMPRESS_SPONGE_READ_BYTES,
};
use crate::sha_extend::sha_extend_stark;
use crate::sha_extend::sha_extend_stark::ShaExtendStark;
use crate::sha_extend_sponge::columns::SHA_EXTEND_SPONGE_READ_BYTES;
use crate::sha_extend_sponge::sha_extend_sponge_stark;
use crate::sha_extend_sponge::sha_extend_sponge_stark::ShaExtendSpongeStark;
use crate::stark::Stark;
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;

#[derive(Clone)]
pub struct AllStark<F: RichField + Extendable<D>, const D: usize> {
    pub arithmetic_stark: ArithmeticStark<F, D>,
    pub cpu_stark: CpuStark<F, D>,
    pub poseidon_stark: PoseidonStark<F, D>,
    pub poseidon_sponge_stark: PoseidonSpongeStark<F, D>,
    pub keccak_stark: KeccakStark<F, D>,
    pub keccak_sponge_stark: KeccakSpongeStark<F, D>,
    pub sha_extend_stark: ShaExtendStark<F, D>,
    pub sha_extend_sponge_stark: ShaExtendSpongeStark<F, D>,
    pub sha_compress_stark: ShaCompressStark<F, D>,
    pub sha_compress_sponge_stark: ShaCompressSpongeStark<F, D>,
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
            keccak_stark: KeccakStark::default(),
            keccak_sponge_stark: KeccakSpongeStark::default(),
            sha_extend_stark: ShaExtendStark::default(),
            sha_extend_sponge_stark: ShaExtendSpongeStark::default(),
            sha_compress_stark: ShaCompressStark::default(),
            sha_compress_sponge_stark: ShaCompressSpongeStark::default(),
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
            self.keccak_stark.num_lookup_helper_columns(config),
            self.keccak_sponge_stark.num_lookup_helper_columns(config),
            self.sha_extend_stark.num_lookup_helper_columns(config),
            self.sha_extend_sponge_stark
                .num_lookup_helper_columns(config),
            self.sha_compress_stark.num_lookup_helper_columns(config),
            self.sha_compress_sponge_stark
                .num_lookup_helper_columns(config),
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
    Keccak = 4,
    KeccakSponge = 5,
    ShaExtend = 6,
    ShaExtendSponge = 7,
    ShaCompress = 8,
    ShaCompressSponge = 9,
    Logic = 10,
    Memory = 11,
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
            Self::Keccak,
            Self::KeccakSponge,
            Self::ShaExtend,
            Self::ShaExtendSponge,
            Self::ShaCompress,
            Self::ShaCompressSponge,
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
        ctl_keccak_sponge(),
        ctl_keccak_inputs(),
        ctl_keccak_outputs(),
        ctl_sha_extend_sponge(),
        ctl_sha_extend_inputs(),
        ctl_sha_extend_outputs(),
        ctl_sha_compress_sponge(),
        ctl_sha_compress_inputs(),
        ctl_sha_compress_outputs(),
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

fn ctl_sha_extend_inputs<F: Field>() -> CrossTableLookup<F> {
    let sha_extend_sponge_looking = TableWithColumns::new(
        Table::ShaExtendSponge,
        sha_extend_sponge_stark::ctl_looking_sha_extend_inputs(),
        Some(sha_extend_sponge_stark::ctl_looking_sha_extend_filter()),
    );
    let sha_extend_looked = TableWithColumns::new(
        Table::ShaExtend,
        sha_extend_stark::ctl_data_inputs(),
        Some(sha_extend_stark::ctl_filter()),
    );
    CrossTableLookup::new(vec![sha_extend_sponge_looking], sha_extend_looked)
}

fn ctl_sha_extend_outputs<F: Field>() -> CrossTableLookup<F> {
    let sha_extend_sponge_looking = TableWithColumns::new(
        Table::ShaExtendSponge,
        sha_extend_sponge_stark::ctl_looking_sha_extend_outputs(),
        Some(sha_extend_sponge_stark::ctl_looking_sha_extend_filter()),
    );
    let sha_extend_looked = TableWithColumns::new(
        Table::ShaExtend,
        sha_extend_stark::ctl_data_outputs(),
        Some(sha_extend_stark::ctl_filter()),
    );
    CrossTableLookup::new(vec![sha_extend_sponge_looking], sha_extend_looked)
}

fn ctl_sha_extend_sponge<F: Field>() -> CrossTableLookup<F> {
    let cpu_looking = TableWithColumns::new(
        Table::Cpu,
        cpu_stark::ctl_data_sha_extend_sponge(),
        Some(cpu_stark::ctl_filter_sha_extend_sponge()),
    );
    let sha_extend_sponge_looked = TableWithColumns::new(
        Table::ShaExtendSponge,
        sha_extend_sponge_stark::ctl_looked_data(),
        Some(sha_extend_sponge_stark::ctl_looking_sha_extend_filter()),
    );
    CrossTableLookup::new(vec![cpu_looking], sha_extend_sponge_looked)
}

fn ctl_sha_compress_inputs<F: Field>() -> CrossTableLookup<F> {
    let sha_compress_sponge_looking = TableWithColumns::new(
        Table::ShaCompressSponge,
        sha_compress_sponge_stark::ctl_looking_sha_compress_inputs(),
        Some(sha_compress_sponge_stark::ctl_looking_sha_compress_filter()),
    );
    let sha_compress_looked = TableWithColumns::new(
        Table::ShaCompress,
        sha_compress_stark::ctl_data_inputs(),
        Some(sha_compress_stark::ctl_filter_inputs()),
    );
    CrossTableLookup::new(vec![sha_compress_sponge_looking], sha_compress_looked)
}

fn ctl_sha_compress_outputs<F: Field>() -> CrossTableLookup<F> {
    let sha_compress_sponge_looking = TableWithColumns::new(
        Table::ShaCompressSponge,
        sha_compress_sponge_stark::ctl_looking_sha_compress_outputs(),
        Some(sha_compress_sponge_stark::ctl_looking_sha_compress_filter()),
    );
    let sha_compress_looked = TableWithColumns::new(
        Table::ShaCompress,
        sha_compress_stark::ctl_data_outputs(),
        Some(sha_compress_stark::ctl_filter_outputs()),
    );
    CrossTableLookup::new(vec![sha_compress_sponge_looking], sha_compress_looked)
}

fn ctl_sha_compress_sponge<F: Field>() -> CrossTableLookup<F> {
    let cpu_looking = TableWithColumns::new(
        Table::Cpu,
        cpu_stark::ctl_data_sha_compress_sponge(),
        Some(cpu_stark::ctl_filter_sha_compress_sponge()),
    );
    let sha_compress_sponge_looked = TableWithColumns::new(
        Table::ShaCompressSponge,
        sha_compress_sponge_stark::ctl_looked_data(),
        Some(sha_compress_sponge_stark::ctl_looked_filter()),
    );
    CrossTableLookup::new(vec![cpu_looking], sha_compress_sponge_looked)
}

pub(crate) fn ctl_logic<F: Field>() -> CrossTableLookup<F> {
    let cpu_looking = TableWithColumns::new(
        Table::Cpu,
        cpu_stark::ctl_data_logic(),
        Some(cpu_stark::ctl_filter_logic()),
    );

    let mut all_lookers = vec![cpu_looking];
    for i in 0..keccak_sponge_stark::num_logic_ctls() {
        let keccak_sponge_looking = TableWithColumns::new(
            Table::KeccakSponge,
            keccak_sponge_stark::ctl_looking_logic(i),
            Some(keccak_sponge_stark::ctl_looking_logic_filter()),
        );
        all_lookers.push(keccak_sponge_looking);
    }
    // sha extend logic
    {
        let sha_extend_s_0_inter_looking = TableWithColumns::new(
            Table::ShaExtend,
            sha_extend_stark::ctl_s_0_inter_looking_logic(),
            Some(sha_extend_stark::ctl_filter()),
        );
        all_lookers.push(sha_extend_s_0_inter_looking);

        let sha_extend_s_0_looking = TableWithColumns::new(
            Table::ShaExtend,
            sha_extend_stark::ctl_s_0_looking_logic(),
            Some(sha_extend_stark::ctl_filter()),
        );
        all_lookers.push(sha_extend_s_0_looking);

        let sha_extend_s_1_inter_looking = TableWithColumns::new(
            Table::ShaExtend,
            sha_extend_stark::ctl_s_1_inter_looking_logic(),
            Some(sha_extend_stark::ctl_filter()),
        );
        all_lookers.push(sha_extend_s_1_inter_looking);

        let sha_extend_s_1_looking = TableWithColumns::new(
            Table::ShaExtend,
            sha_extend_stark::ctl_s_1_looking_logic(),
            Some(sha_extend_stark::ctl_filter()),
        );
        all_lookers.push(sha_extend_s_1_looking);
    }

    // sha compress logic
    {
        let s_1_inter_looking = TableWithColumns::new(
            Table::ShaCompress,
            sha_compress_stark::ctl_s_1_inter_looking_logic(),
            Some(sha_compress_stark::ctl_logic_filter()),
        );
        let s_1_looking = TableWithColumns::new(
            Table::ShaCompress,
            sha_compress_stark::ctl_s_1_looking_logic(),
            Some(sha_compress_stark::ctl_logic_filter()),
        );
        let e_and_f_looking = TableWithColumns::new(
            Table::ShaCompress,
            sha_compress_stark::ctl_e_and_f_looking_logic(),
            Some(sha_compress_stark::ctl_logic_filter()),
        );

        let not_e_and_g_looking = TableWithColumns::new(
            Table::ShaCompress,
            sha_compress_stark::ctl_not_e_and_g_looking_logic(),
            Some(sha_compress_stark::ctl_logic_filter()),
        );

        let ch_looking = TableWithColumns::new(
            Table::ShaCompress,
            sha_compress_stark::ctl_ch_looking_logic(),
            Some(sha_compress_stark::ctl_logic_filter()),
        );

        let s_0_inter_looking = TableWithColumns::new(
            Table::ShaCompress,
            sha_compress_stark::ctl_s_0_inter_looking_logic(),
            Some(sha_compress_stark::ctl_logic_filter()),
        );

        let s_0_looking = TableWithColumns::new(
            Table::ShaCompress,
            sha_compress_stark::ctl_s_0_looking_logic(),
            Some(sha_compress_stark::ctl_logic_filter()),
        );

        let a_and_b_looking = TableWithColumns::new(
            Table::ShaCompress,
            sha_compress_stark::ctl_a_and_b_looking_logic(),
            Some(sha_compress_stark::ctl_logic_filter()),
        );
        let a_and_c_looking = TableWithColumns::new(
            Table::ShaCompress,
            sha_compress_stark::ctl_a_and_c_looking_logic(),
            Some(sha_compress_stark::ctl_logic_filter()),
        );
        let b_and_c_looking = TableWithColumns::new(
            Table::ShaCompress,
            sha_compress_stark::ctl_b_and_c_looking_logic(),
            Some(sha_compress_stark::ctl_logic_filter()),
        );

        let maj_inter_looking = TableWithColumns::new(
            Table::ShaCompress,
            sha_compress_stark::ctl_maj_inter_looking_logic(),
            Some(sha_compress_stark::ctl_logic_filter()),
        );

        let maj_looking = TableWithColumns::new(
            Table::ShaCompress,
            sha_compress_stark::ctl_maj_looking_logic(),
            Some(sha_compress_stark::ctl_logic_filter()),
        );

        all_lookers.extend([
            s_1_inter_looking,
            s_1_looking,
            e_and_f_looking,
            not_e_and_g_looking,
            ch_looking,
            s_0_inter_looking,
            s_0_looking,
            a_and_b_looking,
            a_and_c_looking,
            b_and_c_looking,
            maj_inter_looking,
            maj_looking,
        ]);
    }

    let logic_looked =
        TableWithColumns::new(Table::Logic, logic::ctl_data(), Some(logic::ctl_filter()));

    CrossTableLookup::new(all_lookers, logic_looked)
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

    let keccak_sponge_reads = (0..KECCAK_RATE_BYTES).map(|i| {
        TableWithColumns::new(
            Table::KeccakSponge,
            keccak_sponge_stark::ctl_looking_memory(i),
            Some(keccak_sponge_stark::ctl_looking_memory_filter(i)),
        )
    });

    let sha_extend_sponge_reads = (0..SHA_EXTEND_SPONGE_READ_BYTES).map(|i| {
        TableWithColumns::new(
            Table::ShaExtendSponge,
            sha_extend_sponge_stark::ctl_looking_memory(i),
            Some(sha_extend_sponge_stark::ctl_looking_sha_extend_filter()),
        )
    });

    let sha_compress_sponge_reads = (0..SHA_COMPRESS_SPONGE_READ_BYTES).map(|i| {
        TableWithColumns::new(
            Table::ShaCompressSponge,
            sha_compress_sponge_stark::ctl_looking_memory(i),
            Some(sha_compress_sponge_stark::ctl_looking_sha_compress_filter()),
        )
    });

    let sha_compress_reads = (0..4).map(|i| {
        TableWithColumns::new(
            Table::ShaCompress,
            sha_compress_stark::ctl_looking_memory(i),
            Some(sha_compress_stark::ctl_logic_filter()),
        )
    });

    let all_lookers = []
        .into_iter()
        .chain(cpu_memory_gp_ops)
        .chain(keccak_sponge_reads)
        .chain(poseidon_sponge_reads)
        .chain(sha_extend_sponge_reads)
        .chain(sha_compress_sponge_reads)
        .chain(sha_compress_reads)
        .collect();
    let memory_looked = TableWithColumns::new(
        Table::Memory,
        memory_stark::ctl_data(),
        Some(memory_stark::ctl_filter()),
    );
    CrossTableLookup::new(all_lookers, memory_looked)
}
