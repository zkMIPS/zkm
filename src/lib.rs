#![feature(decl_macro)]
#![feature(generic_arg_infer)]
#![feature(trait_upcasting)]
#![allow(dead_code)]
pub mod all_stark;
pub mod arithmetic;
pub mod backend;
pub mod config;
pub mod constraint_consumer;
pub mod cpu;
pub mod cross_table_lookup;
pub mod evaluation_frame;
pub mod fixed_recursive_verifier;
pub mod frontend;
pub mod generation;
pub mod get_challenges;
pub mod keccak;
pub mod keccak_sponge;
pub mod logic;
pub mod lookup;
pub mod memory;
pub mod mips_emulator;
pub mod proof;
pub mod prover;
pub mod recursive_verifier;
pub mod stark;
pub mod stark_testing;
pub mod util;
pub mod utils;
pub mod vanishing_poly;
pub mod verifier;
pub mod witness;

//#[macro_use]
extern crate prettytable;

extern crate alloc;

pub mod prelude {
    pub use plonky2::field::extension::Extendable;
    pub use plonky2::field::goldilocks_field::GoldilocksField;
    pub use plonky2::field::types::Field;
    pub use plonky2::hash::hash_types::RichField;
    pub use plonky2::iop::target::Target;
    pub use plonky2::iop::witness::{PartialWitness, Witness, WitnessWrite};
    pub use plonky2::plonk::config::PoseidonGoldilocksConfig;
    pub use plonky2x_derive::CircuitVariable;

    pub use crate::backend::circuit::config::{DefaultParameters, PlonkParameters};
    pub use crate::backend::circuit::{GateRegistry, HintRegistry};
    pub use crate::frontend::builder::{CircuitBuilder, DefaultBuilder};
    pub use crate::frontend::ops::*;
    pub use crate::frontend::uint::uint128::U128Variable;
    pub use crate::frontend::uint::uint256::U256Variable;
    pub use crate::frontend::uint::uint64::U64Variable;
    pub use crate::frontend::vars::{
        ArrayVariable, BoolVariable, ByteVariable, Bytes32Variable, BytesVariable, CircuitVariable,
        OutputVariableStream, U32Variable, ValueStream, Variable, VariableStream,
    };
    pub use crate::utils::{address, bytes, bytes32, hex};
}
