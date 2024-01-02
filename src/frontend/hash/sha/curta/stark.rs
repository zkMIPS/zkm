use curta::chip::register::array::ArrayRegister;
use curta::chip::register::bit::BitRegister;
use curta::chip::register::element::ElementRegister;
use curta::chip::register::Register;
use curta::chip::trace::writer::{InnerWriterData, TraceWriter};
use curta::chip::Chip;
use curta::machine::bytes::proof::ByteStarkProof;
use curta::machine::bytes::stark::ByteStark;
use curta::math::prelude::*;
use curta::plonky2::Plonky2Air;
use itertools::Itertools;
use log::debug;
use plonky2::util::timing::TimingTree;

use super::data::{SHAInputData, SHAInputDataValues};
use super::SHA;
use crate::frontend::curta::proof::ByteStarkProofVariable;
use crate::prelude::{CircuitBuilder, PlonkParameters, Variable};

#[derive(Debug, Clone)]
pub struct SHAStark<
    L: PlonkParameters<D>,
    S: SHA<L, D, CYCLE_LEN>,
    const D: usize,
    const CYCLE_LEN: usize,
> {
    pub stark: ByteStark<S::AirParameters, L::CurtaConfig, D>,
    pub padded_chunks: Vec<ArrayRegister<S::IntRegister>>,
    pub end_bits: ArrayRegister<BitRegister>,
    pub digest_bits: ArrayRegister<BitRegister>,
    pub digest_indices: ArrayRegister<ElementRegister>,
    pub digests: Vec<S::StateVariable>,
    pub num_rows: usize,
}

impl<L: PlonkParameters<D>, S: SHA<L, D, CYCLE_LEN>, const D: usize, const CYCLE_LEN: usize>
    SHAStark<L, S, D, CYCLE_LEN>
where
    Chip<S::AirParameters>: Plonky2Air<L::Field, D>,
{
    fn write_input(
        &self,
        writer: &TraceWriter<L::Field>,
        input: SHAInputDataValues<L, S, D, CYCLE_LEN>,
    ) {
        for (digest_index_reg, digest_index) in
            self.digest_indices.iter().zip(input.digest_indices.iter())
        {
            writer.write(&digest_index_reg, digest_index, 0);
        }

        for (digest_reg, digest_value) in self.digests.iter().zip(input.digests.iter()) {
            let array: ArrayRegister<_> = (*digest_reg).into();
            writer.write_array(&array, digest_value.map(S::int_to_field_value), 0);
        }

        for (chunk, chunk_value) in self
            .padded_chunks
            .iter()
            .zip(input.padded_chunks.chunks_exact(16))
        {
            writer.write_array(
                chunk,
                chunk_value.iter().map(|x| S::int_to_field_value(*x)),
                0,
            );
        }

        for (end_bit, end_bit_value) in self.end_bits.iter().zip(input.end_bits) {
            writer.write(
                &end_bit,
                &L::Field::from_canonical_u8(end_bit_value as u8),
                0,
            );
        }

        for (digest_bit, digest_bit_value) in self.digest_bits.iter().zip(input.digest_bits) {
            writer.write(
                &digest_bit,
                &L::Field::from_canonical_u8(digest_bit_value as u8),
                0,
            );
        }
    }

    /// Generate a proof for the SHA stark given the input data.
    #[allow(clippy::type_complexity)]
    pub fn prove(
        &self,
        input: SHAInputDataValues<L, S, D, CYCLE_LEN>,
    ) -> (ByteStarkProof<L::Field, L::CurtaConfig, D>, Vec<L::Field>) {
        // Initialize a writer for the trace.
        let writer = TraceWriter::new(&self.stark.air_data, self.num_rows);
        // Write the public inputs to the trace.
        self.write_input(&writer, input);
        // Execute the air instructions.
        writer.write_global_instructions(&self.stark.air_data);
        for i in 0..self.num_rows {
            writer.write_row_instructions(&self.stark.air_data, i);
        }

        // Extract the trace and public input slice from the writer.
        let InnerWriterData { trace, public, .. } = writer.into_inner().unwrap();
        let proof = self
            .stark
            .prove(&trace, &public, &mut TimingTree::default())
            .unwrap();

        // Verify proof to make sure it's valid.
        self.stark.verify(proof.clone(), &public).unwrap();
        debug!("stark proof verified");

        (proof, public)
    }

    pub fn verify_proof(
        &self,
        builder: &mut CircuitBuilder<L, D>,
        proof: ByteStarkProofVariable<D>,
        public_inputs: &[Variable],
        sha_input: SHAInputData<S::IntVariable>,
    ) {
        // Verify the stark proof.
        builder.verify_byte_stark_proof(&self.stark, proof, public_inputs);

        // Connect the public inputs of the stark proof to it's values.

        // Connect the padded chunks.
        for (int, register) in sha_input
            .padded_chunks
            .iter()
            .zip_eq(self.padded_chunks.iter().flat_map(|x| x.iter()))
        {
            let value = register.read_from_slice(public_inputs);
            let var = S::value_to_variable(builder, value);
            builder.assert_is_equal(*int, var);
        }

        // Connect end_bits.
        for (end_bit, register) in sha_input.end_bits.iter().zip_eq(self.end_bits.iter()) {
            let value = register.read_from_slice(public_inputs);
            builder.assert_is_equal(end_bit.variable, value);
        }

        // Connect digest_bits.
        for (digest_bit, register) in sha_input.digest_bits.iter().zip_eq(self.digest_bits.iter()) {
            let value = register.read_from_slice(public_inputs);
            builder.assert_is_equal(digest_bit.variable, value);
        }

        // Connect digest_indices.
        for (digest_index, register) in sha_input
            .digest_indices
            .iter()
            .zip_eq(self.digest_indices.iter())
        {
            let value = register.read_from_slice(public_inputs);
            builder.assert_is_equal(*digest_index, value);
        }

        // Connect digests.
        for (digest, &register) in sha_input.digests.iter().zip_eq(self.digests.iter()) {
            let array: ArrayRegister<S::IntRegister> = register.into();
            for (int, int_reg) in digest.iter().zip_eq(array.iter()) {
                let value = int_reg.read_from_slice(public_inputs);
                let var = S::value_to_variable(builder, value);
                builder.assert_is_equal(*int, var);
            }
        }
    }
}
