use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::time::Duration;

use anyhow::Result;
use itertools::Itertools;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;
use plonky2x::backend::circuit::Groth16WrapperParameters;
use plonky2x::backend::wrapper::wrap::{WrappedCircuit, WrappedOutput};
use plonky2x::frontend::builder::CircuitBuilder as WrapperBuilder;
use plonky2x::prelude::DefaultParameters;

use crate::all_stark::{AllStark, NUM_TABLES};
use crate::config::StarkConfig;
use crate::cpu::kernel::assembler::Kernel;
use crate::cpu::kernel::elf::Program;
use crate::fixed_recursive_verifier::AllRecursiveCircuits;
use crate::generation::generate_traces;
use crate::generation::outputs::GenerationOutputs;
use crate::proof::{AllProof, PublicValues};
use crate::prover::prove_with_traces;

const DEFAULT_SEG_SIZE: usize = 1 << 20;
const D: usize = 2;

type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

pub struct Prover {
    stark: AllStark<F, D>,
    config: StarkConfig,
    kernel: Kernel,
}

impl Prover {
    pub fn new(kernel_file: File, size: Option<usize>) -> Self {
        let seg_reader = BufReader::new(kernel_file);
        let program = Program::load_segment(seg_reader).expect("load segment err");
        let kernel = Kernel {
            program,
            ordered_labels: vec![],
            global_labels: HashMap::new(),
            blockpath: String::new(),
            steps: size.unwrap_or(DEFAULT_SEG_SIZE),
        };

        Self {
            stark: Default::default(),
            config: StarkConfig::standard_fast_config(),
            kernel,
        }
    }

    pub fn gen_traces(
        &self,
    ) -> Result<(
        [Vec<PolynomialValues<F>>; NUM_TABLES],
        PublicValues,
        GenerationOutputs,
    )> {
        let mut timing = TimingTree::new("traces", log::Level::Info);
        let (traces, public_values, outputs) =
            generate_traces(&self.stark, &self.kernel, &self.config, &mut timing)?;
        timing.filter(Duration::from_millis(100)).print();

        Ok((traces, public_values, outputs))
    }

    pub fn prove(
        &self,
        trace_poly_values: [Vec<PolynomialValues<F>>; NUM_TABLES],
        public_values: PublicValues,
    ) -> Result<AllProof<F, C, D>> {
        let mut timing = TimingTree::new("prove", log::Level::Info);
        let proof = prove_with_traces(
            &self.stark,
            &self.config,
            trace_poly_values,
            public_values,
            &mut timing,
        )?;
        timing.filter(Duration::from_millis(100)).print();

        Ok(proof)
    }
}

pub struct ProverWithKernels {
    stark: AllStark<F, D>,
    config: StarkConfig,
    kernels: Vec<Kernel>,
}

impl ProverWithKernels {
    pub fn new(kernel_files: Vec<String>, size: Option<usize>) -> Self {
        let steps = size.unwrap_or(DEFAULT_SEG_SIZE);

        let kernels = kernel_files
            .into_iter()
            .map(|path| {
                let file = File::open(path).expect("open file err");
                let seg_reader = BufReader::new(file);
                let program = Program::load_segment(seg_reader).expect("load segment err");

                Kernel {
                    program,
                    ordered_labels: vec![],
                    global_labels: HashMap::new(),
                    blockpath: String::new(),
                    steps,
                }
            })
            .collect_vec();

        Self {
            stark: Default::default(),
            config: StarkConfig::standard_fast_config(),
            kernels,
        }
    }
    pub fn prove(&self) -> Result<WrappedOutput<Groth16WrapperParameters, D>> {
        let seg_file_number = self.kernels.len();
        if seg_file_number < 2 {
            panic!("seg file number must >= 2\n");
        }

        let total_timing = TimingTree::new("prove total time", log::Level::Info);
        // Preprocess all circuits.
        let all_circuits = AllRecursiveCircuits::<F, C, D>::new(
            &self.stark,
            &[10..21, 12..22, 12..21, 8..21, 6..21, 13..23],
            &self.config,
        );

        let mut timing = TimingTree::new("prove root first", log::Level::Info);
        let (mut agg_proof, mut updated_agg_public_values) =
            all_circuits.prove_root(&self.stark, &self.kernels[0], &self.config, &mut timing)?;
        timing.filter(Duration::from_millis(100)).print();
        all_circuits.verify_root(agg_proof.clone())?;

        let mut base_seg = 1;
        let mut is_agg = false;

        if seg_file_number % 2 == 0 {
            timing = TimingTree::new("prove root second", log::Level::Info);
            let (root_proof, public_values) = all_circuits.prove_root(
                &self.stark,
                &self.kernels[1],
                &self.config,
                &mut timing,
            )?;
            timing.filter(Duration::from_millis(100)).print();

            all_circuits.verify_root(root_proof.clone())?;

            // Update public values for the aggregation.
            let agg_public_values = PublicValues {
                roots_before: updated_agg_public_values.roots_before,
                roots_after: public_values.roots_after,
                userdata: public_values.userdata,
            };
            timing = TimingTree::new("prove aggression", log::Level::Info);
            // We can duplicate the proofs here because the state hasn't mutated.
            (agg_proof, updated_agg_public_values) = all_circuits.prove_aggregation(
                false,
                &agg_proof,
                false,
                &root_proof,
                agg_public_values.clone(),
            )?;
            timing.filter(Duration::from_millis(100)).print();
            all_circuits.verify_aggregation(&agg_proof)?;

            is_agg = true;
            base_seg = 2;
        }

        for i in 0..(seg_file_number - base_seg) / 2 {
            let mut timing = TimingTree::new("prove root first", log::Level::Info);
            let (root_proof_first, first_public_values) = all_circuits.prove_root(
                &self.stark,
                &self.kernels[base_seg + (i << 1)],
                &self.config,
                &mut timing,
            )?;

            timing.filter(Duration::from_millis(100)).print();
            all_circuits.verify_root(root_proof_first.clone())?;
            let mut timing = TimingTree::new("prove root second", log::Level::Info);
            let (root_proof, public_values) = all_circuits.prove_root(
                &self.stark,
                &self.kernels[base_seg + (i << 1) + 1],
                &self.config,
                &mut timing,
            )?;
            timing.filter(Duration::from_millis(100)).print();

            all_circuits.verify_root(root_proof.clone())?;

            // Update public values for the aggregation.
            let new_agg_public_values = PublicValues {
                roots_before: first_public_values.roots_before,
                roots_after: public_values.roots_after,
                userdata: public_values.userdata,
            };
            timing = TimingTree::new("prove aggression", log::Level::Info);
            // We can duplicate the proofs here because the state hasn't mutated.
            let (new_agg_proof, new_updated_agg_public_values) = all_circuits.prove_aggregation(
                false,
                &root_proof_first,
                false,
                &root_proof,
                new_agg_public_values,
            )?;
            timing.filter(Duration::from_millis(100)).print();
            all_circuits.verify_aggregation(&new_agg_proof)?;

            // Update public values for the nested aggregation.
            let agg_public_values = PublicValues {
                roots_before: updated_agg_public_values.roots_before,
                roots_after: new_updated_agg_public_values.roots_after,
                userdata: new_updated_agg_public_values.userdata,
            };
            timing = TimingTree::new("prove nested aggression", log::Level::Info);

            // We can duplicate the proofs here because the state hasn't mutated.
            (agg_proof, updated_agg_public_values) = all_circuits.prove_aggregation(
                is_agg,
                &agg_proof,
                true,
                &new_agg_proof,
                agg_public_values.clone(),
            )?;
            is_agg = true;
            timing.filter(Duration::from_millis(100)).print();

            all_circuits.verify_aggregation(&agg_proof)?;
        }

        let (block_proof, _block_public_values) =
            all_circuits.prove_block(None, &agg_proof, updated_agg_public_values)?;

        all_circuits.verify_block(&block_proof)?;

        let builder = WrapperBuilder::<DefaultParameters, 2>::new();
        let mut circuit = builder.build();
        circuit.set_data(all_circuits.block.circuit);
        let wrapped_circuit =
            WrappedCircuit::<DefaultParameters, Groth16WrapperParameters, D>::build(circuit);
        log::info!("build finish");

        let wrapped_proof = wrapped_circuit.prove(&block_proof).unwrap();

        total_timing.filter(Duration::from_millis(100)).print();

        Ok(wrapped_proof)
    }
}

#[test]
#[ignore]
fn test_prove() {
    env_logger::try_init().unwrap_or_default();

    let file = File::open("/tmp/output/0").expect("open file err");
    let prover = Prover::new(file, None);
    let (traces, public_values, _) = prover.gen_traces().unwrap();
    let _ = prover.prove(traces, public_values).unwrap();
}

#[test]
#[ignore]
fn test_prove_with_agg() {
    env_logger::try_init().unwrap_or_default();

    let files = (0..3).map(|i| format!("/tmp/output/{}", i)).collect_vec();
    let prover = ProverWithKernels::new(files, Some(262144));
    prover.prove().unwrap();
}
