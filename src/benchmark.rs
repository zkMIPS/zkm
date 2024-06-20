use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::time::Duration;

use anyhow::Result;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;

use crate::all_stark::{AllStark, NUM_TABLES};
use crate::config::StarkConfig;
use crate::cpu::kernel::assembler::Kernel;
use crate::cpu::kernel::elf::Program;
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

#[test]
fn test_sha2() {
    env_logger::try_init().unwrap_or_default();

    let file = File::open("/tmp/output/0").expect("open file err");
    let prover = Prover::new(file, None);
    let (traces, public_values, _) = prover.gen_traces().unwrap();
    let _ = prover.prove(traces, public_values).unwrap();
}
