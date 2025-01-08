use std::fs::File;
use std::io::BufReader;
use std::ops::Range;
use std::time::Duration;

use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;
use plonky2x::backend::circuit::Groth16WrapperParameters;
use plonky2x::backend::wrapper::wrap::WrappedCircuit;
use plonky2x::frontend::builder::CircuitBuilder as WrapperBuilder;
use plonky2x::prelude::DefaultParameters;

use zkm_prover::all_stark::AllStark;
use zkm_prover::config::StarkConfig;
use zkm_prover::cpu::kernel::assembler::segment_kernel;
use zkm_prover::fixed_recursive_verifier::AllRecursiveCircuits;
use zkm_prover::generation::state::{AssumptionReceipts, Receipt};

const DEGREE_BITS_RANGE: [Range<usize>; 8] = [10..21, 12..22, 12..21, 8..21, 12..21, 8..21, 6..21, 13..23];

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

pub fn prove_segments(
    seg_dir: &str,
    basedir: &str,
    block: &str,
    file: &str,
    seg_file_number: usize,
    seg_start_id: usize,
    assumptions: AssumptionReceipts<F, C, D>,
) -> anyhow::Result<Receipt<F, C, D>> {
    type InnerParameters = DefaultParameters;
    type OuterParameters = Groth16WrapperParameters;

    let total_timing = TimingTree::new("prove total time", log::Level::Info);
    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    // Preprocess all circuits.
    let all_circuits =
        AllRecursiveCircuits::<F, C, D>::new(&all_stark, &DEGREE_BITS_RANGE, &config);

    let seg_file = format!("{}/{}", seg_dir, seg_start_id);
    log::info!("Process segment {}", seg_file);
    let seg_reader = BufReader::new(File::open(seg_file)?);
    let input_first = segment_kernel(basedir, block, file, seg_reader);
    let mut timing = TimingTree::new("prove root first", log::Level::Info);
    let mut agg_receipt = all_circuits.prove_root_with_assumption(
        &all_stark,
        &input_first,
        &config,
        &mut timing,
        assumptions.clone(),
    )?;

    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(agg_receipt.clone())?;

    let mut base_seg = seg_start_id + 1;
    let mut seg_num = seg_file_number - 1;
    let mut is_agg = false;

    if seg_file_number % 2 == 0 {
        let seg_file = format!("{}/{}", seg_dir, seg_start_id + 1);
        log::info!("Process segment {}", seg_file);
        let seg_reader = BufReader::new(File::open(seg_file)?);
        let input = segment_kernel(basedir, block, file, seg_reader);
        timing = TimingTree::new("prove root second", log::Level::Info);
        let receipt = all_circuits.prove_root_with_assumption(
            &all_stark,
            &input,
            &config,
            &mut timing,
            assumptions.clone(),
        )?;
        timing.filter(Duration::from_millis(100)).print();

        all_circuits.verify_root(receipt.clone())?;

        timing = TimingTree::new("prove aggression", log::Level::Info);
        // We can duplicate the proofs here because the state hasn't mutated.
        agg_receipt = all_circuits.prove_aggregation(false, &agg_receipt, false, &receipt)?;
        timing.filter(Duration::from_millis(100)).print();
        all_circuits.verify_aggregation(&agg_receipt)?;

        is_agg = true;
        base_seg = seg_start_id + 2;
        seg_num -= 1;
    }

    for i in 0..seg_num / 2 {
        let seg_file = format!("{}/{}", seg_dir, base_seg + (i << 1));
        log::info!("Process segment {}", seg_file);
        let seg_reader = BufReader::new(File::open(&seg_file)?);
        let input_first = segment_kernel(basedir, block, file, seg_reader);
        let mut timing = TimingTree::new("prove root first", log::Level::Info);
        let root_receipt_first = all_circuits.prove_root_with_assumption(
            &all_stark,
            &input_first,
            &config,
            &mut timing,
            assumptions.clone(),
        )?;

        timing.filter(Duration::from_millis(100)).print();
        all_circuits.verify_root(root_receipt_first.clone())?;

        let seg_file = format!("{}/{}", seg_dir, base_seg + (i << 1) + 1);
        log::info!("Process segment {}", seg_file);
        let seg_reader = BufReader::new(File::open(&seg_file)?);
        let input = segment_kernel(basedir, block, file, seg_reader);
        let mut timing = TimingTree::new("prove root second", log::Level::Info);
        let root_receipt = all_circuits.prove_root_with_assumption(
            &all_stark,
            &input,
            &config,
            &mut timing,
            assumptions.clone(),
        )?;
        timing.filter(Duration::from_millis(100)).print();

        all_circuits.verify_root(root_receipt.clone())?;

        timing = TimingTree::new("prove aggression", log::Level::Info);
        // We can duplicate the proofs here because the state hasn't mutated.
        let new_agg_receipt =
            all_circuits.prove_aggregation(false, &root_receipt_first, false, &root_receipt)?;
        timing.filter(Duration::from_millis(100)).print();
        all_circuits.verify_aggregation(&new_agg_receipt)?;

        timing = TimingTree::new("prove nested aggression", log::Level::Info);

        // We can duplicate the proofs here because the state hasn't mutated.
        agg_receipt =
            all_circuits.prove_aggregation(is_agg, &agg_receipt, true, &new_agg_receipt)?;
        is_agg = true;
        timing.filter(Duration::from_millis(100)).print();

        all_circuits.verify_aggregation(&agg_receipt)?;
    }

    log::info!(
        "proof size: {:?}",
        serde_json::to_string(&agg_receipt.proof().proof)
            .unwrap()
            .len()
    );
    let final_receipt = if seg_file_number > 1 {
        let block_receipt = all_circuits.prove_block(None, &agg_receipt)?;
        all_circuits.verify_block(&block_receipt)?;
        let build_path = "../verifier/data".to_string();
        let path = format!("{}/test_circuit/", build_path);
        let builder = WrapperBuilder::<DefaultParameters, 2>::new();
        let mut circuit = builder.build();
        circuit.set_data(all_circuits.block.circuit);
        let mut bit_size = vec![32usize; 16];
        bit_size.extend(vec![8; 32]);
        bit_size.extend(vec![64; 68]);
        let wrapped_circuit = WrappedCircuit::<InnerParameters, OuterParameters, D>::build(
            circuit,
            Some((vec![], bit_size)),
        );
        let wrapped_proof = wrapped_circuit.prove(&block_receipt.proof()).unwrap();
        wrapped_proof.save(path).unwrap();

        block_receipt
    } else {
        agg_receipt
    };

    log::info!("build finish");

    total_timing.filter(Duration::from_millis(100)).print();
    Ok(final_receipt)
}
