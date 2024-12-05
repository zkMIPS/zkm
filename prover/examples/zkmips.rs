#![feature(allocator_api)]

use serde::{Deserialize, Serialize};
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::ops::Range;
use std::time::Duration;

use log::LevelFilter;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;
use plonky2x::backend::circuit::Groth16WrapperParameters;
use plonky2x::backend::wrapper::wrap::WrappedCircuit;
use plonky2x::frontend::builder::CircuitBuilder as WrapperBuilder;
use plonky2x::prelude::DefaultParameters;
use zkm_emulator::utils::{
    get_block_path, load_elf_with_patch, split_prog_into_segs, SEGMENT_STEPS,
};
use zkm_prover::all_stark::AllStark;
use zkm_prover::config::StarkConfig;
use zkm_prover::cpu::kernel::assembler::segment_kernel;
use zkm_prover::fixed_recursive_verifier::AllRecursiveCircuits;
use zkm_prover::generation::state::{AssumptionReceipt, AssumptionReceipts, Receipt};
use zkm_prover::proof;
use zkm_prover::proof::PublicValues;
#[cfg(not(feature = "gpu"))]
use zkm_prover::prover::prove;
use zkm_prover::verifier::verify_proof;

#[cfg(feature = "gpu")]
use plonky2::{
    field::extension::Extendable,
    field::fft::fft_root_table,
    field::types::Field,
    fri::oracle::{create_task, CudaInnerContext, MyAllocator},
    plonk::config::Hasher,
};
#[cfg(feature = "gpu")]
use rustacuda::{memory::DeviceBuffer, prelude::*};
#[cfg(feature = "gpu")]
use std::{collections::BTreeMap, sync::Arc};
#[cfg(feature = "gpu")]
use zkm_prover::prover::prove_gpu;

const DEGREE_BITS_RANGE: [Range<usize>; 6] = [10..21, 12..22, 12..21, 8..21, 6..21, 13..23];

fn split_segments() {
    // 1. split ELF into segs
    let basedir = env::var("BASEDIR").unwrap_or("/tmp/cannon".to_string());
    let elf_path = env::var("ELF_PATH").expect("ELF file is missing");
    let block_no = env::var("BLOCK_NO").unwrap_or("".to_string());
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or(format!("{SEGMENT_STEPS}"));
    let seg_size = seg_size.parse::<_>().unwrap_or(SEGMENT_STEPS);
    let args = env::var("ARGS").unwrap_or("".to_string());
    // assume the first arg is the hash output(which is a public input), and the others are the input.
    let args: Vec<&str> = args.split_whitespace().collect();
    let mut state = load_elf_with_patch(&elf_path, vec![]);

    if !args.is_empty() {
        let public_input: Vec<u8> = args[0].as_bytes().to_vec();
        log::info!("public input value {:X?}", public_input);
        state.add_input_stream(&public_input);
    }

    if args.len() > 1 {
        for (i, arg) in args.iter().enumerate().skip(1) {
            let private_input = arg.as_bytes().to_vec();
            log::info!("private input value {}: {:X?}", i, private_input);
            state.add_input_stream(&private_input);
        }
    }

    let block_path = get_block_path(&basedir, &block_no, "");
    if !block_no.is_empty() {
        state.load_input(&block_path);
    }
    let _ = split_prog_into_segs(state, &seg_path, &block_path, seg_size);
}

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

fn prove_single_seg_common(seg_file: &str, basedir: &str, block: &str, file: &str) {
    #[cfg(feature = "gpu")]
    prove_single_seg_gpu(seg_file, basedir, block, file);

    #[cfg(not(feature = "gpu"))]
    prove_single_seg_cpu(seg_file, basedir, block, file);
}

#[cfg(not(feature = "gpu"))]
fn prove_single_seg_cpu(seg_file: &str, basedir: &str, block: &str, file: &str) {
    let seg_reader = BufReader::new(File::open(seg_file).unwrap());
    let kernel = segment_kernel(basedir, block, file, seg_reader);

    let allstark: AllStark<F, D> = AllStark::default();
    let config = StarkConfig::standard_fast_config();
    let mut timing = TimingTree::new("prove", log::Level::Info);
    let allproof: proof::AllProof<GoldilocksField, C, D> =
        prove(&allstark, &kernel, &config, &mut timing).unwrap();
    let mut count_bytes = 0;
    for (row, proof) in allproof.stark_proofs.clone().iter().enumerate() {
        let proof_str = serde_json::to_string(&proof.proof).unwrap();
        log::info!("row:{} proof bytes:{}", row, proof_str.len());
        count_bytes += proof_str.len();
    }
    timing.filter(Duration::from_millis(100)).print();
    log::info!("total proof bytes:{}KB", count_bytes / 1024);
    verify_proof(&allstark, allproof, &config).unwrap();
    log::info!("Prove done");
}

#[cfg(feature = "gpu")]
fn create_gpu_context(
    config: &StarkConfig,
) -> plonky2::fri::oracle::CudaInvContext<GoldilocksField, PoseidonGoldilocksConfig, 2> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    rustacuda::init(CudaFlags::empty()).unwrap();
    let device_index = 0;
    let device = Device::get_device(device_index).unwrap();
    let _ctx = Context::create_and_push(ContextFlags::MAP_HOST | ContextFlags::SCHED_AUTO, device)
        .unwrap();
    let stream = Stream::new(StreamFlags::NON_BLOCKING, None).unwrap();
    let stream2 = Stream::new(StreamFlags::NON_BLOCKING, None).unwrap();

    let max_lg_n = 22;
    let max_values_flatten_len = (1 << max_lg_n) * 32;

    let rate_bits = config.fri_config.rate_bits;
    let blinding = false;
    const SALT_SIZE: usize = 4;
    let cap_height = config.fri_config.cap_height;
    let salt_size = if blinding { SALT_SIZE } else { 0 };

    let fft_root_table_max = fft_root_table(1 << (max_lg_n + rate_bits)).concat();
    let root_table_device = { DeviceBuffer::from_slice(&fft_root_table_max).unwrap() };

    let fft_root_table_ext =
        fft_root_table::<<F as Extendable<{ D }>>::Extension>(1 << (24)).concat();
    let root_table_ext_device = { DeviceBuffer::from_slice(&fft_root_table_ext).unwrap() };

    let shift_powers = F::coset_shift()
        .powers()
        .take(1 << (max_lg_n))
        .collect::<Vec<_>>();
    let shift_powers_device = { DeviceBuffer::from_slice(&shift_powers).unwrap() };

    let shift_powers_ext = <<F as Extendable<{ D }>>::Extension>::coset_shift()
        .powers()
        .take(1 << (22))
        .collect::<Vec<_>>();
    let shift_powers_ext_device = { DeviceBuffer::from_slice(&shift_powers_ext).unwrap() };

    let max_values_num_per_poly = 1 << max_lg_n;
    // let max_values_flatten_len = 132644864;
    let max_ext_values_flatten_len =
        (max_values_flatten_len + salt_size * max_values_num_per_poly) * (1 << rate_bits);
    let mut ext_values_flatten: Vec<F> = Vec::with_capacity(max_ext_values_flatten_len);
    unsafe {
        ext_values_flatten.set_len(max_ext_values_flatten_len);
    }

    let mut values_flatten: Vec<F, MyAllocator> =
        Vec::with_capacity_in(max_values_flatten_len, MyAllocator {});
    unsafe {
        values_flatten.set_len(max_values_flatten_len);
    }

    let len_cap = 1 << cap_height;
    let num_digests = 2 * (max_values_num_per_poly * (1 << rate_bits) - len_cap);
    let num_digests_and_caps = num_digests + len_cap;
    let mut digests_and_caps_buf: Vec<<<C as GenericConfig<D>>::Hasher as Hasher<F>>::Hash> =
        Vec::with_capacity(num_digests_and_caps);
    unsafe {
        digests_and_caps_buf.set_len(num_digests_and_caps);
    }

    let pad_extvalues_len = max_ext_values_flatten_len;
    let cache_mem_device = {
        unsafe {
            DeviceBuffer::<F>::uninitialized(
                // values_flatten_len +
                pad_extvalues_len + max_ext_values_flatten_len + digests_and_caps_buf.len() * 4,
            )
        }
        .unwrap()
    };

    let mut ctx = plonky2::fri::oracle::CudaInvContext {
        inner: CudaInnerContext { stream, stream2 },
        ext_values_flatten: Arc::new(ext_values_flatten),
        values_flatten: Arc::new(values_flatten),
        digests_and_caps_buf: Arc::new(digests_and_caps_buf),
        cache_mem_device,
        root_table_device,
        shift_powers_device,
        // cache_mem_ext_device,
        root_table_ext_device,
        shift_powers_ext_device,
        tasks: BTreeMap::new(),
        ctx: _ctx,
    };

    let use_dynamic_alloc = std::env::var("USE_DYNAMIC_ALLOC").unwrap_or("0".to_string()) == "1";

    if !use_dynamic_alloc {
        for i in 0..18 {
            create_task(
                &mut ctx,
                i,
                max_lg_n,
                max_values_flatten_len / (1 << max_lg_n),
                0,
                2,
                4,
            );
        }
    }

    ctx
}

#[cfg(feature = "gpu")]
fn prove_single_seg_gpu(seg_file: &str, basedir: &str, block: &str, file: &str) {
    let seg_reader = BufReader::new(File::open(seg_file).unwrap());
    let kernel = segment_kernel(&basedir, &block, &file, seg_reader);

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let allstark: AllStark<F, D> = AllStark::default();
    let config = StarkConfig::standard_fast_config();

    // let mut ctx: plonky2::fri::oracle::CudaInvContext<GoldilocksField, C, D>;
    let mut ctx = create_gpu_context(&config);
    let mut timing = TimingTree::new("prove", log::Level::Info);
    let allproof: proof::AllProof<GoldilocksField, C, D> =
        prove_gpu(&allstark, &kernel, &config, &mut timing, &mut ctx).unwrap();

    let mut count_bytes = 0;
    for (row, proof) in allproof.stark_proofs.clone().iter().enumerate() {
        let proof_str = serde_json::to_string(&proof.proof).unwrap();
        log::info!("row:{} proof bytes:{}", row, proof_str.len());
        count_bytes += proof_str.len();
    }
    // timing.filter(Duration::from_millis(100)).print();
    timing.print();

    log::info!("total proof bytes:{}KB", count_bytes / 1024);
    verify_proof(&allstark, allproof, &config).unwrap();
    log::info!("Prove done");
}

fn prove_multi_seg_common(
    seg_dir: &str,
    basedir: &str,
    block: &str,
    file: &str,
    seg_file_number: usize,
    seg_start_id: usize,
) -> anyhow::Result<()> {
    #[cfg(feature = "gpu")]
    let ret =
        prove_multi_seg_common_gpu(seg_dir, basedir, block, file, seg_file_number, seg_start_id);

    #[cfg(not(feature = "gpu"))]
    let ret =
        prove_multi_seg_common_cpu(seg_dir, basedir, block, file, seg_file_number, seg_start_id);

    ret
}

#[cfg(not(feature = "gpu"))]
fn prove_multi_seg_common_cpu(
    seg_dir: &str,
    basedir: &str,
    block: &str,
    file: &str,
    seg_file_number: usize,
    seg_start_id: usize,
) -> anyhow::Result<()> {
    type InnerParameters = DefaultParameters;
    type OuterParameters = Groth16WrapperParameters;

    if seg_file_number < 2 {
        panic!("seg file number must >= 2\n");
    }

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
    let (mut agg_proof, mut updated_agg_public_values) =
        all_circuits.prove_root(&all_stark, &input_first, &config, &mut timing)?;

    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(agg_proof.clone())?;

    let mut base_seg = seg_start_id + 1;
    let mut seg_num = seg_file_number - 1;
    let mut is_agg = false;

    if seg_file_number % 2 == 0 {
        let seg_file = format!("{}/{}", seg_dir, seg_start_id + 1);
        log::info!("Process segment {}", seg_file);
        let seg_reader = BufReader::new(File::open(seg_file)?);
        let input = segment_kernel(basedir, block, file, seg_reader);
        timing = TimingTree::new("prove root second", log::Level::Info);
        let (root_proof, public_values) =
            all_circuits.prove_root(&all_stark, &input, &config, &mut timing)?;
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
        base_seg = seg_start_id + 2;
        seg_num -= 1;
    }

    for i in 0..seg_num / 2 {
        let seg_file = format!("{}/{}", seg_dir, base_seg + (i << 1));
        log::info!("Process segment {}", seg_file);
        let seg_reader = BufReader::new(File::open(&seg_file)?);
        let input_first = segment_kernel(basedir, block, file, seg_reader);
        let mut timing = TimingTree::new("prove root first", log::Level::Info);
        let (root_proof_first, first_public_values) =
            all_circuits.prove_root(&all_stark, &input_first, &config, &mut timing)?;

        timing.filter(Duration::from_millis(100)).print();
        all_circuits.verify_root(root_proof_first.clone())?;

        let seg_file = format!("{}/{}", seg_dir, base_seg + (i << 1) + 1);
        log::info!("Process segment {}", seg_file);
        let seg_reader = BufReader::new(File::open(&seg_file)?);
        let input = segment_kernel(basedir, block, file, seg_reader);
        let mut timing = TimingTree::new("prove root second", log::Level::Info);
        let (root_proof, public_values) =
            all_circuits.prove_root(&all_stark, &input, &config, &mut timing)?;
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

    log::info!(
        "proof size: {:?}",
        serde_json::to_string(&block_proof.proof).unwrap().len()
    );
    let result = all_circuits.verify_block(&block_proof);

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
    log::info!("build finish");

    let wrapped_proof = wrapped_circuit.prove(&block_proof).unwrap();
    wrapped_proof.save(path).unwrap();

    total_timing.filter(Duration::from_millis(100)).print();
    result
}

#[cfg(feature = "gpu")]
fn prove_multi_seg_common_gpu(
    seg_dir: &str,
    basedir: &str,
    block: &str,
    file: &str,
    seg_file_number: usize,
    seg_start_id: usize,
) -> anyhow::Result<()> {
    type InnerParameters = DefaultParameters;
    type OuterParameters = Groth16WrapperParameters;

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    if seg_file_number < 2 {
        panic!("seg file number must >= 2\n");
    }

    let total_timing = TimingTree::new("prove total time", log::Level::Info);
    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    // Preprocess all circuits.
    let all_circuits =
        AllRecursiveCircuits::<F, C, D>::new(&all_stark, &DEGREE_BITS_RANGE, &config);

    let mut ctx = create_gpu_context(&config);

    let seg_file = format!("{}/{}", seg_dir, seg_start_id);
    log::info!("Process segment {}", seg_file);
    let seg_reader = BufReader::new(File::open(seg_file)?);
    let input_first = segment_kernel(basedir, block, file, seg_reader);
    let mut timing = TimingTree::new("prove root first", log::Level::Info);
    let (mut agg_proof, mut updated_agg_public_values) =
        all_circuits.prove_root_gpu(&all_stark, &input_first, &config, &mut timing, &mut ctx)?;

    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(agg_proof.clone())?;

    let mut base_seg = seg_start_id + 1;
    let mut seg_num = seg_file_number - 1;
    let mut is_agg = false;

    if seg_file_number % 2 == 0 {
        let seg_file = format!("{}/{}", seg_dir, seg_start_id + 1);
        log::info!("Process segment {}", seg_file);
        let seg_reader = BufReader::new(File::open(seg_file)?);
        let input = segment_kernel(basedir, block, file, seg_reader);
        timing = TimingTree::new("prove root second", log::Level::Info);
        let (root_proof, public_values) =
            all_circuits.prove_root_gpu(&all_stark, &input, &config, &mut timing, &mut ctx)?;
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
        base_seg = seg_start_id + 2;
        seg_num -= 1;
    }

    for i in 0..seg_num / 2 {
        let seg_file = format!("{}/{}", seg_dir, base_seg + (i << 1));
        log::info!("Process segment {}", seg_file);
        let seg_reader = BufReader::new(File::open(&seg_file)?);
        let input_first = segment_kernel(basedir, block, file, seg_reader);
        let mut timing = TimingTree::new("prove root first", log::Level::Info);
        let (root_proof_first, first_public_values) = all_circuits.prove_root_gpu(
            &all_stark,
            &input_first,
            &config,
            &mut timing,
            &mut ctx,
        )?;

        timing.filter(Duration::from_millis(100)).print();
        all_circuits.verify_root(root_proof_first.clone())?;

        let seg_file = format!("{}/{}", seg_dir, base_seg + (i << 1) + 1);
        log::info!("Process segment {}", seg_file);
        let seg_reader = BufReader::new(File::open(&seg_file)?);
        let input = segment_kernel(basedir, block, file, seg_reader);
        let mut timing = TimingTree::new("prove root second", log::Level::Info);
        let (root_proof, public_values) =
            all_circuits.prove_root_gpu(&all_stark, &input, &config, &mut timing, &mut ctx)?;
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

    log::info!(
        "proof size: {:?}",
        serde_json::to_string(&block_proof.proof).unwrap().len()
    );
    let result = all_circuits.verify_block(&block_proof);

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
    log::info!("build finish");

    let wrapped_proof = wrapped_circuit.prove(&block_proof).unwrap();
    wrapped_proof.save(path).unwrap();

    total_timing.filter(Duration::from_millis(100)).print();
    result
}

fn prove_sha2_rust() {
    // 1. split ELF into segs
    let elf_path = env::var("ELF_PATH").expect("ELF file is missing");
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or("65536".to_string());
    let seg_size = seg_size.parse::<_>().unwrap_or(0);

    let mut state = load_elf_with_patch(&elf_path, vec![]);
    // load input
    let args = env::var("ARGS").unwrap_or("data-to-hash".to_string());
    // assume the first arg is the hash output(which is a public input), and the second is the input.
    let args: Vec<&str> = args.split_whitespace().collect();
    assert_eq!(args.len(), 2);

    let public_input: Vec<u8> = hex::decode(args[0]).unwrap();
    state.add_input_stream(&public_input);
    log::info!("expected public value in hex: {:X?}", args[0]);
    log::info!("expected public value: {:X?}", public_input);

    let private_input = args[1].as_bytes().to_vec();
    log::info!("private input value: {:X?}", private_input);
    state.add_input_stream(&private_input);

    let (_total_steps, seg_num, mut state) = split_prog_into_segs(state, &seg_path, "", seg_size);

    let value = state.read_public_values::<[u8; 32]>();
    log::info!("public value: {:X?}", value);
    log::info!("public value: {} in hex", hex::encode(value));

    if seg_num == 1 {
        let seg_file = format!("{seg_path}/{}", 0);
        prove_single_seg_common(&seg_file, "", "", "")
    } else {
        prove_multi_seg_common(&seg_path, "", "", "", seg_num, 0).unwrap()
    }
}

fn u32_array_to_u8_vec(u32_array: &[u32; 8]) -> Vec<u8> {
    let mut u8_vec = Vec::with_capacity(u32_array.len() * 4);
    for &item in u32_array {
        u8_vec.extend_from_slice(&item.to_le_bytes());
    }
    u8_vec
}

#[cfg(not(feature = "gpu"))]
fn prove_sha_5_precompile(
    elf_path: &str,
    seg_path: &str,
) -> Receipt<<C as GenericConfig<D>>::F, C, D> {
    let mut state = load_elf_with_patch(elf_path, vec![]);
    let n: u32 = 5;
    let public_input: [u8; 32] = [
        37, 148, 182, 169, 46, 191, 177, 195, 49, 45, 235, 125, 1, 192, 21, 251, 149, 233, 251,
        233, 189, 123, 198, 181, 39, 175, 7, 129, 62, 199, 185, 16,
    ];
    state.add_input_stream(&public_input.to_vec());
    state.add_input_stream(&n.to_le_bytes().to_vec());

    let (_total_steps, seg_num, mut state) = split_prog_into_segs(state, seg_path, "", 0);

    let value = state.read_public_values::<[u8; 32]>();
    log::info!("public value: {:?}", value);

    assert!(seg_num == 1);

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    // Preprocess all circuits.
    let all_circuits =
        AllRecursiveCircuits::<F, C, D>::new(&all_stark, &DEGREE_BITS_RANGE, &config);

    let seg_file: String = format!("{}/{}", seg_path, 0);
    log::info!("Process segment {}", seg_file);
    let seg_reader = BufReader::new(File::open(seg_file).unwrap());
    let input_first = segment_kernel("", "", "", seg_reader);
    let mut timing = TimingTree::new("prove root first", log::Level::Info);
    let (agg_proof, updated_agg_public_values) = all_circuits
        .prove_root(&all_stark, &input_first, &config, &mut timing)
        .unwrap();

    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(agg_proof.clone()).unwrap();

    Receipt::<F, C, D> {
        proof: agg_proof,
        root_before: u32_array_to_u8_vec(&updated_agg_public_values.roots_before.root),
        userdata: updated_agg_public_values.userdata.clone(),
    }
}

#[cfg(feature = "gpu")]
fn prove_sha_5_precompile_gpu(
    elf_path: &str,
    seg_path: &str,
    ctx: &mut plonky2::fri::oracle::CudaInvContext<F, C, D>,
) -> Receipt<<C as GenericConfig<D>>::F, C, D> {
    let mut state = load_elf_with_patch(elf_path, vec![]);
    let n: u32 = 5;
    let public_input: [u8; 32] = [
        37, 148, 182, 169, 46, 191, 177, 195, 49, 45, 235, 125, 1, 192, 21, 251, 149, 233, 251,
        233, 189, 123, 198, 181, 39, 175, 7, 129, 62, 199, 185, 16,
    ];
    state.add_input_stream(&public_input.to_vec());
    state.add_input_stream(&n.to_le_bytes().to_vec());

    let (_total_steps, seg_num, mut state) = split_prog_into_segs(state, seg_path, "", 0);

    let value = state.read_public_values::<[u8; 32]>();
    log::info!("public value: {:?}", value);

    assert!(seg_num == 1);

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    // Preprocess all circuits.
    let all_circuits =
        AllRecursiveCircuits::<F, C, D>::new(&all_stark, &DEGREE_BITS_RANGE, &config);

    let seg_file: String = format!("{}/{}", seg_path, 0);
    log::info!("Process segment {}", seg_file);
    let seg_reader = BufReader::new(File::open(seg_file).unwrap());
    let input_first = segment_kernel("", "", "", seg_reader);
    let mut timing = TimingTree::new("prove root with gpu first", log::Level::Info);
    let (agg_proof, updated_agg_public_values) = all_circuits
        .prove_root_gpu(&all_stark, &input_first, &config, &mut timing, ctx)
        .unwrap();

    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(agg_proof.clone()).unwrap();

    Receipt::<F, C, D> {
        proof: agg_proof,
        root_before: u32_array_to_u8_vec(&updated_agg_public_values.roots_before.root),
        userdata: updated_agg_public_values.userdata.clone(),
    }
}

#[cfg(not(feature = "gpu"))]
fn prove_sha2_precompile() {
    // 1. split ELF into segs
    let elf_path = env::var("ELF_PATH").expect("ELF file is missing");
    let precompile_path = env::var("PRECOMPILE_PATH").expect("PRECOMPILE ELF file is missing");
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");
    let mut receipts: AssumptionReceipts<F, C, D> = vec![];
    let receipt = prove_sha_5_precompile(&precompile_path, &seg_path);

    log::info!(
        "elf_id: {:?}, data: {:?}",
        receipt.root_before,
        receipt.userdata
    );

    let image_id = receipt.root_before.clone();
    receipts.push(receipt.into());

    let mut state = load_elf_with_patch(&elf_path, vec![]);

    let public_input: [u8; 32] = [
        91, 15, 50, 181, 63, 91, 186, 46, 9, 26, 167, 190, 200, 232, 40, 101, 149, 181, 253, 89,
        24, 150, 142, 102, 14, 67, 78, 221, 18, 205, 95, 28,
    ];
    state.add_input_stream(&public_input.to_vec());
    log::info!("expected public value: {:?}", public_input);

    let private_input: [u8; 32] = [
        37, 148, 182, 169, 46, 191, 177, 195, 49, 45, 235, 125, 1, 192, 21, 251, 149, 233, 251,
        233, 189, 123, 198, 181, 39, 175, 7, 129, 62, 199, 185, 16,
    ];
    log::info!("private input value: {:?}", private_input);
    state.add_input_stream(&private_input.to_vec());

    state.add_input_stream(&image_id);

    let (_total_steps, _seg_num, mut state) = split_prog_into_segs(state, &seg_path, "", 0);

    let value = state.read_public_values::<[u8; 32]>();
    log::info!("public value: {:X?}", value);
    log::info!("public value: {} in hex", hex::encode(value));

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    // Preprocess all circuits.
    let all_circuits =
        AllRecursiveCircuits::<F, C, D>::new(&all_stark, &DEGREE_BITS_RANGE, &config);

    let seg_file: String = format!("{}/{}", seg_path, 0);
    log::info!("Process segment {}", seg_file);
    let seg_reader = BufReader::new(File::open(seg_file).unwrap());
    let kernel = segment_kernel("", "", "", seg_reader);

    let mut timing = TimingTree::new("prove", log::Level::Info);
    let (agg_proof, _updated_agg_public_values, receipts_used) = all_circuits
        .prove_root_with_assumption(&all_stark, &kernel, &config, &mut timing, receipts)
        .unwrap();

    log::info!("Process assumptions");
    timing = TimingTree::new("prove aggression", log::Level::Info);

    for assumption in receipts_used.borrow_mut().iter_mut() {
        let receipt = assumption.1.clone();
        match receipt {
            AssumptionReceipt::Proven(receipt) => {
                all_circuits.verify_root(receipt.proof.clone()).unwrap();
            }
            AssumptionReceipt::Unresolved(assumpt) => {
                log::error!("unresolved assumption: {:X?}", assumpt);
            }
        }
    }
    log::info!("verify");
    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(agg_proof.clone()).unwrap();
}

#[cfg(feature = "gpu")]
fn prove_sha2_precompile_gpu() {
    log::info!("prove sha2 precompile with gpu");

    let config = StarkConfig::standard_fast_config();
    let mut ctx = create_gpu_context(&config);

    // 1. split ELF into segs
    let elf_path = env::var("ELF_PATH").expect("ELF file is missing");
    let precompile_path = env::var("PRECOMPILE_PATH").expect("PRECOMPILE ELF file is missing");
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");
    let mut receipts: AssumptionReceipts<F, C, D> = vec![];
    let receipt = prove_sha_5_precompile_gpu(&precompile_path, &seg_path, &mut ctx);

    log::info!(
        "elf_id: {:?}, data: {:?}",
        receipt.root_before,
        receipt.userdata
    );

    let image_id = receipt.root_before.clone();
    receipts.push(receipt.into());

    let mut state = load_elf_with_patch(&elf_path, vec![]);

    let public_input: [u8; 32] = [
        91, 15, 50, 181, 63, 91, 186, 46, 9, 26, 167, 190, 200, 232, 40, 101, 149, 181, 253, 89,
        24, 150, 142, 102, 14, 67, 78, 221, 18, 205, 95, 28,
    ];
    state.add_input_stream(&public_input.to_vec());
    log::info!("expected public value: {:?}", public_input);

    let private_input: [u8; 32] = [
        37, 148, 182, 169, 46, 191, 177, 195, 49, 45, 235, 125, 1, 192, 21, 251, 149, 233, 251,
        233, 189, 123, 198, 181, 39, 175, 7, 129, 62, 199, 185, 16,
    ];
    log::info!("private input value: {:?}", private_input);
    state.add_input_stream(&private_input.to_vec());

    state.add_input_stream(&image_id);

    let (_total_steps, _seg_num, mut state) = split_prog_into_segs(state, &seg_path, "", 0);

    let value = state.read_public_values::<[u8; 32]>();
    log::info!("public value: {:X?}", value);
    log::info!("public value: {} in hex", hex::encode(value));

    let all_stark = AllStark::<F, D>::default();
    // Preprocess all circuits.
    let all_circuits =
        AllRecursiveCircuits::<F, C, D>::new(&all_stark, &DEGREE_BITS_RANGE, &config);

    let seg_file: String = format!("{}/{}", seg_path, 0);
    log::info!("Process segment {}", seg_file);
    let seg_reader = BufReader::new(File::open(seg_file).unwrap());
    let kernel = segment_kernel("", "", "", seg_reader);

    let mut timing = TimingTree::new("prove with gpu", log::Level::Info);
    let (agg_proof, _updated_agg_public_values, receipts_used) = all_circuits
        .prove_root_with_assumption_gpu(
            &all_stark,
            &kernel,
            &config,
            &mut timing,
            receipts,
            &mut ctx,
        )
        .unwrap();

    log::info!("Process assumptions");
    timing = TimingTree::new("prove aggression", log::Level::Info);

    for assumption in receipts_used.borrow_mut().iter_mut() {
        let receipt = assumption.1.clone();
        match receipt {
            AssumptionReceipt::Proven(receipt) => {
                all_circuits.verify_root(receipt.proof.clone()).unwrap();
            }
            AssumptionReceipt::Unresolved(assumpt) => {
                log::error!("unresolved assumption: {:X?}", assumpt);
            }
        }
    }
    log::info!("verify");
    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(agg_proof.clone()).unwrap();
}

fn prove_sha2_go() {
    // 1. split ELF into segs
    let elf_path = env::var("ELF_PATH").expect("ELF file is missing");
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or("0".to_string());
    let seg_size = seg_size.parse::<_>().unwrap_or(0);

    let mut state = load_elf_with_patch(&elf_path, vec![]);
    // load input
    let args = env::var("ARGS").unwrap_or("data-to-hash".to_string());
    // assume the first arg is the hash output(which is a public input), and the second is the input.
    let args: Vec<&str> = args.split_whitespace().collect();
    assert_eq!(args.len(), 2);

    let mut data = Data::new();

    // Fill in the input data
    data.input10 = hex::decode(args[0]).unwrap();
    data.input12 = args[1].to_string();

    state.add_input_stream(&data);
    log::info!(
        "enum {} {} {}",
        DataId::TYPE1 as u8,
        DataId::TYPE2 as u8,
        DataId::TYPE3 as u8
    );
    log::info!("public input: {:X?}", data);

    let (_total_steps, seg_num, mut state) = split_prog_into_segs(state, &seg_path, "", seg_size);

    let value = state.read_public_values::<Data>();
    log::info!("public value: {:X?}", value);

    if seg_num == 1 {
        let seg_file = format!("{seg_path}/{}", 0);
        prove_single_seg_common(&seg_file, "", "", "")
    } else {
        prove_multi_seg_common(&seg_path, "", "", "", seg_num, 0).unwrap()
    }
}

fn prove_revm() {
    // 1. split ELF into segs
    let elf_path = env::var("ELF_PATH").expect("ELF file is missing");
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");
    let json_path = env::var("JSON_PATH").expect("JSON file is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or("0".to_string());
    let seg_size = seg_size.parse::<_>().unwrap_or(0);
    let mut f = File::open(json_path).unwrap();
    let mut data = vec![];
    f.read_to_end(&mut data).unwrap();

    let mut state = load_elf_with_patch(&elf_path, vec![]);
    // load input
    state.input_stream.push(data);

    let (_total_steps, seg_num, mut _state) = split_prog_into_segs(state, &seg_path, "", seg_size);

    if seg_num == 1 {
        let seg_file = format!("{seg_path}/{}", 0);
        prove_single_seg_common(&seg_file, "", "", "")
    } else {
        prove_multi_seg_common(&seg_path, "", "", "", seg_num, 0).unwrap()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum DataId {
    TYPE1,
    TYPE2,
    TYPE3,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Data {
    pub input1: [u8; 10],
    pub input2: u8,
    pub input3: i8,
    pub input4: u16,
    pub input5: i16,
    pub input6: u32,
    pub input7: i32,
    pub input8: u64,
    pub input9: i64,
    pub input10: Vec<u8>,
    pub input11: DataId,
    pub input12: String,
}

impl Default for Data {
    fn default() -> Self {
        Self::new()
    }
}

impl Data {
    pub fn new() -> Self {
        let array = [1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8, 9u8, 10u8];
        Self {
            input1: array,
            input2: 0x11u8,
            input3: -1i8,
            input4: 0x1122u16,
            input5: -1i16,
            input6: 0x112233u32,
            input7: -1i32,
            input8: 0x1122334455u64,
            input9: -1i64,
            input10: array[1..3].to_vec(),
            input11: DataId::TYPE3,
            input12: "hello".to_string(),
        }
    }
}

fn prove_add_example() {
    // 1. split ELF into segs
    let elf_path = env::var("ELF_PATH").expect("ELF file is missing");
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or("0".to_string());
    let seg_size = seg_size.parse::<_>().unwrap_or(0);

    let mut state = load_elf_with_patch(&elf_path, vec![]);

    let data = Data::new();
    state.add_input_stream(&data);
    log::info!(
        "enum {} {} {}",
        DataId::TYPE1 as u8,
        DataId::TYPE2 as u8,
        DataId::TYPE3 as u8
    );
    log::info!("public input: {:X?}", data);

    let (_total_steps, seg_num, mut state) = split_prog_into_segs(state, &seg_path, "", seg_size);

    let value = state.read_public_values::<Data>();
    log::info!("public value: {:X?}", value);

    if seg_num == 1 {
        let seg_file = format!("{seg_path}/{}", 0);
        prove_single_seg_common(&seg_file, "", "", "")
    } else {
        prove_multi_seg_common(&seg_path, "", "", "", seg_num, 0).unwrap()
    }
}

fn prove_host() {
    let host_program = env::var("HOST_PROGRAM").expect("host_program name is missing");
    match host_program.as_str() {
        "sha2_rust" => prove_sha2_rust(),
        "sha2_precompile" => {
            #[cfg(feature = "gpu")]
            prove_sha2_precompile_gpu();

            #[cfg(not(feature = "gpu"))]
            prove_sha2_precompile();
        }
        "sha2_go" => prove_sha2_go(),
        "revm" => prove_revm(),
        "add_example" => prove_add_example(),
        _ => log::error!("Host program {} is not supported!", host_program),
    };
}

fn prove_segments() {
    let basedir = env::var("BASEDIR").unwrap_or("/tmp/cannon".to_string());
    let block = env::var("BLOCK_NO").unwrap_or("".to_string());
    let file = env::var("BLOCK_FILE").unwrap_or(String::from(""));
    let seg_dir = env::var("SEG_FILE_DIR").expect("segment file dir is missing");
    let seg_num = env::var("SEG_NUM").unwrap_or("1".to_string());
    let seg_num = seg_num.parse::<_>().unwrap_or(1usize);
    let seg_start_id = env::var("SEG_START_ID").unwrap_or("0".to_string());
    let seg_start_id = seg_start_id.parse::<_>().unwrap_or(0usize);

    if seg_num == 1 {
        let seg_file = format!("{seg_dir}/{}", seg_start_id);
        prove_single_seg_common(&seg_file, &basedir, &block, &file)
    } else {
        prove_multi_seg_common(&seg_dir, &basedir, &block, &file, seg_num, seg_start_id).unwrap()
    }
}

fn main() {
    //env_logger::try_init().unwrap_or_default();
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Debug);
    builder.try_init().unwrap_or_default();
    let args: Vec<String> = env::args().collect();
    let helper = || {
        log::info!(
            "Help: {} split | prove_segments | prove_host_program",
            args[0]
        );
        std::process::exit(-1);
    };
    if args.len() < 2 {
        helper();
    }
    match args[1].as_str() {
        "split" => split_segments(),
        "prove_segments" => prove_segments(),
        "prove_host_program" => prove_host(),
        _ => helper(),
    };
}
