#![feature(allocator_api)]

use std::collections::BTreeMap;
use elf::{endian::AnyEndian, ElfBytes};
use std::env;
use std::fs::{self, File};
use std::io::BufReader;
use std::ops::Range;
use std::time::Duration;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;
use plonky2x::backend::circuit::Groth16WrapperParameters;
use plonky2x::backend::wrapper::wrap::WrappedCircuit;
use plonky2x::frontend::builder::CircuitBuilder as WrapperBuilder;
use plonky2x::prelude::DefaultParameters;
use zkm::all_stark::AllStark;
use std::sync::Arc;
use log::LevelFilter;
use plonky2::field::fft::fft_root_table;
use plonky2::field::types::Field;
use plonky2::fri::oracle::{CudaInnerContext, MyAllocator};
use plonky2_util::log2_strict;
use zkm::all_stark::{Table};
use zkm::config::StarkConfig;
use zkm::cpu::kernel::assembler::segment_kernel;
use zkm::fixed_recursive_verifier::AllRecursiveCircuits;
use zkm::mips_emulator::state::{InstrumentedState, State, SEGMENT_STEPS};
use zkm::mips_emulator::utils::get_block_path;
use zkm::proof;
use zkm::proof::PublicValues;
use zkm::prover::{prove, prove_gpu};
use zkm::verifier::verify_proof;

const DEGREE_BITS_RANGE: [Range<usize>; 6] = [10..21, 12..22, 12..21, 8..21, 6..21, 13..23];
use rustacuda::memory::{cuda_malloc, DeviceBox};
use rustacuda::prelude::*;
use rustacuda::memory::DeviceBuffer;
use plonky2::plonk::config::{AlgebraicHasher, Hasher};

fn split_elf_into_segs() {
    // 1. split ELF into segs
    let basedir = env::var("BASEDIR").unwrap_or("/tmp/cannon".to_string());
    let elf_path = env::var("ELF_PATH").expect("ELF file is missing");
    let block_no = env::var("BLOCK_NO");
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or(format!("{SEGMENT_STEPS}"));
    let seg_size = seg_size.parse::<_>().unwrap_or(SEGMENT_STEPS);
    let args = env::var("ARGS").unwrap_or("".to_string());
    let args = args.split_whitespace().collect();

    let data = fs::read(elf_path).expect("could not read file");
    let file =
        ElfBytes::<AnyEndian>::minimal_parse(data.as_slice()).expect("opening elf file failed");
    let (mut state, _) = State::load_elf(&file);
    state.patch_elf(&file);
    state.patch_stack(args);

    let block_path = match block_no {
        Ok(no) => {
            let block_path = get_block_path(&basedir, &no, "");
            state.load_input(&block_path);
            block_path
        }
        _ => "".to_string(),
    };

    let mut instrumented_state = InstrumentedState::new(state, block_path);
    std::fs::create_dir_all(&seg_path).unwrap();
    let new_writer = |_: &str| -> Option<std::fs::File> { None };
    instrumented_state.split_segment(false, &seg_path, new_writer);
    let mut segment_step: usize = seg_size;
    let new_writer = |name: &str| -> Option<std::fs::File> { File::create(name).ok() };
    loop {
        if instrumented_state.state.exited {
            break;
        }
        instrumented_state.step();
        segment_step -= 1;
        if segment_step == 0 {
            segment_step = seg_size;
            instrumented_state.split_segment(true, &seg_path, new_writer);
        }
    }
    instrumented_state.split_segment(true, &seg_path, new_writer);
    log::info!("Split done {}", instrumented_state.state.step);

    instrumented_state.dump_memory();
}

fn prove_single_seg() {
    let basedir = env::var("BASEDIR").unwrap_or("/tmp/cannon".to_string());
    let block = env::var("BLOCK_NO").unwrap_or("".to_string());
    let file = env::var("BLOCK_FILE").unwrap_or(String::from(""));
    let seg_file = env::var("SEG_FILE").expect("Segment file is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or(format!("{SEGMENT_STEPS}"));
    let seg_size = seg_size.parse::<_>().unwrap_or(SEGMENT_STEPS);
    let seg_reader = BufReader::new(File::open(seg_file).unwrap());
    let kernel = segment_kernel(&basedir, &block, &file, seg_reader, seg_size);

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let allstark: AllStark<F, D> = AllStark::default();
    let config = StarkConfig::standard_fast_config();
    let mut timing = TimingTree::new("prove", log::Level::Info);

    let mut ctx;
    {
        rustacuda::init(CudaFlags::empty()).unwrap();
        let device_index = 0;
        let device = rustacuda::prelude::Device::get_device(device_index).unwrap();
        let _ctx = Context::create_and_push(ContextFlags::MAP_HOST | ContextFlags::SCHED_AUTO, device).unwrap();
        let stream  = Stream::new(StreamFlags::NON_BLOCKING, None).unwrap();
        let stream2 = Stream::new(StreamFlags::NON_BLOCKING, None).unwrap();

        let blinding = false;
        const SALT_SIZE: usize = 4;
        let rate_bits = config.fri_config.rate_bits;
        let cap_height = config.fri_config.cap_height;
        let salt_size = if blinding { SALT_SIZE } else { 0 };

        let create_task = |lg_n: usize, poly_num: usize| -> plonky2::fri::oracle::CudaInvTaskContext<F, C, D> {
            let values_num_per_poly = 1 << lg_n;
            // let lg_n = log2_strict(values_num_per_poly );

            let values_flatten_len = poly_num*values_num_per_poly;
            let ext_values_flatten_len = (values_flatten_len+salt_size*values_num_per_poly) * (1<<rate_bits);
            let mut ext_values_flatten :Vec<F> = Vec::with_capacity(ext_values_flatten_len);
            unsafe {
                ext_values_flatten.set_len(ext_values_flatten_len);
            }

            let mut values_flatten :Vec<F, MyAllocator> = Vec::with_capacity_in(values_flatten_len, MyAllocator{});
            unsafe {
                values_flatten.set_len(values_flatten_len);
            }

            let len_cap = 1 << cap_height;
            let num_digests = 2 * (values_num_per_poly*(1<<rate_bits) - len_cap);
            let num_digests_and_caps = num_digests + len_cap;
            let mut digests_and_caps_buf :Vec<<<C as GenericConfig<D>>::Hasher as Hasher<F>>::Hash> = Vec::with_capacity(num_digests_and_caps);
            unsafe {
                digests_and_caps_buf.set_len(num_digests_and_caps);
            }

            let pad_extvalues_len = ext_values_flatten.len();
            let cache_mem_device = {
                let cache_mem_device = unsafe {
                    DeviceBuffer::<F>::uninitialized(
                        // values_flatten_len +
                        pad_extvalues_len +
                            ext_values_flatten_len +

                            digests_and_caps_buf.len()*4
                    )
                }.unwrap();

                cache_mem_device
            };

            plonky2::fri::oracle::CudaInvTaskContext {
                lg_n,
                ext_values_flatten: Arc::new(ext_values_flatten.clone()),
                values_flatten: Arc::new(values_flatten.clone()),
                digests_and_caps_buf: Arc::new(digests_and_caps_buf.clone()),
                cache_mem_device: cache_mem_device,
            }
        };

        let mut tasks = std::collections::BTreeMap::new();
        tasks.insert(Table::Arithmetic as u32, create_task(16, 54));
        tasks.insert(Table::Cpu as u32,        create_task(17, 253));
        tasks.insert(Table::Poseidon as u32,   create_task(13, 262));
        tasks.insert(Table::PoseidonSponge as u32, create_task(13, 110));
        tasks.insert(Table::Logic as u32,      create_task(11, 69));
        tasks.insert(Table::Memory as u32,     create_task(20, 13));

        tasks.insert(7,     create_task(16, 22));
        tasks.insert(8,     create_task(17, 20));
        tasks.insert(9,     create_task(13, 4));
        tasks.insert(10,     create_task(13, 40));
        tasks.insert(11,     create_task(11, 2));
        tasks.insert(12,     create_task(20, 6));

        let max_lg_n = tasks.iter().max_by_key(|kv|kv.1.lg_n).unwrap().1.lg_n;
        println!("max_lg_n: {}", max_lg_n);
        // let max_lg_n = 20;
        let fft_root_table_max    = fft_root_table(1<<(max_lg_n + rate_bits)).concat();

        let root_table_device = {
            let root_table_device = DeviceBuffer::from_slice(&fft_root_table_max).unwrap();
            root_table_device
        };

        let shift_powers = F::coset_shift().powers().take(1<<(max_lg_n)).collect::<Vec<_>>();
        let shift_powers_device = {
            let shift_powers_device = DeviceBuffer::from_slice(&shift_powers).unwrap();
            shift_powers_device
        };


        ctx = plonky2::fri::oracle::CudaInvContext {
            inner: CudaInnerContext{stream, stream2,},
            root_table_device,
            shift_powers_device,
            tasks,
            ctx: _ctx,
        };
    }

    // let allproof: proof::AllProof<GoldilocksField, C, D> =
    //     prove(&allstark, &kernel, &config, &mut timing).unwrap();
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

fn prove_groth16() {
    todo!()
}

fn main() {
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Debug);
    builder.try_init().unwrap_or_default();
    let args: Vec<String> = env::args().collect();
    let helper = || {
        log::info!(
            "Help: {} split | prove | aggregate_proof | aggregate_proof_all | prove_groth16",
            args[0]
        );
        std::process::exit(-1);
    };
    if args.len() < 2 {
        helper();
    }
    match args[1].as_str() {
        "split" => split_elf_into_segs(),
        "prove" => prove_single_seg(),
        "aggregate_proof" => aggregate_proof().unwrap(),
        "aggregate_proof_all" => aggregate_proof_all().unwrap(),
        "prove_groth16" => prove_groth16(),
        _ => helper(),
    };
}

fn aggregate_proof() -> anyhow::Result<()> {
    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    let basedir = env::var("BASEDIR").unwrap_or("/tmp/cannon".to_string());
    let block = env::var("BLOCK_NO").unwrap_or("".to_string());
    let file = env::var("BLOCK_FILE").unwrap_or(String::from(""));
    let seg_file = env::var("SEG_FILE").expect("first segment file is missing");
    let seg_file2 = env::var("SEG_FILE2").expect("The next segment file is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or(format!("{SEGMENT_STEPS}"));
    let seg_size = seg_size.parse::<_>().unwrap_or(SEGMENT_STEPS);
    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    // Preprocess all circuits.
    let all_circuits =
        AllRecursiveCircuits::<F, C, D>::new(&all_stark, &DEGREE_BITS_RANGE, &config);

    let seg_reader = BufReader::new(File::open(seg_file)?);
    let input_first = segment_kernel(&basedir, &block, &file, seg_reader, seg_size);
    let mut timing = TimingTree::new("prove root first", log::Level::Info);
    let (root_proof_first, first_public_values) =
        all_circuits.prove_root(&all_stark, &input_first, &config, &mut timing)?;

    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(root_proof_first.clone())?;

    let seg_reader = BufReader::new(File::open(seg_file2)?);
    let input = segment_kernel(&basedir, &block, &file, seg_reader, seg_size);
    let mut timing = TimingTree::new("prove root second", log::Level::Info);
    let (root_proof, public_values) =
        all_circuits.prove_root(&all_stark, &input, &config, &mut timing)?;
    timing.filter(Duration::from_millis(100)).print();

    all_circuits.verify_root(root_proof.clone())?;

    // Update public values for the aggregation.
    let agg_public_values = PublicValues {
        roots_before: first_public_values.roots_before,
        roots_after: public_values.roots_after,
        userdata: public_values.userdata,
    };

    // We can duplicate the proofs here because the state hasn't mutated.
    let timing = TimingTree::new("prove aggregation", log::Level::Info);
    let (agg_proof, updated_agg_public_values) = all_circuits.prove_aggregation(
        false,
        &root_proof_first,
        false,
        &root_proof,
        agg_public_values,
    )?;
    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_aggregation(&agg_proof)?;

    let timing = TimingTree::new("prove block", log::Level::Info);
    let (block_proof, _block_public_values) =
        all_circuits.prove_block(None, &agg_proof, updated_agg_public_values)?;
    timing.filter(Duration::from_millis(100)).print();

    log::info!(
        "proof size: {:?}",
        serde_json::to_string(&block_proof.proof).unwrap().len()
    );
    all_circuits.verify_block(&block_proof)
}

fn aggregate_proof_all() -> anyhow::Result<()> {
    type InnerParameters = DefaultParameters;
    type OuterParameters = Groth16WrapperParameters;

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    let basedir = env::var("BASEDIR").unwrap_or("/tmp/cannon".to_string());
    let block = env::var("BLOCK_NO").unwrap_or("".to_string());
    let file = env::var("BLOCK_FILE").unwrap_or(String::from(""));
    let seg_dir = env::var("SEG_FILE_DIR").expect("segment file dir is missing");
    let seg_file_number = env::var("SEG_FILE_NUM").expect("The segment file number is missing");
    let seg_file_number = seg_file_number.parse::<_>().unwrap_or(2usize);
    let seg_size = env::var("SEG_SIZE").unwrap_or(format!("{SEGMENT_STEPS}"));
    let seg_size = seg_size.parse::<_>().unwrap_or(SEGMENT_STEPS);

    if seg_file_number < 2 {
        panic!("seg file number must >= 2\n");
    }

    let total_timing = TimingTree::new("prove total time", log::Level::Info);
    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    // Preprocess all circuits.
    let all_circuits =
        AllRecursiveCircuits::<F, C, D>::new(&all_stark, &DEGREE_BITS_RANGE, &config);

    let seg_file = format!("{}/{}", seg_dir, 0);
    log::info!("Process segment 0");
    let seg_reader = BufReader::new(File::open(seg_file)?);
    let input_first = segment_kernel(&basedir, &block, &file, seg_reader, seg_size);
    let mut timing = TimingTree::new("prove root first", log::Level::Info);
    let (mut agg_proof, mut updated_agg_public_values) =
        all_circuits.prove_root(&all_stark, &input_first, &config, &mut timing)?;

    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(agg_proof.clone())?;

    let mut base_seg = 1;
    let mut is_agg = false;

    if seg_file_number % 2 == 0 {
        let seg_file = format!("{}/{}", seg_dir, 1);
        log::info!("Process segment 1");
        let seg_reader = BufReader::new(File::open(seg_file)?);
        let input = segment_kernel(&basedir, &block, &file, seg_reader, seg_size);
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
        base_seg = 2;
    }

    for i in 0..(seg_file_number - base_seg) / 2 {
        let seg_file = format!("{}/{}", seg_dir, base_seg + (i << 1));
        log::info!("Process segment {}", base_seg + (i << 1));
        let seg_reader = BufReader::new(File::open(&seg_file)?);
        let input_first = segment_kernel(&basedir, &block, &file, seg_reader, seg_size);
        let mut timing = TimingTree::new("prove root first", log::Level::Info);
        let (root_proof_first, first_public_values) =
            all_circuits.prove_root(&all_stark, &input_first, &config, &mut timing)?;

        timing.filter(Duration::from_millis(100)).print();
        all_circuits.verify_root(root_proof_first.clone())?;

        let seg_file = format!("{}/{}", seg_dir, base_seg + (i << 1) + 1);
        log::info!("Process segment {}", base_seg + (i << 1) + 1);
        let seg_reader = BufReader::new(File::open(&seg_file)?);
        let input = segment_kernel(&basedir, &block, &file, seg_reader, seg_size);
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
    let wrapped_circuit = WrappedCircuit::<InnerParameters, OuterParameters, D>::build(circuit);
    log::info!("build finish");

    let wrapped_proof = wrapped_circuit.prove(&block_proof).unwrap();
    wrapped_proof.save(path).unwrap();

    total_timing.filter(Duration::from_millis(100)).print();
    result
}
