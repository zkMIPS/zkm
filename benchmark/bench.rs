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
use zkm::config::StarkConfig;
use zkm::cpu::kernel::assembler::segment_kernel;
use zkm::fixed_recursive_verifier::AllRecursiveCircuits;
use zkm::mips_emulator::state::{InstrumentedState, State, SEGMENT_STEPS};
use zkm::mips_emulator::utils::get_block_path;
use zkm::proof;
use zkm::proof::PublicValues;
use zkm::prover::prove;
use zkm::verifier::verify_proof;

fn main() {
    // 1. split ELF into segs
    let basedir = env::var("BASEDIR").unwrap_or("/tmp/cannon".to_string());
    let elf_path = env::var("ELF_PATH").expect("ELF file is missing");
    let block_no = env::var("BLOCK_NO");
    let blockfile = env::var("BLOCK_FILE").unwrap_or(String::from(""));
    let seg_path = env::var("SEG_OUTPUT").expect("Segment output path is missing");
    let seg_size = env::var("SEG_SIZE").unwrap_or(format!("{SEGMENT_STEPS}"));
    let seg_size = seg_size.parse::<_>().unwrap_or(SEGMENT_STEPS);
    let args = env::var("ARGS").unwrap_or("".to_string());
    let args = args.split_whitespace().collect();
    
    let data = fs::read(elf_path).expect("could not read file");
    let file =
        ElfBytes::<AnyEndian>::minimal_parse(data.as_slice()).expect("opening elf file failed");
    let (mut state, _) = State::load_elf(&file);
    state.patch_go(&file);
    state.patch_stack(args);
    let input = [5u8; 32];
    state.add_input_stream(&input);

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
}
