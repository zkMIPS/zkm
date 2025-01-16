use crate::state::{InstrumentedState, State};
use elf::{endian::AnyEndian, ElfBytes};
use std::fs;
use std::fs::File;
use crate::memory::INIT_SP;

pub const SEGMENT_STEPS: usize = 65536;

/// From the minigeth's rule, the `block` starts with `0_`
pub fn get_block_path(basedir: &str, block: &str, file: &str) -> String {
    format!("{basedir}/0_{block}/{file}")
}

pub fn load_elf_with_patch(elf_path: &str, _args: Vec<&str>) -> Box<State> {
    let data = fs::read(elf_path).expect("could not read file");
    let file =
        ElfBytes::<AnyEndian>::minimal_parse(data.as_slice()).expect("opening elf file failed");
    let mut state = State::load_elf(&file);
    //state.patch_elf(&file);
    //state.patch_stack(args);
    state.registers[29] = INIT_SP;
    state
}

pub fn split_prog_into_segs(
    state: Box<State>,
    seg_path: &str,
    block_path: &str,
    seg_size: usize,
) -> (usize, usize, Box<State>) {
    let mut instrumented_state = InstrumentedState::new(state, block_path.to_string());
    std::fs::create_dir_all(seg_path).unwrap();
    let new_writer = |_: &str| -> Option<std::fs::File> { None };
    instrumented_state.split_segment(false, seg_path, new_writer);
    let new_writer = |name: &str| -> Option<std::fs::File> { File::create(name).ok() };
    loop {
        let cycles = instrumented_state.step();
        if instrumented_state.state.exited {
            break;
        }
        if cycles > (seg_size as isize - 1) as u64 {
            instrumented_state.split_segment(true, seg_path, new_writer);
        }
    }
    instrumented_state.split_segment(true, seg_path, new_writer);
    log::info!(
        "Split done {} : {}",
        instrumented_state.state.total_step,
        instrumented_state.state.total_cycle
    );

    instrumented_state.dump_memory();
    (
        instrumented_state.state.total_step as usize,
        instrumented_state.pre_segment_id as usize,
        instrumented_state.state,
    )
}

pub fn load_segment(seg_file: &str) -> (Box<State>, u64) {
    State::load_seg(seg_file)
}

pub fn split_seg_into_segs(
    seg_file: &str,
    seg_path: &str,
    block_path: &str,
    seg_size: usize,
) -> (usize, usize, Box<State>) {
    let (state, final_step) = load_segment(seg_file);
    let mut instrumented_state = InstrumentedState::new(state, block_path.to_string());
    log::debug!("start pc: {:X} {}", instrumented_state.state.pc, final_step);
    std::fs::create_dir_all(seg_path).unwrap();
    let new_writer = |_: &str| -> Option<std::fs::File> { None };
    instrumented_state.split_segment(false, seg_path, new_writer);
    let new_writer = |name: &str| -> Option<std::fs::File> { File::create(name).ok() };
    loop {
        let cycles = instrumented_state.step();
        if instrumented_state.state.total_step + instrumented_state.state.step == final_step {
            break;
        }
        if cycles > (seg_size as isize - 1) as u64 {
            instrumented_state.split_segment(true, seg_path, new_writer);
            log::debug!(
                "Split at {} : {} into {}",
                instrumented_state.state.total_step,
                instrumented_state.state.total_cycle,
                instrumented_state.pre_segment_id
            );
        }
    }
    instrumented_state.split_segment(true, seg_path, new_writer);
    log::info!(
        "Split done {} : {} into {}",
        instrumented_state.state.total_step,
        instrumented_state.state.total_cycle,
        instrumented_state.pre_segment_id
    );

    instrumented_state.dump_memory();
    (
        instrumented_state.state.total_step as usize,
        instrumented_state.pre_segment_id as usize,
        instrumented_state.state,
    )
}
