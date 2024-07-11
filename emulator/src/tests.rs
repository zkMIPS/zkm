#[allow(clippy::module_inception)]
#[cfg(test)]
mod tests {
    use elf::{endian::AnyEndian, ElfBytes};
    use std::fs::File;
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use crate::state::SEGMENT_STEPS;
    use crate::state::{InstrumentedState, State};
    use crate::utils::get_block_path;

    const END_ADDR: u32 = 0xa7ef00d0;
    const OUTPUT: &str = "/tmp/segment";

    fn execute_open_mips(path: PathBuf) {
        if path.ends_with("oracle.bin") {
            println!("oracle test needs to be updated to use syscall pre-image oracle");
            return;
        }
        let data = fs::read(path).expect("could not read file");
        let data: Box<&[u8]> = Box::new(data.as_slice());

        let mut state = State::new();
        state
            .memory
            .set_memory_range(0, data)
            .expect("set memory range failed");
        state.registers[31] = END_ADDR;

        let mut instrumented_state = InstrumentedState::new(state, String::from(""));

        for _ in 0..1000 {
            if instrumented_state.state.pc == END_ADDR {
                break;
            }
            instrumented_state.step();
        }
    }

    #[test]
    fn test_execute_open_mips() {
        for file_name in fs::read_dir("./src/open_mips_tests/test/bin/").unwrap() {
            let file_name_path_buf = file_name.unwrap().path();
            if file_name_path_buf.ends_with(Path::new("oracle.bin")) {
                continue;
            }
            println!("testing: {:?}", &file_name_path_buf);
            execute_open_mips(file_name_path_buf);
        }
    }

    #[test]
    fn test_execute_hello() {
        let path = PathBuf::from("test-vectors/hello");
        let data = fs::read(path).expect("could not read file");
        let file =
            ElfBytes::<AnyEndian>::minimal_parse(data.as_slice()).expect("opening elf file failed");
        let mut state = State::load_elf(&file);

        state.patch_elf(&file);
        state.patch_stack(vec!["aab", "ccd"]);

        let mut instrumented_state = InstrumentedState::new(state, String::from(""));

        for _ in 0..40000000 {
            if instrumented_state.state.exited {
                break;
            }
            instrumented_state.step();
        }
    }

    #[test]
    fn test_execute_rust_fib() {
        let path = PathBuf::from("test-vectors/rust_fib");
        let data = fs::read(path).expect("could not read file");
        let file =
            ElfBytes::<AnyEndian>::minimal_parse(data.as_slice()).expect("opening elf file failed");
        let mut state = State::load_elf(&file);
        state.patch_elf(&file);
        state.patch_stack(vec![]);

        let mut instrumented_state = InstrumentedState::new(state, String::from(""));
        log::debug!("begin execute\n");
        for _ in 0..400000 {
            if instrumented_state.state.exited {
                break;
            }
            instrumented_state.step();
        }
    }

    #[test]
    #[ignore]
    fn test_execute_minigeth() {
        let path = PathBuf::from("test-vectors/minigeth");
        let data = fs::read(path).expect("could not read file");
        let file =
            ElfBytes::<AnyEndian>::minimal_parse(data.as_slice()).expect("opening elf file failed");
        let mut state = State::load_elf(&file);

        state.patch_elf(&file);
        state.patch_stack(vec![]);

        let block_path = get_block_path("../test-vectors", "13284491", "");
        state.load_input(&block_path);

        let mut instrumented_state = InstrumentedState::new(state, block_path);
        std::fs::create_dir_all(OUTPUT).unwrap();
        let new_writer = |_: &str| -> Option<std::fs::File> { None };
        instrumented_state.split_segment(false, OUTPUT, new_writer);
        let mut segment_step = SEGMENT_STEPS;
        let new_writer = |name: &str| -> Option<std::fs::File> { File::create(name).ok() };
        loop {
            if instrumented_state.state.exited {
                break;
            }
            instrumented_state.step();
            segment_step -= 1;
            if segment_step == 0 {
                segment_step = SEGMENT_STEPS;
                instrumented_state.split_segment(true, OUTPUT, new_writer);
            }
        }

        instrumented_state.split_segment(true, OUTPUT, new_writer);
    }

    #[test]
    fn test_execute_split_hello() {
        let path = PathBuf::from("test-vectors/hello");
        let data = fs::read(path).expect("could not read file");
        let file =
            ElfBytes::<AnyEndian>::minimal_parse(data.as_slice()).expect("opening elf file failed");
        let mut state = State::load_elf(&file);

        state.patch_elf(&file);
        state.patch_stack(vec![]);

        let mut instrumented_state = InstrumentedState::new(state, String::from(""));
        std::fs::create_dir_all(OUTPUT).unwrap();
        let new_writer = |_: &str| -> Option<std::fs::File> { None };
        instrumented_state.split_segment(false, OUTPUT, new_writer);
        let mut segment_step = SEGMENT_STEPS;
        let new_writer = |name: &str| -> Option<std::fs::File> { File::create(name).ok() };
        loop {
            if instrumented_state.state.exited {
                break;
            }
            instrumented_state.step();
            segment_step -= 1;
            if segment_step == 0 {
                segment_step = SEGMENT_STEPS;
                instrumented_state.split_segment(true, OUTPUT, new_writer);
            }
        }

        instrumented_state.split_segment(true, OUTPUT, new_writer);
    }
}
