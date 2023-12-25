#[cfg(test)]
mod tests {
    use elf::{endian::AnyEndian, ElfBytes};
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use crate::mips_emulator::state::SEGMENT_STEPS;
    use crate::mips_emulator::state::{InstrumentedState, State};

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
        for file_name in fs::read_dir("./src/mips_emulator/open_mips_tests/test/bin/").unwrap() {
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
        let path = PathBuf::from("./test-vectors/hello");
        let data = fs::read(path).expect("could not read file");
        let file =
            ElfBytes::<AnyEndian>::minimal_parse(data.as_slice()).expect("opening elf file failed");
        let (mut state, _) = State::load_elf(&file);

        state.patch_go(&file);
        state.patch_stack();

        let mut instrumented_state = InstrumentedState::new(state, String::from(""));

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
        let path = PathBuf::from("./test-vectors/minigeth");
        let data = fs::read(path).expect("could not read file");
        let file =
            ElfBytes::<AnyEndian>::minimal_parse(data.as_slice()).expect("opening elf file failed");
        let (mut state, _) = State::load_elf(&file);

        state.patch_go(&file);
        state.patch_stack();

        let block_path = state.get_block_path("./test-vectors", "13284491");
        state.load_input(&block_path);

        let mut instrumented_state = InstrumentedState::new(state, block_path);
        instrumented_state.split_segment(false, OUTPUT);
        let mut segment_step = SEGMENT_STEPS;
        loop {
            if instrumented_state.state.exited {
                break;
            }
            instrumented_state.step();
            segment_step -= 1;
            if segment_step == 0 {
                segment_step = SEGMENT_STEPS;
                instrumented_state.split_segment(true, OUTPUT);
            }
        }

        instrumented_state.split_segment(true, OUTPUT);
    }

    #[test]
    fn test_execute_hello_split() {
        let path = PathBuf::from("./test-vectors/hello");
        let data = fs::read(path).expect("could not read file");
        let file =
            ElfBytes::<AnyEndian>::minimal_parse(data.as_slice()).expect("opening elf file failed");
        let (mut state, _) = State::load_elf(&file);

        state.patch_go(&file);
        state.patch_stack();

        let mut instrumented_state = InstrumentedState::new(state, String::from(""));
        instrumented_state.split_segment(false, OUTPUT);
        let mut segment_step = SEGMENT_STEPS;
        loop {
            if instrumented_state.state.exited {
                break;
            }
            instrumented_state.step();
            segment_step -= 1;
            if segment_step == 0 {
                segment_step = SEGMENT_STEPS;
                instrumented_state.split_segment(true, OUTPUT);
            }
        }

        instrumented_state.split_segment(true, OUTPUT);
    }
}
