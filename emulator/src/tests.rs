#[allow(clippy::module_inception)]
#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use crate::state::{InstrumentedState, State};
    use crate::utils::{get_block_path, load_elf_with_patch, split_prog_into_segs, SEGMENT_STEPS};

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
        let state = load_elf_with_patch("test-vectors/hello", vec!["aab", "ccd"]);

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
        let state = load_elf_with_patch("test-vectors/rust_fib", vec![]);

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
    #[ignore = "Two slow"]
    fn test_execute_minigeth() {
        let mut state = load_elf_with_patch("test-vectors/minigeth", vec![]);

        let block_path = get_block_path("test-vectors", "13284491", "");
        state.load_input(&block_path);

        let _ = split_prog_into_segs(state, OUTPUT, &block_path, SEGMENT_STEPS);
    }

    #[test]
    fn test_execute_split_hello() {
        let state = load_elf_with_patch("test-vectors/hello", vec![]);
        let _ = split_prog_into_segs(state, OUTPUT, "", SEGMENT_STEPS);
    }
}
