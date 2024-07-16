use super::elf::Program;
use zkm_emulator::utils::get_block_path;

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io::Read};
use zkm_emulator::memory::INIT_SP;

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Kernel {
    // MIPS ELF
    pub(crate) program: Program,
    // For debugging purposes
    pub(crate) ordered_labels: Vec<String>,
    //  should be preprocessed after loading code
    pub(crate) global_labels: HashMap<String, usize>,
    pub blockpath: String,
    pub steps: usize,
}

pub const MAX_MEM: u32 = 0x80000000;

pub fn segment_kernel<T: Read>(
    basedir: &str,
    block: &str,
    file: &str,
    seg_reader: T,
    steps: usize,
) -> Kernel {
    let p: Program = Program::load_segment(seg_reader).unwrap();
    let blockpath = get_block_path(basedir, block, file);

    Kernel {
        program: p,
        ordered_labels: vec![],
        global_labels: HashMap::new(),
        blockpath,
        steps,
    }
}

impl Kernel {
    /// Get a string representation of the current offset for debugging purposes.
    pub(crate) fn offset_name(&self, offset: usize) -> String {
        match self
            .ordered_labels
            .binary_search_by_key(&offset, |label| self.global_labels[label])
        {
            Ok(idx) => self.ordered_labels[idx].clone(),
            Err(0) => offset.to_string(),
            Err(idx) => format!("{}, below {}", offset, self.ordered_labels[idx - 1]),
        }
    }

    pub(crate) fn offset_label(&self, offset: usize) -> Option<String> {
        self.global_labels
            .iter()
            .find_map(|(k, v)| (*v == offset).then(|| k.clone()))
    }

    /// Read public input from memory at page INIT_SP
    pub fn read_public_inputs(&self) -> Vec<u8> {
        let arg_size = self.program.image.get(&INIT_SP).unwrap();
        if *arg_size == 0 {
            return vec![];
        }

        let paddr = INIT_SP + 4;
        let daddr = self.program.image.get(&paddr).unwrap();
        log::trace!("Try read input at {}", daddr.to_be());
        let mut args = vec![];
        let mut value_addr = daddr.to_be();
        let mut b = false;
        while !b {
            let value = self.program.image.get(&value_addr).unwrap();
            let bytes = value.to_le_bytes();
            for c in bytes.iter() {
                if *c != 0 {
                    args.push(*c)
                } else {
                    b = true;
                    break;
                }
            }
            value_addr += 4;
        }
        log::trace!("Read public input: {:?}", args);
        args
    }
}
