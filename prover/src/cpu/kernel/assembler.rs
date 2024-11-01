use super::elf::Program;
use zkm_emulator::utils::get_block_path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, io::Read};

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Kernel {
    // MIPS ELF
    pub(crate) program: Program,
    // For debugging purposes
    pub(crate) ordered_labels: Vec<String>,
    //  should be preprocessed after loading code
    pub(crate) global_labels: HashMap<String, usize>,
    pub blockpath: String,
}

pub const MAX_MEM: u32 = 0x80000000;

pub fn segment_kernel<T: Read>(basedir: &str, block: &str, file: &str, seg_reader: T) -> Kernel {
    let p: Program = Program::load_segment(seg_reader).unwrap();
    let blockpath = get_block_path(basedir, block, file);

    Kernel {
        program: p,
        ordered_labels: vec![],
        global_labels: HashMap::new(),
        blockpath,
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

    /// Read public input from input stream index 0
    pub fn read_public_inputs(&self) -> Vec<u8> {
        if let Some(first) = self.program.input_stream.first() {
            // bincode::deserialize::<Vec<u8>>(first).expect("deserialization failed")
            let mut hasher = Sha256::new();
            hasher.update(first);
            let result = hasher.finalize();
            result.to_vec()
        } else {
            vec!(0u8; 32)
        }
    }
}
