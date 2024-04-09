use super::elf::Program;
use crate::mips_emulator::utils::get_block_path;

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io::Read};

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Kernel {
    // MIPS ELF
    pub(crate) program: Program,
    // For debugging purposes
    pub(crate) ordered_labels: Vec<String>,
    // FIXME: precompiled function and global variable, like HALT PC or ecrecover
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
    crate::print_mem_usage("before load segment");
    let p: Program = Program::load_segment(seg_reader).unwrap();
    crate::print_mem_usage("after load segment");
    let blockpath = get_block_path(basedir, block, file);
    crate::print_mem_usage("after get block");

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
}

/// The number of bytes to push when pushing an offset within the code (i.e. when assembling jumps).
/// Ideally we would automatically use the minimal number of bytes required, but that would be
/// nontrivial given the circular dependency between an offset and its size.
pub(crate) const BYTES_PER_OFFSET: u8 = 3;
