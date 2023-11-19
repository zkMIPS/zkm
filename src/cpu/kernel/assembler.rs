use super::elf::Program;
use keccak_hash::keccak;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Kernel {
    // MIPS ELF
    pub(crate) code: Vec<u8>,
    pub(crate) program: Program,
    pub(crate) code_hash: [u32; 8],
    // For debugging purposes
    pub(crate) ordered_labels: Vec<String>,
    // FIXME: precompiled function and global variable, like HALT PC or ecrecover
    //  should be preprocessed after loading code
    pub(crate) global_labels: HashMap<String, usize>,
    pub blockpath: String,
}

// FIXME
pub const KERNLE_FILE: &str = "test-vectors/hello";

// FIXME: impl the mips vm
pub(crate) fn combined_kernel() -> Kernel {
    let mut reader = BufReader::new(File::open("test-vectors/hello").unwrap());
    let mut code = Vec::new();
    reader.read_to_end(&mut code).unwrap();
    //FIXME: define it as global constant
    let max_mem = 0x80000000;
    let mut p: Program = Program::load_elf(&code, max_mem).unwrap();
    let real_blockpath = Program::get_block_path("13284491", "input");
    println!("real block path: {}, entry: {}", real_blockpath, p.entry);
    let test_blockpath: &str = "test-vectors/0_13284491/input";
    p.load_block(test_blockpath).unwrap();

    let code_hash_bytes = keccak(&code).0;
    let code_hash_be = core::array::from_fn(|i| {
        u32::from_le_bytes(core::array::from_fn(|j| code_hash_bytes[i * 4 + j]))
    });
    let code_hash = code_hash_be.map(u32::from_be);
    log::debug!("code_hash: {:?}", code_hash);
    let blockpath = Program::get_block_path("13284491", "");

    Kernel {
        program: p,
        code,
        code_hash,
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
}

/// The number of bytes to push when pushing an offset within the code (i.e. when assembling jumps).
/// Ideally we would automatically use the minimal number of bytes required, but that would be
/// nontrivial given the circular dependency between an offset and its size.
pub(crate) const BYTES_PER_OFFSET: u8 = 3;

pub static KERNEL: Lazy<Kernel> = Lazy::new(combined_kernel);
