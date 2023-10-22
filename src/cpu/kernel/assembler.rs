use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Kernel {
    pub(crate) code: Vec<u8>,
    pub(crate) ordered_labels: Vec<String>,
    pub(crate) global_labels: HashMap<String, usize>,
}

//FIXME load ELF: https://github.com/risc0/risc0/blob/main/risc0/binfmt/src/elf.rs#L34
pub(crate) fn combined_kernel() -> Kernel {
    // load ELF
    Kernel {
        code: vec![],
        ordered_labels: vec![],
        global_labels: HashMap::new(),
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
